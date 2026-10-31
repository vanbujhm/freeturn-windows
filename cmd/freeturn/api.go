package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vanbujhm/freeturn-windows/internal/ipc"
	"github.com/vanbujhm/freeturn-windows/internal/link"
	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/profile"
	"github.com/vanbujhm/freeturn-windows/internal/split"
	"github.com/vanbujhm/freeturn-windows/internal/wgconf"
)

// previewTTL - сколько живёт токен превью импорта.
const previewTTL = 10 * time.Minute

// Имена событий Wails.
const (
	eventStatus      = "status"
	eventLog         = "log"
	eventImport      = "import"
	eventServiceDown = "service-down"
)

// Коды ошибок API. Интерфейс выбирает по ним текст, Message это запасной русский текст.
const (
	codeBadLink        = "bad_link"
	codeBadRule        = "bad_rule"
	codeBadConfig      = "bad_config"
	codeBadCallLink    = "bad_call_link"
	codeNoProfile      = "no_profile"
	codeIncomplete     = "incomplete"
	codePreviewExpired = "preview_expired"
	codeServiceDown    = "service_down"
	codeService        = "service"
	codeCorrupt        = "profiles_corrupt"
	codeStorage        = "storage"
	codeNoCaptcha      = "no_captcha"
	codeSettings       = "settings"
)

// Error - ошибка метода API. Через MarshalError уходит в интерфейс как JSON, поэтому у полей
// есть теги. Секретов в ней нет: текст ошибок разбора ссылки и конфига заменяется на
// постоянный.
type Error struct {
	Code    string        `json:"code"`
	Message string        `json:"message"`
	Fields  []model.Field `json:"fields,omitempty"`
	cause   error
}

func (e *Error) Error() string { return e.Message }
func (e *Error) Unwrap() error { return e.cause }

func newError(code, msg string, cause error) *Error {
	return &Error{Code: code, Message: msg, cause: cause}
}

// Service - то, что окну нужно от службы. Реализует *ipc.Client и supervisor.
type Service interface {
	Connect(model.ConnectRequest) error
	Disconnect() error
	Status() (model.Status, error)
	Logs() ([]string, error)
}

// ProfileView - профиль для интерфейса. Секретов (ключ обфускации, ссылка на звонок,
// конфиг WireGuard) здесь нет. Missing показывает, чего профилю не хватает.
type ProfileView struct {
	ID, Name, Peer, Provider, ClientID string
	GeneratedClientID                  bool
	Missing                            []model.Field
}

// ImportPreview - то, что человек подтверждает перед сохранением профиля.
// GeneratedClientID непусто, если в ссылке не было cid и ID создан окном.
type ImportPreview struct {
	Token             string
	Name, Peer        string
	Missing           []model.Field
	GeneratedClientID string
}

type preview struct {
	profile model.Profile
	expires time.Time
}

// apiDeps - всё внешнее, чем пользуется API. В тестах подменяется.
type apiDeps struct {
	Service      Service
	Store        *profile.Store
	Corrupt      bool // Open вернул ErrCorrupt
	Settings     profile.Settings
	SettingsPath string
	// Emit шлёт событие окну. Может быть nil.
	Emit func(name string, data ...any)
	// SetAutostart включает и выключает запуск с Windows.
	SetAutostart func(bool) error
	// DesktopDir возвращает рабочий стол пользователя.
	DesktopDir func() (string, error)
	// OpenURL открывает адрес в браузере по умолчанию.
	OpenURL func(string) error
	Now     func() time.Time
}

// API - сервис, привязанный к интерфейсу. Все экспортируемые методы вызываются из окна.
type API struct {
	svc          Service
	store        *profile.Store
	settingsPath string
	emit         func(name string, data ...any)
	setAutostart func(bool) error
	desktopDir   func() (string, error)
	openURL      func(string) error
	now          func() time.Time

	mu       sync.Mutex
	corrupt  bool
	settings profile.Settings
	previews map[string]preview
	pending  *ImportPreview
}

func newAPI(d apiDeps) *API {
	a := &API{
		svc:          d.Service,
		store:        d.Store,
		corrupt:      d.Corrupt,
		settings:     d.Settings,
		settingsPath: d.SettingsPath,
		emit:         d.Emit,
		setAutostart: d.SetAutostart,
		desktopDir:   d.DesktopDir,
		openURL:      d.OpenURL,
		now:          d.Now,
		previews:     make(map[string]preview),
	}
	if a.now == nil {
		a.now = time.Now
	}
	if a.emit == nil {
		a.emit = func(string, ...any) {}
	}
	if a.setAutostart == nil {
		a.setAutostart = func(bool) error { return nil }
	}
	return a
}

// ProfilesCorrupt сообщает, что файл профилей не прочитан и нужен ResetProfiles.
func (a *API) ProfilesCorrupt() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.corrupt
}

// ListProfiles возвращает профили без секретов.
func (a *API) ListProfiles() ([]ProfileView, error) {
	list := a.store.List()
	views := make([]ProfileView, len(list))
	for i, p := range list {
		views[i] = viewOf(p)
	}
	return views, nil
}

func viewOf(p model.Profile) ProfileView {
	missing := p.Missing()
	if missing == nil {
		missing = []model.Field{}
	}
	return ProfileView{
		ID: p.ID, Name: p.Name, Peer: p.Peer, Provider: p.Provider,
		ClientID: p.ClientID, GeneratedClientID: p.GeneratedClientID,
		Missing: missing,
	}
}

// linkRefusals - отказы разбора ссылки. Текст ошибки разбора может цитировать части
// ссылки, поэтому человеку показывается только постоянная причина.
var linkRefusals = []error{link.ErrScheme, link.ErrPayload, link.ErrVersion, link.ErrRequired, link.ErrTCPMode}

func linkError(err error) *Error {
	for _, known := range linkRefusals {
		if errors.Is(err, known) {
			return newError(codeBadLink, known.Error(), known)
		}
	}
	return newError(codeBadLink, "ссылка не разобрана", err)
}

// PreviewLink разбирает ссылку и возвращает превью. Профиль не сохраняется до ConfirmImport.
func (a *API) PreviewLink(raw string) (ImportPreview, error) {
	p, err := link.Parse(raw)
	if err != nil {
		return ImportPreview{}, linkError(err)
	}
	out := ImportPreview{Name: p.Name, Peer: p.Peer, Missing: p.Missing()}
	if out.Missing == nil {
		out.Missing = []model.Field{}
	}
	if strings.TrimSpace(p.ClientID) == "" {
		p.ClientID = link.NewClientID()
		p.GeneratedClientID = true
		out.GeneratedClientID = p.ClientID
	}
	token, err := newToken()
	if err != nil {
		return ImportPreview{}, newError(codeStorage, "не удалось создать токен импорта", err)
	}
	out.Token = token

	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for t, pv := range a.previews {
		if !now.Before(pv.expires) {
			delete(a.previews, t)
		}
	}
	a.previews[token] = preview{profile: p, expires: now.Add(previewTTL)}
	return out, nil
}

// ConfirmImport сохраняет профиль из превью. Токен одноразовый и живёт десять минут.
// Если запись не удалась, токен остаётся: можно повторить после ResetProfiles.
func (a *API) ConfirmImport(token string) (ProfileView, error) {
	a.mu.Lock()
	pv, ok := a.previews[token]
	if ok && !a.now().Before(pv.expires) {
		delete(a.previews, token)
		ok = false
	}
	a.mu.Unlock()
	if !ok {
		return ProfileView{}, newError(codePreviewExpired, "превью устарело, вставьте ссылку заново", nil)
	}
	saved, err := a.store.Save(pv.profile)
	if err != nil {
		return ProfileView{}, storeError(err)
	}
	a.mu.Lock()
	delete(a.previews, token)
	a.mu.Unlock()
	return viewOf(saved), nil
}

func storeError(err error) *Error {
	if errors.Is(err, profile.ErrCorrupt) {
		return newError(codeCorrupt, "файл профилей повреждён, импортируйте профили заново", err)
	}
	return newError(codeStorage, "не удалось записать профили", err)
}

// PendingImport отдаёт превью ссылки, пришедшей при запуске, и забывает его. Окно
// вызывает метод при загрузке: событие import могло уйти раньше, чем интерфейс подписался.
func (a *API) PendingImport() *ImportPreview {
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.pending
	a.pending = nil
	return p
}

// handleLink разбирает ссылку, полученную при запуске программы, и сообщает окну.
func (a *API) handleLink(raw string) error {
	pv, err := a.PreviewLink(raw)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.pending = &pv
	a.mu.Unlock()
	a.emit(eventImport, pv)
	return nil
}

// updateProfile читает профиль, применяет изменение и сохраняет.
func (a *API) updateProfile(id string, change func(*model.Profile) *Error) error {
	p, ok := a.store.Get(id)
	if !ok {
		return newError(codeNoProfile, "профиль не найден", nil)
	}
	if e := change(&p); e != nil {
		return e
	}
	if _, err := a.store.Save(p); err != nil {
		return storeError(err)
	}
	return nil
}

// SetCallLink задаёт или заменяет ссылку на звонок.
func (a *API) SetCallLink(id, callLink string) error {
	callLink = strings.TrimSpace(callLink)
	return a.updateProfile(id, func(p *model.Profile) *Error {
		if callLink == "" {
			return newError(codeBadCallLink, "ссылка на звонок пуста", nil)
		}
		p.CallLink = callLink
		return nil
	})
}

// SetWGConfig задаёт конфиг WireGuard. Разбор нужен, чтобы отказать сразу, а не при
// подключении. Текст ошибки разбора цитирует строки конфига, поэтому он не показывается.
func (a *API) SetWGConfig(id, text string) error {
	cfg, err := wgconf.Parse(text)
	if err != nil {
		return newError(codeBadConfig, "конфиг WireGuard не разобран: проверьте, что вставлен весь файл", err)
	}
	if len(cfg.Peers) != 1 {
		return newError(codeBadConfig, "в конфиге должен быть ровно один пир", nil)
	}
	return a.updateProfile(id, func(p *model.Profile) *Error {
		p.WGConfig = text
		return nil
	})
}

// DeleteProfile удаляет профиль и забывает его как последний.
func (a *API) DeleteProfile(id string) error {
	if err := a.store.Delete(id); err != nil {
		return storeError(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.settings.LastProfileID == id {
		a.settings.LastProfileID = ""
		if err := profile.SaveSettings(a.settingsPath, a.settings); err != nil {
			return newError(codeSettings, "не удалось записать настройки", err)
		}
	}
	return nil
}

// ResetProfiles убирает повреждённый файл профилей в сторону и возвращает возможность записи.
func (a *API) ResetProfiles() error {
	if err := a.store.Reset(); err != nil {
		return storeError(err)
	}
	a.mu.Lock()
	a.corrupt = false
	a.mu.Unlock()
	return nil
}

// serviceError переводит ошибку канала в ошибку API.
func serviceError(err error) *Error {
	if errors.Is(err, ipc.ErrClosed) || errors.Is(err, ipc.ErrTimeout) || errors.Is(err, errNoService) {
		return newError(codeServiceDown, "служба FreeTurn недоступна", err)
	}
	return newError(codeService, err.Error(), err)
}

// Connect отправляет службе профиль и настройки. Неполный профиль службе не отправляется.
func (a *API) Connect(id string) error {
	p, ok := a.store.Get(id)
	if !ok {
		return newError(codeNoProfile, "профиль не найден", nil)
	}
	if missing := p.Missing(); len(missing) > 0 {
		e := newError(codeIncomplete, "в профиле не хватает данных для подключения", nil)
		e.Fields = missing
		return e
	}
	a.mu.Lock()
	opts := a.settings.Options
	a.mu.Unlock()
	opts.Rules = append([]model.Rule(nil), opts.Rules...)

	if err := a.svc.Connect(model.ConnectRequest{Profile: p, Options: opts}); err != nil {
		return serviceError(err)
	}
	a.remember(id)
	return nil
}

// remember запоминает профиль последнего подключения. Подключение уже прошло, поэтому
// сбой записи не делает его ошибкой, а уходит в журнал окна.
func (a *API) remember(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.settings.LastProfileID == id {
		return
	}
	next := a.settings
	next.LastProfileID = id
	if err := profile.SaveSettings(a.settingsPath, next); err != nil {
		a.emit(eventLog, "не удалось запомнить профиль последнего подключения: "+err.Error())
		return
	}
	a.settings = next
}

// Disconnect просит службу отключить туннель.
func (a *API) Disconnect() error {
	if err := a.svc.Disconnect(); err != nil {
		return serviceError(err)
	}
	return nil
}

// Status возвращает состояние службы. Если службы нет, это не ошибка вызова, а состояние:
// Phase error с кодом service_down, как его показывает интерфейс.
func (a *API) Status() (model.Status, error) {
	st, err := a.svc.Status()
	if err != nil {
		return model.Status{Phase: model.PhaseError, Code: model.ErrServiceDown}, nil
	}
	return st, nil
}

// Settings возвращает настройки.
func (a *API) Settings() profile.Settings {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.settings
	s.Options.Rules = append([]model.Rule(nil), s.Options.Rules...)
	return s
}

// SaveSettings записывает настройки. LastProfileID интерфейс менять не может: его ведёт
// Connect. Запуск с Windows применяется сразу, при сбое записи прежнее значение возвращается.
func (a *API) SaveSettings(s profile.Settings) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	cur := a.settings
	s.LastProfileID = cur.LastProfileID
	s.Options.Rules = append([]model.Rule(nil), s.Options.Rules...)

	if s.Autostart != cur.Autostart {
		if err := a.setAutostart(s.Autostart); err != nil {
			return newError(codeSettings, "не удалось изменить запуск с Windows", err)
		}
	}
	if err := profile.SaveSettings(a.settingsPath, s); err != nil {
		if s.Autostart != cur.Autostart {
			_ = a.setAutostart(cur.Autostart)
		}
		return newError(codeSettings, "не удалось записать настройки", err)
	}
	a.settings = s
	return nil
}

// ClassifyRule определяет вид правила обхода по вводу человека.
func (a *API) ClassifyRule(value string) (model.Rule, error) {
	r, err := split.Classify(value)
	if err != nil {
		return model.Rule{}, newError(codeBadRule, err.Error(), err)
	}
	return r, nil
}

// Logs возвращает журнал службы.
func (a *API) Logs() ([]string, error) {
	lines, err := a.svc.Logs()
	if err != nil {
		return nil, serviceError(err)
	}
	return lines, nil
}

// SaveDiagnostics выгружает журнал службы на рабочий стол и возвращает путь к файлу.
// Строки уже замаскированы службой.
func (a *API) SaveDiagnostics() (string, error) {
	lines, err := a.svc.Logs()
	if err != nil {
		return "", serviceError(err)
	}
	dir, err := a.desktopDir()
	if err != nil {
		return "", newError(codeStorage, "не найден рабочий стол", err)
	}
	name := "freeturn-diagnostics-" + a.now().Format("2006-01-02") + ".txt"
	path := filepath.Join(dir, name)
	text := strings.Join(lines, "\r\n") + "\r\n"
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return "", newError(codeStorage, "не удалось записать файл диагностики", err)
	}
	return path, nil
}

// OpenCaptchaInBrowser открывает страницу капчи в браузере по умолчанию. Адрес приходит
// от службы, поэтому открываются только http и https.
func (a *API) OpenCaptchaInBrowser() error {
	st, err := a.svc.Status()
	if err != nil {
		return serviceError(err)
	}
	if st.Phase != model.PhaseCaptcha || st.CaptchaURL == "" {
		return newError(codeNoCaptcha, "капча сейчас не запрошена", nil)
	}
	u, err := url.Parse(st.CaptchaURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return newError(codeNoCaptcha, "адрес капчи не похож на веб-страницу", nil)
	}
	if err := a.openURL(u.String()); err != nil {
		return newError(codeStorage, "не удалось открыть браузер", err)
	}
	return nil
}

// onServiceUp вызывается при каждом (пере)подключении к каналу службы. Если служба
// перезапустилась и ждёт профиль, окно отправляет последний заново. Иначе при первом
// подключении после запуска программы выполняется «подключение при запуске».
func (a *API) onServiceUp(st model.Status, first bool) {
	a.emit(eventStatus, st)
	a.mu.Lock()
	id := a.settings.LastProfileID
	onLaunch := a.settings.ConnectOnLaunch
	a.mu.Unlock()
	if id == "" {
		return
	}
	switch {
	case st.AwaitingProfile:
	case first && onLaunch && st.Phase == model.PhaseIdle:
	default:
		return
	}
	if err := a.Connect(id); err != nil {
		a.emit(eventLog, "не удалось подключиться автоматически: "+err.Error())
	}
}

func newToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
