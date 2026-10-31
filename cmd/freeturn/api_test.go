package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vanbujhm/freeturn-windows/internal/ipc"
	"github.com/vanbujhm/freeturn-windows/internal/link"
	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/profile"
)

// Ключи в тестах только сгенерированные: base64 от 32 одинаковых байт.
var (
	testKey      = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
	testObfKey   = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("o", 32)))
	testCallLink = "https://example.test/call/FAKE-CALL-LINK"
	testWGConfig = "[Interface]\nPrivateKey = " + testKey + "\nAddress = 203.0.113.2/32\n\n" +
		"[Peer]\nPublicKey = " + testKey + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.1:51820\n"
	hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// fakeService записывает вызовы и возвращает заданные ответы.
type fakeService struct {
	mu          sync.Mutex
	connects    []model.ConnectRequest
	connectErr  error
	disconnects int
	status      model.Status
	statusErr   error
	logs        []string
}

func (f *fakeService) Connect(r model.ConnectRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connects = append(f.connects, r)
	return f.connectErr
}

func (f *fakeService) Disconnect() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disconnects++
	return nil
}

func (f *fakeService) Status() (model.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status, f.statusErr
}

func (f *fakeService) Logs() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logs, f.statusErr
}

func (f *fakeService) connectCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.connects)
}

type emitted struct {
	name string
	data []any
}

type testEnv struct {
	api      *API
	svc      *fakeService
	store    *profile.Store
	dir      string
	now      time.Time
	events   *[]emitted
	opened   *[]string
	autostar *[]bool
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	store, err := profile.Open(filepath.Join(dir, "profiles.dat"))
	if err != nil {
		t.Fatal(err)
	}
	env := &testEnv{
		svc: &fakeService{}, store: store, dir: dir,
		now:      time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC),
		events:   new([]emitted),
		opened:   new([]string),
		autostar: new([]bool),
	}
	env.api = newAPI(apiDeps{
		Service:      env.svc,
		Store:        store,
		Settings:     profile.Settings{Autostart: true},
		SettingsPath: filepath.Join(dir, "settings.json"),
		Emit: func(name string, data ...any) {
			*env.events = append(*env.events, emitted{name, data})
		},
		SetAutostart: func(on bool) error { *env.autostar = append(*env.autostar, on); return nil },
		DesktopDir:   func() (string, error) { return dir, nil },
		OpenURL:      func(u string) error { *env.opened = append(*env.opened, u); return nil },
		Now:          func() time.Time { return env.now },
	})
	return env
}

// encodeLink собирает синтетическую ссылку, как это делает приложение-источник.
func encodeLink(t *testing.T, extra map[string]any) string {
	t.Helper()
	m := map[string]any{"v": 1, "provider": "vk", "peer": "203.0.113.5:56000", "key": testObfKey}
	for k, v := range extra {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return "freeturn://" + base64.RawURLEncoding.EncodeToString(b)
}

// importProfile проводит ссылку через превью и подтверждение.
func (e *testEnv) importProfile(t *testing.T, extra map[string]any) ProfileView {
	t.Helper()
	pv, err := e.api.PreviewLink(encodeLink(t, extra))
	if err != nil {
		t.Fatal(err)
	}
	v, err := e.api.ConfirmImport(pv.Token)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// complete делает профиль пригодным для подключения.
func (e *testEnv) complete(t *testing.T, id string) {
	t.Helper()
	if err := e.api.SetCallLink(id, testCallLink); err != nil {
		t.Fatal(err)
	}
	if err := e.api.SetWGConfig(id, testWGConfig); err != nil {
		t.Fatal(err)
	}
}

func apiCode(t *testing.T, err error) string {
	t.Helper()
	var ae *Error
	if !errors.As(err, &ae) {
		t.Fatalf("ожидалась *Error, получили %v", err)
	}
	return ae.Code
}

func TestPreviewDoesNotSave(t *testing.T) {
	e := newEnv(t)
	if _, err := e.api.PreviewLink(encodeLink(t, nil)); err != nil {
		t.Fatal(err)
	}
	list, err := e.api.ListProfiles()
	if err != nil || len(list) != 0 {
		t.Fatalf("после превью профили: %v, %v", list, err)
	}
	if got := e.store.List(); len(got) != 0 {
		t.Fatalf("превью записало профиль в хранилище: %v", got)
	}
}

func TestConfirmImportSaves(t *testing.T) {
	e := newEnv(t)
	pv, err := e.api.PreviewLink(encodeLink(t, map[string]any{"name": "Дом"}))
	if err != nil {
		t.Fatal(err)
	}
	if pv.Name != "Дом" || pv.Peer != "203.0.113.5:56000" {
		t.Fatalf("превью: %+v", pv)
	}
	v, err := e.api.ConfirmImport(pv.Token)
	if err != nil {
		t.Fatal(err)
	}
	if v.ID == "" || v.Name != "Дом" {
		t.Fatalf("профиль: %+v", v)
	}
	list, _ := e.api.ListProfiles()
	if len(list) != 1 || list[0].ID != v.ID {
		t.Fatalf("список: %+v", list)
	}
	if _, err := e.api.ConfirmImport(pv.Token); apiCode(t, err) != codePreviewExpired {
		t.Fatalf("повторный токен принят: %v", err)
	}
	if list, _ := e.api.ListProfiles(); len(list) != 1 {
		t.Fatalf("повторный токен добавил профиль: %+v", list)
	}
}

func TestPreviewTokenExpires(t *testing.T) {
	e := newEnv(t)
	pv, err := e.api.PreviewLink(encodeLink(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(previewTTL)
	if _, err := e.api.ConfirmImport(pv.Token); apiCode(t, err) != codePreviewExpired {
		t.Fatalf("токен старше десяти минут принят: %v", err)
	}
	if list, _ := e.api.ListProfiles(); len(list) != 0 {
		t.Fatalf("устаревшее превью сохранило профиль: %+v", list)
	}
	if _, err := e.api.ConfirmImport("нет-такого"); apiCode(t, err) != codePreviewExpired {
		t.Fatalf("неизвестный токен принят: %v", err)
	}
}

func TestPreviewGeneratesClientID(t *testing.T) {
	e := newEnv(t)
	pv, err := e.api.PreviewLink(encodeLink(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !hex32.MatchString(pv.GeneratedClientID) {
		t.Fatalf("GeneratedClientID %q не 32 hex", pv.GeneratedClientID)
	}
	v, err := e.api.ConfirmImport(pv.Token)
	if err != nil {
		t.Fatal(err)
	}
	if v.ClientID != pv.GeneratedClientID || !v.GeneratedClientID {
		t.Fatalf("профиль %+v не хранит созданный ID %q", v, pv.GeneratedClientID)
	}

	own := e.importProfile(t, map[string]any{"cid": "0123456789abcdef"})
	if own.ClientID != "0123456789abcdef" || own.GeneratedClientID {
		t.Fatalf("ID из ссылки заменён: %+v", own)
	}
	pv2, _ := e.api.PreviewLink(encodeLink(t, map[string]any{"cid": "0123456789abcdef"}))
	if pv2.GeneratedClientID != "" {
		t.Fatalf("для ссылки с cid создан ID %q", pv2.GeneratedClientID)
	}
}

func TestViewsHaveNoSecrets(t *testing.T) {
	e := newEnv(t)
	v := e.importProfile(t, nil)
	e.complete(t, v.ID)
	pv, _ := e.api.PreviewLink(encodeLink(t, nil))

	list, err := e.api.ListProfiles()
	if err != nil || len(list) != 1 {
		t.Fatalf("список: %v, %v", list, err)
	}
	for _, payload := range []any{list, pv} {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{testObfKey, testCallLink, testKey, "ObfKey", "CallLink", "WGConfig", "PrivateKey"} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("в JSON для интерфейса есть %q: %s", secret, raw)
			}
		}
	}
	if len(list[0].Missing) != 0 {
		t.Fatalf("у полного профиля Missing = %v", list[0].Missing)
	}
}

func TestMissingListedForIncompleteProfile(t *testing.T) {
	e := newEnv(t)
	pv, _ := e.api.PreviewLink(encodeLink(t, nil))
	want := []model.Field{model.FieldCallLink, model.FieldWGConfig}
	if !slices.Equal(pv.Missing, want) {
		t.Fatalf("Missing превью %v", pv.Missing)
	}
	v, _ := e.api.ConfirmImport(pv.Token)
	if !slices.Equal(v.Missing, want) {
		t.Fatalf("Missing профиля %v", v.Missing)
	}
}

func TestSetWGConfigRejectsGarbage(t *testing.T) {
	e := newEnv(t)
	v := e.importProfile(t, nil)
	err := e.api.SetWGConfig(v.ID, "это не конфиг\nPrivateKey = "+testKey)
	if apiCode(t, err) != codeBadConfig {
		t.Fatalf("мусор принят: %v", err)
	}
	if strings.Contains(err.Error(), testKey) {
		t.Fatalf("текст ошибки цитирует конфиг: %v", err)
	}
	two := testWGConfig + "\n[Peer]\nPublicKey = " + testKey + "\nAllowedIPs = 10.0.0.0/8\n"
	if apiCode(t, e.api.SetWGConfig(v.ID, two)) != codeBadConfig {
		t.Fatal("конфиг с двумя пирами принят")
	}
	if got, _ := e.store.Get(v.ID); got.WGConfig != "" {
		t.Fatal("отвергнутый конфиг сохранён")
	}
}

func TestConnectRejectsIncomplete(t *testing.T) {
	e := newEnv(t)
	v := e.importProfile(t, nil)
	if err := e.api.SetCallLink(v.ID, testCallLink); err != nil {
		t.Fatal(err)
	}
	err := e.api.Connect(v.ID)
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != codeIncomplete || !slices.Equal(ae.Fields, []model.Field{model.FieldWGConfig}) {
		t.Fatalf("ожидалась ошибка с FieldWGConfig, получили %v", err)
	}
	if n := e.svc.connectCount(); n != 0 {
		t.Fatalf("служба получила неполный профиль (%d вызовов)", n)
	}
	if apiCode(t, e.api.Connect("нет-такого")) != codeNoProfile {
		t.Fatal("неизвестный профиль не отвергнут")
	}
}

func TestConnectSendsOptions(t *testing.T) {
	e := newEnv(t)
	v := e.importProfile(t, nil)
	e.complete(t, v.ID)
	rules := []model.Rule{{Kind: model.RuleDomain, Value: "example.test"}, {Kind: model.RuleSubnet, Value: "203.0.113.0/24"}}
	s := e.api.Settings()
	s.Options = model.Options{KillSwitch: true, AllowLAN: false, Rules: rules}
	if err := e.api.SaveSettings(s); err != nil {
		t.Fatal(err)
	}
	if err := e.api.Connect(v.ID); err != nil {
		t.Fatal(err)
	}
	if e.svc.connectCount() != 1 {
		t.Fatal("служба не получила Connect")
	}
	got := e.svc.connects[0]
	if !got.Options.KillSwitch || got.Options.AllowLAN || !slices.Equal(got.Options.Rules, rules) {
		t.Fatalf("настройки в запросе: %+v", got.Options)
	}
	if got.Profile.ID != v.ID || got.Profile.WGConfig != testWGConfig || got.Profile.CallLink != testCallLink {
		t.Fatal("в запросе не тот или неполный профиль")
	}
}

func TestConnectRemembersProfile(t *testing.T) {
	e := newEnv(t)
	v := e.importProfile(t, nil)
	e.complete(t, v.ID)
	if err := e.api.Connect(v.ID); err != nil {
		t.Fatal(err)
	}
	if got := e.api.Settings().LastProfileID; got != v.ID {
		t.Fatalf("LastProfileID в памяти %q", got)
	}
	saved, err := profile.LoadSettings(filepath.Join(e.dir, "settings.json"))
	if err != nil || saved.LastProfileID != v.ID {
		t.Fatalf("LastProfileID в файле %q, %v", saved.LastProfileID, err)
	}

	// Окно не может подменить LastProfileID через SaveSettings.
	s := e.api.Settings()
	s.LastProfileID = "чужой"
	if err := e.api.SaveSettings(s); err != nil {
		t.Fatal(err)
	}
	if got := e.api.Settings().LastProfileID; got != v.ID {
		t.Fatalf("SaveSettings изменил LastProfileID: %q", got)
	}

	// Отказ службы профиль последним не делает.
	other := e.importProfile(t, map[string]any{"name": "Второй"})
	e.complete(t, other.ID)
	e.svc.connectErr = errors.New("отказ")
	if apiCode(t, e.api.Connect(other.ID)) != codeService {
		t.Fatal("ошибка службы не отдана как service")
	}
	if got := e.api.Settings().LastProfileID; got != v.ID {
		t.Fatalf("неудачное подключение стало последним: %q", got)
	}
}

func TestConnectServiceDown(t *testing.T) {
	e := newEnv(t)
	v := e.importProfile(t, nil)
	e.complete(t, v.ID)
	e.svc.connectErr = ipc.ErrClosed
	if apiCode(t, e.api.Connect(v.ID)) != codeServiceDown {
		t.Fatal("обрыв канала не отдан как service_down")
	}
}

func TestStatusServiceDown(t *testing.T) {
	e := newEnv(t)
	e.svc.statusErr = errNoService
	st, err := e.api.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Code != model.ErrServiceDown || st.Phase != model.PhaseError {
		t.Fatalf("состояние при недоступной службе: %+v", st)
	}
	e.svc.statusErr = nil
	e.svc.status = model.Status{Phase: model.PhaseConnected}
	if st, _ := e.api.Status(); st.Phase != model.PhaseConnected {
		t.Fatalf("состояние службы потеряно: %+v", st)
	}
}

func TestPreviewTCPMode(t *testing.T) {
	e := newEnv(t)
	_, err := e.api.PreviewLink(encodeLink(t, map[string]any{"mode": "tcp"}))
	if !errors.Is(err, link.ErrTCPMode) {
		t.Fatalf("ожидалась link.ErrTCPMode, получили %v", err)
	}
	if apiCode(t, err) != codeBadLink {
		t.Fatalf("код %q", apiCode(t, err))
	}
	if _, err := e.api.PreviewLink("freeturn://обрезано"); apiCode(t, err) != codeBadLink {
		t.Fatalf("обрезанная ссылка: %v", err)
	}
}

func TestPreviewErrorHasNoLinkText(t *testing.T) {
	e := newEnv(t)
	raw := encodeLink(t, map[string]any{"v": 7})
	_, err := e.api.PreviewLink(raw)
	if err == nil || strings.Contains(err.Error(), strings.TrimPrefix(raw, "freeturn://")) {
		t.Fatalf("ошибка цитирует ссылку: %v", err)
	}
}

func TestDeleteProfileForgetsLast(t *testing.T) {
	e := newEnv(t)
	v := e.importProfile(t, nil)
	e.complete(t, v.ID)
	if err := e.api.Connect(v.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.api.DeleteProfile(v.ID); err != nil {
		t.Fatal(err)
	}
	if got := e.api.Settings().LastProfileID; got != "" {
		t.Fatalf("LastProfileID после удаления %q", got)
	}
	if list, _ := e.api.ListProfiles(); len(list) != 0 {
		t.Fatalf("профиль не удалён: %+v", list)
	}
}

func TestCorruptStoreResetFlow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.dat")
	if err := os.WriteFile(path, []byte("чужие байты"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := profile.Open(path)
	if !errors.Is(err, profile.ErrCorrupt) {
		t.Fatalf("Open: %v", err)
	}
	api := newAPI(apiDeps{Service: &fakeService{}, Store: store, Corrupt: true,
		SettingsPath: filepath.Join(dir, "settings.json")})
	if !api.ProfilesCorrupt() {
		t.Fatal("ProfilesCorrupt = false")
	}
	if list, err := api.ListProfiles(); err != nil || len(list) != 0 {
		t.Fatalf("список повреждённого хранилища: %v, %v", list, err)
	}
	pv, err := api.PreviewLink(encodeLink(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.ConfirmImport(pv.Token); apiCode(t, err) != codeCorrupt {
		t.Fatalf("запись в повреждённое хранилище: %v", err)
	}
	if err := api.ResetProfiles(); err != nil {
		t.Fatal(err)
	}
	if api.ProfilesCorrupt() {
		t.Fatal("ProfilesCorrupt остался после ResetProfiles")
	}
	// Токен пережил отказ и работает после сброса.
	if _, err := api.ConfirmImport(pv.Token); err != nil {
		t.Fatalf("импорт после сброса: %v", err)
	}
	if _, err := os.Stat(path + ".bad"); err != nil {
		t.Fatalf("повреждённый файл не сохранён: %v", err)
	}
}

func TestSaveSettingsAppliesAutostart(t *testing.T) {
	e := newEnv(t)
	s := e.api.Settings()
	s.Autostart = false
	if err := e.api.SaveSettings(s); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*e.autostar, []bool{false}) {
		t.Fatalf("вызовы автозапуска: %v", *e.autostar)
	}
	if err := e.api.SaveSettings(s); err != nil {
		t.Fatal(err)
	}
	if len(*e.autostar) != 1 {
		t.Fatalf("автозапуск переписан без изменений: %v", *e.autostar)
	}
	loaded, _ := profile.LoadSettings(filepath.Join(e.dir, "settings.json"))
	if loaded.Autostart {
		t.Fatal("настройка не записана в файл")
	}
}

func TestClassifyRule(t *testing.T) {
	e := newEnv(t)
	r, err := e.api.ClassifyRule(" 203.0.113.0/24 ")
	if err != nil || r.Kind != model.RuleSubnet || r.Value != "203.0.113.0/24" {
		t.Fatalf("%+v, %v", r, err)
	}
	if _, err := e.api.ClassifyRule("*.example.test"); apiCode(t, err) != codeBadRule {
		t.Fatalf("шаблон принят: %v", err)
	}
}

func TestSaveDiagnostics(t *testing.T) {
	e := newEnv(t)
	e.svc.logs = []string{"строка 1", "строка 2"}
	path, err := e.api.SaveDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "freeturn-diagnostics-2026-10-31.txt" || filepath.Dir(path) != e.dir {
		t.Fatalf("путь %q", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(raw), "строка 1") || !strings.Contains(string(raw), "строка 2") {
		t.Fatalf("содержимое %q, %v", raw, err)
	}
	e.svc.statusErr = ipc.ErrClosed
	if _, err := e.api.SaveDiagnostics(); apiCode(t, err) != codeServiceDown {
		t.Fatalf("без службы: %v", err)
	}
}

func TestOpenCaptchaInBrowser(t *testing.T) {
	e := newEnv(t)
	if apiCode(t, e.api.OpenCaptchaInBrowser()) != codeNoCaptcha {
		t.Fatal("без капчи браузер открыт")
	}
	e.svc.status = model.Status{Phase: model.PhaseCaptcha, CaptchaURL: "file:///C:/Windows/System32/calc.exe"}
	if apiCode(t, e.api.OpenCaptchaInBrowser()) != codeNoCaptcha || len(*e.opened) != 0 {
		t.Fatal("адрес не из веб открыт")
	}
	e.svc.status.CaptchaURL = "https://captcha.example.test/page?x=1"
	if err := e.api.OpenCaptchaInBrowser(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*e.opened, []string{"https://captcha.example.test/page?x=1"}) {
		t.Fatalf("открыто %v", *e.opened)
	}
}

func TestHandleLinkEmitsImport(t *testing.T) {
	e := newEnv(t)
	if err := e.api.handleLink(encodeLink(t, nil)); err != nil {
		t.Fatal(err)
	}
	if len(*e.events) != 1 || (*e.events)[0].name != eventImport {
		t.Fatalf("события: %+v", *e.events)
	}
	pv, ok := (*e.events)[0].data[0].(ImportPreview)
	if !ok || pv.Token == "" {
		t.Fatalf("данные события: %+v", (*e.events)[0].data)
	}
	if p := e.api.PendingImport(); p == nil || p.Token != pv.Token {
		t.Fatalf("PendingImport: %+v", p)
	}
	if e.api.PendingImport() != nil {
		t.Fatal("PendingImport отдан дважды")
	}
	if err := e.api.handleLink("freeturn://"); err == nil {
		t.Fatal("пустая ссылка принята")
	}
}

func TestOnServiceUpResumesAwaitingProfile(t *testing.T) {
	e := newEnv(t)
	v := e.importProfile(t, nil)
	e.complete(t, v.ID)
	if err := e.api.Connect(v.ID); err != nil {
		t.Fatal(err)
	}
	before := e.svc.connectCount()

	e.api.onServiceUp(model.Status{Phase: model.PhaseConnected}, false)
	if e.svc.connectCount() != before {
		t.Fatal("профиль отправлен службе, которая его не ждёт")
	}
	e.api.onServiceUp(model.Status{Phase: model.PhaseIdle, AwaitingProfile: true}, false)
	if e.svc.connectCount() != before+1 || e.svc.connects[before].Profile.ID != v.ID {
		t.Fatal("LastProfileID не отправлен заново")
	}
	if n := len(*e.events); n != 2 || (*e.events)[0].name != eventStatus || (*e.events)[1].name != eventStatus {
		t.Fatalf("окну отправлено не по одному состоянию на вызов: %+v", *e.events)
	}
}

func TestOnServiceUpConnectOnLaunch(t *testing.T) {
	e := newEnv(t)
	v := e.importProfile(t, nil)
	e.complete(t, v.ID)
	if err := e.api.Connect(v.ID); err != nil {
		t.Fatal(err)
	}
	before := e.svc.connectCount()

	e.api.onServiceUp(model.Status{Phase: model.PhaseIdle}, true)
	if e.svc.connectCount() != before {
		t.Fatal("подключение при запуске выключено, но Connect вызван")
	}
	s := e.api.Settings()
	s.ConnectOnLaunch = true
	if err := e.api.SaveSettings(s); err != nil {
		t.Fatal(err)
	}
	e.api.onServiceUp(model.Status{Phase: model.PhaseConnected}, true)
	e.api.onServiceUp(model.Status{Phase: model.PhaseIdle}, false)
	if e.svc.connectCount() != before {
		t.Fatal("подключение при запуске сработало не там, где нужно")
	}
	e.api.onServiceUp(model.Status{Phase: model.PhaseIdle}, true)
	if e.svc.connectCount() != before+1 {
		t.Fatal("подключение при запуске не выполнено")
	}
}
