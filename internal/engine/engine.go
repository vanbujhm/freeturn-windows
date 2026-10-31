// Package engine выстраивает подключение по шагам, откатывает его при сбое и держит
// состояние, которое видит окно. Весь системный ввод-вывод идёт через интерфейсы из deps.go.
//
// Каждое подключение ведёт один рабочий поток, он живёт от Connect до конца отката. Потоку
// можно только отменить контекст, причина отмены говорит, чем закончить: откат всегда идёт
// в потоке, в одном месте.
//
// Блокировки:
//   - ctl упорядочивает команды Connect, Disconnect, ArmBlock, AwaitProfile;
//   - mu защищает статус и поля сессии, при вызовах зависимостей не держится;
//   - notifyMu держит порядок OnChange, берётся раньше mu;
//   - fwMu держится на время одного вызова брандмауэра.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/vanbujhm/freeturn-windows/internal/firewall"
	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/secretmask"
	"github.com/vanbujhm/freeturn-windows/internal/split"
	"github.com/vanbujhm/freeturn-windows/internal/wgconf"
)

// Уровни журнала совпадают с уровнями ядра.
const (
	levelInfo  = "info"
	levelWarn  = "warn"
	levelError = "error"
)

// Состояния ядра, которые приходят в OnCoreState.
const (
	coreConnecting = "connecting"
	coreConnected  = "connected"
	coreCaptcha    = "captcha"
	coreError      = "error"
)

// minConfigToken - длина, с которой слово неразобранного конфига считается секретом.
const minConfigToken = 16

// ErrBusy: подключение или отключение уже идёт.
var ErrBusy = errors.New("engine: подключение уже идёт")

// errDisconnected - причина отмены по команде Disconnect.
var errDisconnected = errors.New("engine: отключено по команде")

// failure - причина отмены или сбоя шага. msg ещё не прошёл через Masker.
type failure struct {
	code model.ErrorCode
	msg  string
}

func (f *failure) Error() string { return string(f.code) + ": " + f.msg }

func failed(code model.ErrorCode, err error) error {
	return &failure{code: code, msg: err.Error()}
}

// session - одно подключение. Поля из первого блока не меняются после создания, второй блок
// принадлежит рабочему потоку, третий защищён Engine.mu. До established третий блок пишет
// только рабочий поток, поэтому свои записи он читает без mu. Менять эти поля из другого
// потока можно только после established.
type session struct {
	req     model.ConnectRequest
	ctx     context.Context
	cancel  context.CancelCauseFunc
	done    chan struct{} // закрыт после отката
	coreUp  chan struct{} // закрыт при первом connected от ядра
	captcha chan struct{} // ёмкость 1: капча открылась или закрылась, таймер шага 3 смотрит статус

	undo      []func()
	holdBlock bool // сбой не снимает блокировку
	keepBlock bool // решение для текущего отката

	listening   bool // события ядра принимаются
	coreSeen    bool
	established bool // шаг 5 пройден
	ph          model.Physical
	listen      netip.AddrPort
	cfg         *wgconf.Config
	rules       split.Compiled
	luid        uint64
	resolved    []netip.Addr
}

// push кладёт обратную операцию на стек отката.
func (s *session) push(fn func()) { s.undo = append(s.undo, fn) }

// stopped возвращает причину отмены, если сессию уже отменили.
func (s *session) stopped() error {
	if s.ctx.Err() != nil {
		return context.Cause(s.ctx)
	}
	return nil
}

// addResolved добавляет адреса доменов без повторов и сообщает, появились ли новые.
func (s *session) addResolved(addrs []netip.Addr) bool {
	added := false
	for _, a := range addrs {
		a = a.Unmap()
		if a.IsValid() && !slices.Contains(s.resolved, a) {
			s.resolved = append(s.resolved, a)
			added = true
		}
	}
	return added
}

// bypass возвращает префиксы правил и адреса доменов как /32 и /128, без повторов.
func (s *session) bypass() []netip.Prefix {
	out := slices.Clone(s.rules.Prefixes)
	for _, a := range s.resolved {
		if p := netip.PrefixFrom(a, a.BitLen()); !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// firewallOptions собирает разрешения блокировки для текущих адресов.
func (s *session) firewallOptions() firewall.Options {
	return firewall.Options{
		TunLUID:  s.luid,
		DNS:      s.cfg.DNS,
		AllowLAN: s.req.Options.AllowLAN,
		Bypass:   s.bypass(),
	}
}

// restingPhase - фаза, в которую сессия возвращается после капчи.
func (s *session) restingPhase(streams int) model.Phase {
	switch {
	case !s.established:
		return model.PhaseConnecting
	case streams > 0:
		return model.PhaseConnected
	default:
		return model.PhaseReconnecting
	}
}

// signalCaptcha будит ожидание шага 3. Сигнал не копится: таймер смотрит статус.
func (s *session) signalCaptcha() {
	select {
	case s.captcha <- struct{}{}:
	default:
	}
}

// Engine - движок подключения. Туннель один на машину, поэтому и Engine один.
type Engine struct {
	d Deps

	ctl      sync.Mutex
	notifyMu sync.Mutex

	mu   sync.Mutex
	st   model.Status
	sess *session
	mask *secretmask.Masker

	fwMu sync.Mutex
	fwOn bool // блокировка стоит
}

// New создаёт движок в состоянии Idle.
func New(d Deps) *Engine {
	if d.OnChange == nil {
		d.OnChange = func(model.Status) {}
	}
	if d.Logf == nil {
		d.Logf = func(string, string) {}
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.CoreTimeout == 0 {
		d.CoreTimeout = defaultCoreTimeout
	}
	if d.HandshakeTimeout == 0 {
		d.HandshakeTimeout = defaultHandshakeTimeout
	}
	return &Engine{d: d, st: model.Status{Phase: model.PhaseIdle}}
}

// Connect запускает подключение и сразу возвращается. Результат виден в статусе, ошибка
// только ErrBusy. Из Blocked подключиться можно: блокировка держится, пока туннель не готов.
func (e *Engine) Connect(req model.ConnectRequest) error {
	// Идущее отключение это тоже занято, а не повод ждать.
	if !e.ctl.TryLock() {
		return ErrBusy
	}
	defer e.ctl.Unlock()

	ctx, cancel := context.WithCancelCause(context.Background())
	s := &session{
		req:     req,
		ctx:     ctx,
		cancel:  cancel,
		done:    make(chan struct{}),
		coreUp:  make(chan struct{}),
		captcha: make(chan struct{}, 1),
	}
	busy := false
	e.update(func(st *model.Status) bool {
		if e.sess != nil {
			busy = true
			return false
		}
		e.sess = s
		e.mask = secretmask.ForProfile(req.Profile, nil)
		s.holdBlock = st.Phase == model.PhaseBlocked
		*st = model.Status{Phase: model.PhaseConnecting, ProfileID: req.Profile.ID}
		return true
	})
	if busy {
		cancel(nil)
		return ErrBusy
	}
	go e.run(s)
	return nil
}

// Disconnect отменяет подключение, ждёт конца отката и снимает блокировку, если она осталась.
func (e *Engine) Disconnect() {
	e.ctl.Lock()
	defer e.ctl.Unlock()

	e.mu.Lock()
	s := e.sess
	e.mu.Unlock()
	if s != nil {
		s.cancel(errDisconnected)
		<-s.done
	}
	e.fwClear()
	e.update(func(st *model.Status) bool {
		*st = model.Status{Phase: model.PhaseIdle, Warnings: st.Warnings}
		return true
	})
	e.logf(levelInfo, "отключено")
}

// Status возвращает снимок состояния.
func (e *Engine) Status() model.Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.snapshot()
}

// OnCoreState принимает состояние ядра. Вызывается из потока ядра и не блокируется на шагах.
func (e *Engine) OnCoreState(state string, streams, total int, errMsg string) {
	var fatal *failure
	if state == coreError {
		fatal = &failure{code: e.d.Classify(errMsg), msg: errMsg}
	}
	e.update(func(st *model.Status) bool {
		s := e.sess
		if s == nil || !s.listening {
			return false
		}
		changed := st.Streams != streams || st.Total != total
		st.Streams, st.Total = streams, total
		switch state {
		case coreConnected:
			if !s.coreSeen {
				s.coreSeen = true
				close(s.coreUp)
			}
			if st.Phase == model.PhaseReconnecting {
				st.Phase = model.PhaseConnected
				changed = true
			}
		case coreConnecting, coreCaptcha:
			if st.Phase == model.PhaseConnected && streams == 0 {
				st.Phase = model.PhaseReconnecting
				changed = true
			}
		case coreError:
			s.cancel(fatal)
		}
		return changed
	})
}

// OnCaptcha принимает страницу капчи. Пустой url закрывает её, а автоматическая проверка
// (manual=false) окну не показывается.
func (e *Engine) OnCaptcha(url string, manual bool) {
	e.update(func(st *model.Status) bool {
		s := e.sess
		if s == nil || !s.listening {
			return false
		}
		switch {
		case url == "":
			if st.Phase != model.PhaseCaptcha {
				return false
			}
			st.Phase = s.restingPhase(st.Streams)
			st.CaptchaURL = ""
		case manual:
			st.Phase = model.PhaseCaptcha
			st.CaptchaURL = url
		default:
			return false
		}
		s.signalCaptcha()
		return true
	})
}

// ArmBlock возвращает блокировку после падения службы: адаптера ещё нет, окно пришлёт профиль.
func (e *Engine) ArmBlock(o model.Options) error {
	e.ctl.Lock()
	defer e.ctl.Unlock()

	e.mu.Lock()
	busy := e.sess != nil
	e.mu.Unlock()
	if busy {
		return ErrBusy
	}
	err := e.fwApply(firewall.Options{AllowLAN: o.AllowLAN, Bypass: split.Compile(o.Rules).Prefixes})
	if err != nil {
		return err
	}
	e.update(func(st *model.Status) bool {
		*st = model.Status{Phase: model.PhaseBlocked, AwaitingProfile: true}
		return true
	})
	return nil
}

// AwaitProfile отмечает, что служба упала без kill switch и ждёт профиль от окна.
func (e *Engine) AwaitProfile() {
	e.ctl.Lock()
	defer e.ctl.Unlock()

	e.update(func(st *model.Status) bool {
		if e.sess != nil {
			return false
		}
		*st = model.Status{Phase: model.PhaseIdle, AwaitingProfile: true}
		return true
	})
}

// run - рабочий поток сессии. Успешное подключение ждёт здесь отмены.
func (e *Engine) run(s *session) {
	defer close(s.done)

	err := e.establish(s)
	if err == nil {
		e.markConnected(s)
		<-s.ctx.Done()
		err = context.Cause(s.ctx)
	}
	e.finish(s, err)
}

// establish проходит шаги 1-5 из раздела 5 спецификации.
func (e *Engine) establish(s *session) error {
	if err := e.prepare(s); err != nil {
		return err
	}
	if err := e.startCore(s); err != nil {
		return err
	}
	if err := e.openTunnel(s); err != nil {
		return err
	}
	if err := e.applyNetwork(s); err != nil {
		return err
	}
	// Теперь блокировка зависит только от выбора в этом подключении.
	s.holdBlock = s.req.Options.KillSwitch
	return s.stopped()
}

// prepare - шаг 1: проверка профиля и правил. Служба не доверяет данным окна.
func (e *Engine) prepare(s *session) error {
	p := s.req.Profile
	if missing := p.Missing(); len(missing) > 0 {
		return &failure{code: model.ErrBadProfile, msg: fmt.Sprintf("в профиле нет полей %v", missing)}
	}
	cfg, err := wgconf.ParseForTunnel(p.WGConfig, p.MTU)
	if err != nil {
		return &failure{code: model.ErrBadProfile, msg: configMask(p.WGConfig).Mask(err.Error())}
	}
	rules := split.Compile(s.req.Options.Rules)

	e.mu.Lock()
	e.mask = secretmask.ForProfile(p, cfg)
	s.cfg, s.rules = cfg, rules
	e.mu.Unlock()

	for _, skip := range rules.Skipped {
		e.warn(model.WarnRuleSkipped, skip.Rule.Value)
		e.logf(levelWarn, "правило пропущено ("+skip.Reason+"): "+skip.Rule.Value)
	}
	if len(cfg.DNS) == 0 {
		e.warn(model.WarnNoDNS, "")
		e.logf(levelWarn, "в конфиге нет DNS, остаётся системный")
	}
	return nil
}

// configMask прячет длинные слова конфига, который не разобрался. Ключей из него Masker
// не знает, а текст ошибки цитирует строку, и в ней может быть ключ. Часть ошибок разбора
// цитирует её в нижнем регистре.
func configMask(text string) *secretmask.Masker {
	var secrets []string
	for _, w := range strings.FieldsFunc(text, func(r rune) bool { return unicode.IsSpace(r) || r == '=' }) {
		if len(w) >= minConfigToken {
			secrets = append(secrets, w, strings.ToLower(w))
		}
	}
	return secretmask.New(secrets...)
}

// startCore - шаги 2 и 3: физический интерфейс, защита сокетов, запуск ядра и ожидание.
func (e *Engine) startCore(s *session) error {
	if err := s.stopped(); err != nil {
		return err
	}
	listen, err := e.d.FreePort()
	if err != nil {
		return failed(model.ErrCore, err)
	}
	ph, err := e.d.Net.FindPhysical(0)
	if err != nil {
		return failed(model.ErrNoNetwork, err)
	}
	if name, found := e.d.Net.OtherTunnel(0); found {
		e.warn(model.WarnOtherVPN, name)
		e.logf(levelWarn, "маршрут по умолчанию держит другой VPN: "+name)
	}
	e.d.Protect.SetInterface(ph.Index4, ph.Index6)

	// События ядра могут обогнать возврат Start, поэтому приём открывается раньше.
	e.mu.Lock()
	s.ph, s.listen = ph, listen
	s.listening = true
	e.mu.Unlock()

	if err := e.d.Core.Start(s.req.Profile, listen); err != nil {
		return failed(e.d.Classify(err.Error()), err)
	}
	s.push(e.d.Core.Stop)
	e.logf(levelInfo, "ядро запущено, ждём потоки")
	return e.waitCore(s)
}

// waitCore ждёт connected. Пока открыта ручная капча, таймаут стоит, после закрытия идёт заново.
func (e *Engine) waitCore(s *session) error {
	timer := time.NewTimer(e.d.CoreTimeout)
	defer timer.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return context.Cause(s.ctx)
		case <-s.coreUp:
			return nil
		case <-s.captcha:
			if !e.captchaOpen() {
				timer.Reset(e.d.CoreTimeout)
			}
		case <-timer.C:
			if !e.captchaOpen() {
				return &failure{code: model.ErrServerSilent, msg: "ядро не подняло потоки за отведённое время"}
			}
		}
	}
}

func (e *Engine) captchaOpen() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.st.Phase == model.PhaseCaptcha
}

// openTunnel - шаг 4: адаптер, адрес, устройство WireGuard и первое рукопожатие.
func (e *Engine) openTunnel(s *session) error {
	if err := s.stopped(); err != nil {
		return err
	}
	dev, err := e.d.Tunnels.Open(s.cfg, s.listen)
	if err != nil {
		return failed(model.ErrAdapter, err)
	}
	s.push(dev.Close)
	luid := dev.LUID()

	e.mu.Lock()
	s.luid = luid
	e.mu.Unlock()

	if err := e.d.Net.ConfigureInterface(luid, s.cfg.Addresses, s.cfg.MTU); err != nil {
		return failed(model.ErrAdapter, err)
	}
	if err := s.stopped(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(s.ctx, e.d.HandshakeTimeout)
	defer cancel()
	err = dev.WaitHandshake(ctx)
	if stop := s.stopped(); stop != nil {
		return stop
	}
	if err != nil {
		return failed(model.ErrNoHandshake, err)
	}
	return nil
}

// applyNetwork - шаг 5. Сбой любой части, включая блокировку, это сбой подключения: без
// блокировки туннель не поднимается. Обратные операции кладутся до вызова, потому что
// SetBypass и ApplyTunnelRoutes при ошибке могут оставить часть маршрутов.
func (e *Engine) applyNetwork(s *session) error {
	if err := s.stopped(); err != nil {
		return err
	}
	killSwitch := s.req.Options.KillSwitch

	s.push(func() {
		if !s.keepBlock {
			e.fwDisable()
		}
	})
	if killSwitch {
		e.mu.Lock()
		opts := s.firewallOptions()
		e.mu.Unlock()
		if err := e.fwApply(opts); err != nil {
			return failed(model.ErrAdapter, err)
		}
	}

	added, err := e.resolveDomains(s)
	if err != nil {
		return err
	}
	if added {
		e.mu.Lock()
		opts := s.firewallOptions()
		e.mu.Unlock()
		if err := e.fwRefresh(opts); err != nil {
			return failed(model.ErrAdapter, err)
		}
	}

	e.mu.Lock()
	bypass := s.bypass()
	e.mu.Unlock()
	s.push(func() { e.logFailure("снятие маршрутов обхода", e.d.Net.ClearBypass()) })
	if err := e.d.Net.SetBypass(s.ph, bypass); err != nil {
		return failed(model.ErrAdapter, err)
	}
	if err := s.stopped(); err != nil {
		return err
	}

	s.push(func() { e.logFailure("снятие маршрутов туннеля", e.d.Net.ClearTunnel(s.luid)) })
	if err := e.d.Net.ApplyTunnelRoutes(s.luid, s.cfg.AllowedPrefixes(), s.cfg.DNS); err != nil {
		return failed(model.ErrAdapter, err)
	}

	// Блокировка от прошлого подключения, а в этом kill switch выключен.
	if !killSwitch {
		e.fwClear()
	}
	return nil
}

// resolveDomains разрешает домены по одному, иначе неразрешённый домен не назвать
// в предупреждении. Сообщает, появились ли новые адреса.
func (e *Engine) resolveDomains(s *session) (added bool, err error) {
	for _, domain := range s.rules.Domains {
		addrs := e.d.Resolver.Resolve(s.ctx, []string{domain}, s.ph)
		if err := s.stopped(); err != nil {
			return false, err
		}
		if len(addrs) == 0 {
			e.warn(model.WarnDomainUnresolved, domain)
			e.logf(levelWarn, "домен не разрешился: "+domain)
			continue
		}
		e.mu.Lock()
		if s.addResolved(addrs) {
			added = true
		}
		e.mu.Unlock()
	}
	return added, nil
}

// markConnected - шаг 6. Открытая капча остаётся на экране, закрытие вернёт в Connected.
func (e *Engine) markConnected(s *session) {
	e.update(func(st *model.Status) bool {
		s.established = true
		if st.Phase != model.PhaseCaptcha {
			st.Phase = model.PhaseConnected
		}
		return true
	})
	e.logf(levelInfo, "подключено")
}

// finish откатывает всё сделанное и выставляет итог сбоя. Итог отмены по команде
// выставляет Disconnect, ему ещё снимать блокировку.
func (e *Engine) finish(s *session, err error) {
	var f *failure
	isFailure := errors.As(err, &f)
	s.keepBlock = isFailure && s.holdBlock

	e.mu.Lock()
	s.listening = false
	e.mu.Unlock()

	for _, undo := range slices.Backward(s.undo) {
		undo()
	}

	if !isFailure {
		e.update(func(*model.Status) bool {
			e.sess = nil
			return false
		})
		return
	}
	e.logf(levelError, "подключение прервано: "+f.Error())
	detail := e.detailFor(f)
	e.update(func(st *model.Status) bool {
		e.sess = nil
		phase := model.PhaseError
		if s.keepBlock {
			phase = model.PhaseBlocked
		}
		*st = model.Status{
			Phase: phase, Code: f.code, Detail: detail,
			ProfileID: st.ProfileID, Warnings: st.Warnings,
		}
		return true
	})
}

// detailFor даёт текст ошибки для кодов без постоянного текста в окне.
func (e *Engine) detailFor(f *failure) string {
	switch f.code {
	case model.ErrAdapter, model.ErrCore, model.ErrBadProfile:
		return e.masked(f.msg)
	default:
		return ""
	}
}

// fwApply ставит блокировку, а если она уже стоит, обновляет разрешения.
func (e *Engine) fwApply(o firewall.Options) error {
	e.fwMu.Lock()
	defer e.fwMu.Unlock()
	if e.fwOn {
		return e.d.FW.Update(o)
	}
	if err := e.d.FW.Enable(o); err != nil {
		return err
	}
	e.fwOn = true
	return nil
}

// fwRefresh обновляет разрешения стоящей блокировки. Снятую не трогает: опоздавшее
// обновление иначе вернуло бы её, Update при выключенной блокировке работает как Enable.
func (e *Engine) fwRefresh(o firewall.Options) error {
	e.fwMu.Lock()
	defer e.fwMu.Unlock()
	if !e.fwOn {
		return nil
	}
	return e.d.FW.Update(o)
}

// fwDisable снимает блокировку. Снятие без блокировки безопасно.
func (e *Engine) fwDisable() {
	e.fwMu.Lock()
	defer e.fwMu.Unlock()
	e.d.FW.Disable()
	e.fwOn = false
}

// fwClear снимает блокировку, только если она стоит.
func (e *Engine) fwClear() {
	e.fwMu.Lock()
	defer e.fwMu.Unlock()
	if e.fwOn {
		e.d.FW.Disable()
		e.fwOn = false
	}
}

// update меняет статус и, если fn вернула true, сообщает новый снимок. notifyMu держит
// порядок сообщений. Внутри fn mu занят: зависимости из неё не вызываются. OnChange
// вызывается без mu, поэтому может читать Status, но не менять состояние движка.
func (e *Engine) update(fn func(*model.Status) bool) {
	e.notifyMu.Lock()
	defer e.notifyMu.Unlock()

	e.mu.Lock()
	changed := fn(&e.st)
	snap := e.snapshot()
	e.mu.Unlock()

	if changed {
		e.d.OnChange(snap)
	}
}

// snapshot копирует статус. Вызывается под mu.
func (e *Engine) snapshot() model.Status {
	st := e.st
	st.Warnings = slices.Clone(e.st.Warnings)
	return st
}

func (e *Engine) warn(code model.WarningCode, value string) {
	e.update(func(st *model.Status) bool {
		st.Warnings = append(st.Warnings, model.Warning{Code: code, Value: value})
		return true
	})
}

func (e *Engine) masked(s string) string {
	e.mu.Lock()
	m := e.mask
	e.mu.Unlock()
	return m.Mask(s)
}

// logf пишет в журнал. Текст проходит через Masker, другого пути в журнал нет.
func (e *Engine) logf(level, msg string) {
	e.d.Logf(level, e.masked(msg))
}

// logFailure пишет ошибку обратной операции. Откат идёт дальше: чем больше снято, тем лучше.
func (e *Engine) logFailure(what string, err error) {
	if err != nil {
		e.logf(levelWarn, what+": "+err.Error())
	}
}
