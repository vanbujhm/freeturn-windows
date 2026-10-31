package engine

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vanbujhm/freeturn-windows/internal/firewall"
	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/netcfg"
	"github.com/vanbujhm/freeturn-windows/internal/secretmask"
)

const captchaURL = "http://127.0.0.1:1/"

// disconnectAsync запускает Disconnect и возвращает канал его завершения.
func disconnectAsync(e *Engine) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.Disconnect()
	}()
	return done
}

func TestConnectOrder(t *testing.T) {
	h := newHarness(t)
	h.core.silent = true
	h.connect(testRequest())
	h.waitCall("core.start")
	h.wantNotCalled("tunnel.open")

	_ = h.log.hit("core.connected")
	h.e.OnCoreState("connected", 3, 12, "")

	st := h.waitPhase(model.PhaseConnected)
	h.wantLog("protect.set", "core.start", "core.connected", "tunnel.open", "net.configure",
		"tunnel.handshake", "fw.enable", "net.bypass", "net.routes")
	if st.Streams != 3 || st.Total != 12 {
		t.Errorf("потоки %d/%d, ожидалось 3/12", st.Streams, st.Total)
	}
	if st.ProfileID != "p1" {
		t.Errorf("ProfileID = %q", st.ProfileID)
	}
	if h.prot.i4 != 11 || h.prot.i6 != 12 {
		t.Errorf("защита получила индексы %d, %d", h.prot.i4, h.prot.i6)
	}
	o := h.fw.last()
	if o.TunLUID != testLUID || !o.AllowLAN || !slices.Equal(o.DNS, []netip.Addr{netip.MustParseAddr("198.51.100.53")}) {
		t.Errorf("параметры брандмауэра %+v", o)
	}
	wantAllowed := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	if !slices.Equal(h.net.allowed, wantAllowed) || len(h.net.dns) != 1 {
		t.Errorf("маршруты %v, DNS %v", h.net.allowed, h.net.dns)
	}
}

func TestConnectKillSwitchOff(t *testing.T) {
	h := newHarness(t)
	req := testRequest()
	req.Options.KillSwitch = false
	h.connect(req)
	h.waitPhase(model.PhaseConnected)
	h.wantNotCalled("fw.enable", "fw.update")
	h.wantCalled("net.bypass", "net.routes")
}

func TestDisconnectOrder(t *testing.T) {
	h := newHarness(t)
	h.connect(testRequest())
	h.waitPhase(model.PhaseConnected)
	before := len(h.log.snapshot())

	h.e.Disconnect()

	got := h.log.snapshot()[before:]
	want := []string{"net.clear", "net.bypassClear", "fw.disable", "tunnel.close", "core.stop"}
	if !slices.Equal(got, want) {
		t.Errorf("порядок отключения\n got %v\nwant %v", got, want)
	}
	if st := h.e.Status(); st.Phase != model.PhaseIdle || st.Streams != 0 {
		t.Errorf("статус %+v", st)
	}
}

func TestRollbackCoreStartFails(t *testing.T) {
	h := newHarness(t)
	h.log.failOn("core.start", errBoom)
	h.connect(testRequest())
	st := h.waitPhase(model.PhaseError)
	if st.Code != model.ErrCore {
		t.Errorf("Code = %q", st.Code)
	}
	if st.Detail != errBoom.Error() {
		t.Errorf("Detail = %q", st.Detail)
	}
	h.wantNotCalled("tunnel.open", "fw.enable")
}

func TestRollbackCoreTimeout(t *testing.T) {
	h := newHarness(t, withCoreTimeout(5*time.Millisecond))
	h.core.silent = true
	h.connect(testRequest())
	st := h.waitPhase(model.PhaseError)
	if st.Code != model.ErrServerSilent {
		t.Errorf("Code = %q", st.Code)
	}
	if st.Detail != "" {
		t.Errorf("у кода с постоянным текстом Detail = %q", st.Detail)
	}
	h.wantCalled("core.stop")
	h.wantNotCalled("tunnel.open")
}

func TestRollbackTunnelOpenFails(t *testing.T) {
	h := newHarness(t)
	h.log.failOn("tunnel.open", errBoom)
	h.connect(testRequest())
	st := h.waitPhase(model.PhaseError)
	if st.Code != model.ErrAdapter || st.Detail != errBoom.Error() {
		t.Errorf("Code = %q, Detail = %q", st.Code, st.Detail)
	}
	h.wantCalled("core.stop")
	h.wantNotCalled("net.configure", "tunnel.close", "fw.enable")
}

func TestRollbackNoHandshake(t *testing.T) {
	h := newHarness(t, withHandshakeTimeout(5*time.Millisecond))
	h.dev.hang = true
	h.connect(testRequest())
	st := h.waitPhase(model.PhaseError)
	if st.Code != model.ErrNoHandshake {
		t.Errorf("Code = %q", st.Code)
	}
	h.wantCalled("tunnel.close", "core.stop")
	h.wantNotCalled("fw.enable", "net.bypass", "net.routes")
}

func TestRollbackRoutesFail(t *testing.T) {
	h := newHarness(t)
	h.log.failOn("net.routes", errBoom)
	h.connect(testRequest())
	st := h.waitPhase(model.PhaseError)
	if st.Code != model.ErrAdapter {
		t.Errorf("Code = %q", st.Code)
	}
	h.wantLog("protect.set", "core.start", "tunnel.open", "net.configure", "tunnel.handshake",
		"fw.enable", "net.bypass", "net.routes",
		"net.clear", "net.bypassClear", "fw.disable", "tunnel.close", "core.stop")
}

func TestRollbackFirewallEnableFails(t *testing.T) {
	h := newHarness(t)
	h.log.failOn("fw.enable", errBoom)
	h.connect(testRequest())
	st := h.waitPhase(model.PhaseError)
	if st.Code != model.ErrAdapter {
		t.Errorf("Code = %q", st.Code)
	}
	h.wantCalled("tunnel.close", "core.stop")
	h.wantNotCalled("net.bypass", "net.routes")
}

// Update вызывается только при уже стоящей блокировке, поэтому сбой остаётся в Blocked.
func TestRollbackFirewallUpdateFails(t *testing.T) {
	h := newHarness(t)
	if err := h.e.ArmBlock(model.Options{KillSwitch: true}); err != nil {
		t.Fatal(err)
	}
	h.log.failOn("fw.update", errBoom)
	h.connect(testRequest())
	st := h.waitPhase(model.PhaseBlocked)
	if st.Code != model.ErrAdapter {
		t.Errorf("Code = %q", st.Code)
	}
	h.wantCalled("tunnel.close", "core.stop")
	h.wantNotCalled("fw.disable", "net.bypass", "net.routes")
}

func TestRollbackOtherSteps(t *testing.T) {
	cases := []struct {
		step    string
		called  []string
		skipped []string
	}{
		{"net.configure", []string{"tunnel.close", "core.stop"}, []string{"tunnel.handshake", "fw.enable"}},
		{"net.bypass", []string{"net.bypassClear", "fw.disable", "tunnel.close", "core.stop"}, []string{"net.routes"}},
	}
	for _, c := range cases {
		t.Run(c.step, func(t *testing.T) {
			h := newHarness(t)
			h.log.failOn(c.step, errBoom)
			h.connect(testRequest())
			st := h.waitPhase(model.PhaseError)
			if st.Code != model.ErrAdapter {
				t.Errorf("Code = %q", st.Code)
			}
			h.wantCalled(c.called...)
			h.wantNotCalled(c.skipped...)
		})
	}
}

func TestCaptchaManualPhase(t *testing.T) {
	h := newHarness(t)
	h.core.silent = true
	h.connect(testRequest())
	h.waitCall("core.start")
	h.e.OnCaptcha(captchaURL, true)
	st := h.waitPhase(model.PhaseCaptcha)
	if st.CaptchaURL != captchaURL {
		t.Errorf("CaptchaURL = %q", st.CaptchaURL)
	}
}

func TestCaptchaSuspendsCoreTimeout(t *testing.T) {
	h := newHarness(t, withCoreTimeout(5*time.Millisecond))
	h.core.silent = true
	h.core.onStart = func() { h.e.OnCaptcha(captchaURL, true) }
	h.connect(testRequest())
	h.waitCall("core.start")

	time.Sleep(30 * time.Millisecond)
	if st := h.e.Status(); st.Phase != model.PhaseCaptcha {
		t.Fatalf("таймаут сработал при открытой капче: %+v", st)
	}
	h.wantNotCalled("core.stop")

	// Капчу закрыли, а потоков нет: таймаут снова идёт.
	h.e.OnCaptcha("", false)
	st := h.waitPhase(model.PhaseError)
	if st.Code != model.ErrServerSilent {
		t.Errorf("Code = %q", st.Code)
	}
}

func TestCaptchaAutoHidden(t *testing.T) {
	h := newHarness(t)
	h.core.silent = true
	h.connect(testRequest())
	h.waitCall("core.start")
	h.e.OnCaptcha(captchaURL, false)
	if st := h.e.Status(); st.Phase != model.PhaseConnecting || st.CaptchaURL != "" {
		t.Errorf("статус %+v", st)
	}
}

func TestCaptchaAutoDoesNotSuspendTimeout(t *testing.T) {
	h := newHarness(t, withCoreTimeout(5*time.Millisecond))
	h.core.silent = true
	h.core.onStart = func() { h.e.OnCaptcha(captchaURL, false) }
	h.connect(testRequest())
	if st := h.waitPhase(model.PhaseError); st.Code != model.ErrServerSilent {
		t.Errorf("Code = %q", st.Code)
	}
}

func TestCaptchaClosed(t *testing.T) {
	h := newHarness(t)
	h.core.silent = true
	h.connect(testRequest())
	h.waitCall("core.start")
	h.e.OnCaptcha(captchaURL, true)
	h.waitPhase(model.PhaseCaptcha)

	h.e.OnCaptcha("", false)

	st := h.waitPhase(model.PhaseConnecting)
	if st.CaptchaURL != "" {
		t.Errorf("CaptchaURL = %q", st.CaptchaURL)
	}
	h.e.OnCoreState("connected", 1, 12, "")
	h.waitPhase(model.PhaseConnected)
}

// Капча пришла, пока идут шаги 4 и 5: они не ждут её, а закрытие вернёт в Connected.
func TestCaptchaAfterCoreConnected(t *testing.T) {
	h := newHarness(t)
	release := h.log.hold("fw.enable")
	defer release()
	h.connect(testRequest())
	h.waitCall("fw.enable")
	h.e.OnCaptcha(captchaURL, true)
	release()

	h.waitCall("net.routes")
	st := h.waitPhase(model.PhaseCaptcha)
	if st.CaptchaURL != captchaURL {
		t.Errorf("CaptchaURL = %q", st.CaptchaURL)
	}
	h.e.OnCoreState("connected", 3, 12, "")
	h.waitFor("подключение закончено", func() bool { return h.establishedNow() })
	h.e.OnCaptcha("", false)
	h.waitPhase(model.PhaseConnected)
}

func (h *harness) establishedNow() bool {
	h.e.mu.Lock()
	defer h.e.mu.Unlock()
	return h.e.sess != nil && h.e.sess.established
}

// Капча в уже работающем туннеле: потоки упали до нуля, после закрытия это Reconnecting.
func TestCaptchaWhileConnected(t *testing.T) {
	h := newHarness(t)
	h.connect(testRequest())
	h.waitPhase(model.PhaseConnected)

	h.e.OnCoreState("captcha", 0, 12, "")
	h.e.OnCaptcha(captchaURL, true)
	h.waitPhase(model.PhaseCaptcha)
	h.e.OnCaptcha("", false)
	h.waitPhase(model.PhaseReconnecting)
	h.wantNotCalled("net.clear")
}

func TestCoreReconnectFlipsPhase(t *testing.T) {
	h := newHarness(t)
	h.connect(testRequest())
	h.waitPhase(model.PhaseConnected)

	h.e.OnCoreState("connecting", 0, 12, "")
	h.waitPhase(model.PhaseReconnecting)
	h.wantNotCalled("net.clear", "tunnel.close", "core.stop")

	h.e.OnCoreState("connected", 2, 12, "")
	st := h.waitPhase(model.PhaseConnected)
	if st.Streams != 2 {
		t.Errorf("Streams = %d", st.Streams)
	}
}

func TestDisconnectDuringConnecting(t *testing.T) {
	h := newHarness(t)
	h.core.silent = true
	h.connect(testRequest())
	h.waitCall("core.start")

	h.e.Disconnect()

	h.wantLog("protect.set", "core.start", "core.stop")
	if st := h.e.Status(); st.Phase != model.PhaseIdle {
		t.Errorf("статус %+v", st)
	}
}

func TestDisconnectDuringCaptcha(t *testing.T) {
	h := newHarness(t)
	h.core.silent = true
	h.connect(testRequest())
	h.waitCall("core.start")
	h.e.OnCaptcha(captchaURL, true)
	h.waitPhase(model.PhaseCaptcha)

	h.e.Disconnect()

	h.wantLog("protect.set", "core.start", "core.stop")
	if st := h.e.Status(); st.Phase != model.PhaseIdle || st.CaptchaURL != "" {
		t.Errorf("статус %+v", st)
	}
}

func TestDisconnectDuringHandshake(t *testing.T) {
	h := newHarness(t)
	h.dev.hang = true
	h.connect(testRequest())
	h.waitCall("tunnel.handshake")

	h.e.Disconnect()

	select {
	case <-h.dev.cancelled:
	default:
		t.Error("WaitHandshake не получил отмену ctx")
	}
	h.wantCalled("tunnel.close", "core.stop")
	h.wantNotCalled("fw.enable")
	if st := h.e.Status(); st.Phase != model.PhaseIdle {
		t.Errorf("статус %+v", st)
	}
}

func TestDisconnectDuringResolve(t *testing.T) {
	h := newHarness(t)
	h.res.hang = true
	req := testRequest()
	req.Options.Rules = []model.Rule{{Kind: model.RuleDomain, Value: "example.com"}}
	h.connect(req)
	h.waitCall("resolve")

	h.e.Disconnect()

	h.wantCalled("fw.disable", "tunnel.close", "core.stop")
	h.wantNotCalled("net.bypass", "net.routes")
	if st := h.e.Status(); st.Phase != model.PhaseIdle {
		t.Errorf("статус %+v", st)
	}
}

// Обычная установка укладывается в срок: снятие ждёт её и не пересекается с ней.
func TestDisconnectWaitsFirewallWithinGrace(t *testing.T) {
	h := newHarness(t)
	release := h.log.hold("fw.enable")
	defer release()
	h.connect(testRequest())
	h.waitCall("fw.enable")

	done := disconnectAsync(h.e)
	time.Sleep(10 * time.Millisecond)
	h.wantNotCalled("fw.disable")
	release()
	<-done

	h.wantCalled("fw.disable", "tunnel.close", "core.stop")
	h.wantNotCalled("net.bypass", "net.routes")
	if st := h.e.Status(); st.Phase != model.PhaseIdle {
		t.Errorf("статус %+v", st)
	}
}

// Зависшая установка не держит блокировку: после FirewallGrace Disable приходит мимо неё,
// а Disconnect дожидается потока, потому что откат идёт только там.
func TestDisconnectHungFirewallGetsDisable(t *testing.T) {
	for _, step := range []string{"fw.enable", "fw.update"} {
		t.Run(step, func(t *testing.T) {
			h := newHarness(t, withFirewallGrace(time.Millisecond))
			if step == "fw.update" {
				if err := h.e.ArmBlock(model.Options{KillSwitch: true}); err != nil {
					t.Fatal(err)
				}
			}
			release := h.log.hold(step)
			defer release()
			h.connect(testRequest())
			h.waitCall(step)

			done := disconnectAsync(h.e)
			h.waitCall("fw.disable")

			select {
			case <-done:
				t.Fatal("Disconnect не дождался потока")
			default:
			}
			h.wantNotCalled("tunnel.close", "core.stop")
			if !slices.ContainsFunc(h.logLines(), func(l string) bool {
				return strings.HasPrefix(l, "warn: брандмауэр не отвечает")
			}) {
				t.Errorf("нет предупреждения в журнале: %v", h.logLines())
			}

			release()
			<-done
			h.wantCalled("tunnel.close", "core.stop")
			h.wantNotCalled("net.bypass", "net.routes")
			if st := h.e.Status(); st.Phase != model.PhaseIdle {
				t.Errorf("статус %+v", st)
			}
			h.wantFirewallOff()
		})
	}
}

// Срок вышел, но брандмауэр ни при чём: откат идёт своим порядком, лишнего Disable нет.
func TestDisconnectSlowRollbackKeepsOrder(t *testing.T) {
	h := newHarness(t, withFirewallGrace(time.Millisecond))
	h.connect(testRequest())
	h.waitPhase(model.PhaseConnected)
	release := h.log.hold("tunnel.close")
	defer release()

	done := disconnectAsync(h.e)
	h.waitCall("tunnel.close")
	time.Sleep(10 * time.Millisecond)
	release()
	<-done

	if n := h.log.count("fw.disable"); n != 1 {
		t.Errorf("fw.disable вызван %d раз", n)
	}
}

func (h *harness) wantFirewallOff() {
	h.t.Helper()
	h.e.fwMu.Lock()
	defer h.e.fwMu.Unlock()
	if h.e.fwOn {
		h.t.Error("блокировка осталась")
	}
}

func TestConnectWhileBusy(t *testing.T) {
	h := newHarness(t)
	h.core.silent = true
	h.connect(testRequest())
	h.waitCall("core.start")

	if err := h.e.Connect(testRequest()); !errors.Is(err, ErrBusy) {
		t.Fatalf("второй Connect: %v", err)
	}

	h.wantNotCalled("core.stop")
	h.e.OnCoreState("connected", 3, 12, "")
	h.waitPhase(model.PhaseConnected)
	if err := h.e.Connect(testRequest()); !errors.Is(err, ErrBusy) {
		t.Fatalf("Connect в Connected: %v", err)
	}
}

func TestConnectAfterError(t *testing.T) {
	h := newHarness(t)
	h.log.failOn("tunnel.open", errBoom)
	h.connect(testRequest())
	h.waitPhase(model.PhaseError)

	h.log.failOn("tunnel.open", nil)
	h.connect(testRequest())
	if st := h.waitPhase(model.PhaseConnected); st.Code != "" || st.Detail != "" {
		t.Errorf("старая ошибка осталась: %+v", st)
	}
}

func TestNoNetwork(t *testing.T) {
	h := newHarness(t)
	h.net.physErr = netcfg.ErrNoNetwork
	h.connect(testRequest())
	st := h.waitPhase(model.PhaseError)
	if st.Code != model.ErrNoNetwork {
		t.Errorf("Code = %q", st.Code)
	}
	h.wantLog()
}

// Не удалось прочитать сеть: это не «нет подключения», человеку нужен текст ошибки.
func TestFindPhysicalFails(t *testing.T) {
	h := newHarness(t)
	req := testRequest()
	h.net.physErr = errors.New("чтение адаптеров: " + req.Profile.ClientID)
	h.connect(req)
	st := h.waitPhase(model.PhaseError)
	if st.Code != model.ErrCore || st.Detail != "чтение адаптеров: "+secretmask.Replacement {
		t.Errorf("Code = %q, Detail = %q", st.Code, st.Detail)
	}
	h.wantLog()
}

func TestOtherVPNWarns(t *testing.T) {
	h := newHarness(t)
	h.net.other = "AmneziaVPN"
	h.connect(testRequest())
	h.waitPhase(model.PhaseConnected)
	h.wantWarning(model.Warning{Code: model.WarnOtherVPN, Value: "AmneziaVPN"})
}

func TestNoDNSWarns(t *testing.T) {
	h := newHarness(t)
	req := testRequest()
	req.Profile.WGConfig = wgConfig("")
	h.connect(req)
	h.waitPhase(model.PhaseConnected)
	h.wantWarning(model.Warning{Code: model.WarnNoDNS})
}

func TestWarningsResetOnConnect(t *testing.T) {
	h := newHarness(t)
	h.net.other = "AmneziaVPN"
	h.connect(testRequest())
	h.waitPhase(model.PhaseConnected)
	h.e.Disconnect()

	h.net.other = ""
	h.connect(testRequest())
	if st := h.waitPhase(model.PhaseConnected); len(st.Warnings) != 0 {
		t.Errorf("предупреждения %+v", st.Warnings)
	}
}

func TestFatalWithKillSwitch(t *testing.T) {
	h := newHarness(t)
	h.connect(testRequest())
	h.waitPhase(model.PhaseConnected)

	h.e.OnCoreState("error", 0, 12, "fatal: CALL_FULL")

	st := h.waitPhase(model.PhaseBlocked)
	if st.Code != model.ErrCallFull {
		t.Errorf("Code = %q", st.Code)
	}
	h.wantNotCalled("fw.disable")
	h.wantCalled("net.clear", "net.bypassClear", "tunnel.close", "core.stop")
}

func TestFatalWithoutKillSwitch(t *testing.T) {
	h := newHarness(t)
	req := testRequest()
	req.Options.KillSwitch = false
	h.connect(req)
	h.waitPhase(model.PhaseConnected)

	h.e.OnCoreState("error", 0, 12, "fatal: CALL_FULL")

	st := h.waitPhase(model.PhaseError)
	if st.Code != model.ErrCallFull {
		t.Errorf("Code = %q", st.Code)
	}
	h.wantCalled("fw.disable", "net.clear", "tunnel.close", "core.stop")
}

func TestFatalWhileConnecting(t *testing.T) {
	h := newHarness(t)
	h.core.silent = true
	h.connect(testRequest())
	h.waitCall("core.start")

	h.e.OnCoreState("error", 0, 12, "неизвестный сбой")

	st := h.waitPhase(model.PhaseError)
	if st.Code != model.ErrCore || st.Detail != "неизвестный сбой" {
		t.Errorf("Code = %q, Detail = %q", st.Code, st.Detail)
	}
	h.wantCalled("core.stop")
	h.wantNotCalled("tunnel.open")
}

// Подключение ещё не прошло шаг 5: фатальный сбой даёт Error и не оставляет блокировки.
func TestFatalDuringHandshake(t *testing.T) {
	h := newHarness(t)
	h.dev.hang = true
	h.connect(testRequest())
	h.waitCall("tunnel.handshake")

	h.e.OnCoreState("error", 0, 12, "fatal: CALL_FULL")

	st := h.waitPhase(model.PhaseError)
	if st.Code != model.ErrCallFull {
		t.Errorf("Code = %q", st.Code)
	}
	h.wantCalled("tunnel.close", "core.stop")
	h.wantNotCalled("fw.enable")
}

// Правило: блокировки нет до шага 6. Сбой ядра на шаге 5 нового подключения даёт Error и снятый
// брандмауэр, где бы ни застало его событие.
func step5Cases() map[string]func(*harness) (arrive string, release func()) {
	return map[string]func(*harness) (string, func()){
		"domains": func(h *harness) (string, func()) {
			h.res.hang = true
			return "resolve", func() {}
		},
		"firewall": func(h *harness) (string, func()) { return "fw.enable", h.log.hold("fw.enable") },
		"bypass":   func(h *harness) (string, func()) { return "net.bypass", h.log.hold("net.bypass") },
		"routes":   func(h *harness) (string, func()) { return "net.routes", h.log.hold("net.routes") },
	}
}

func step5Request() model.ConnectRequest {
	req := testRequest()
	req.Options.Rules = []model.Rule{{Kind: model.RuleDomain, Value: "example.com"}}
	return req
}

func TestFatalDuringStep5(t *testing.T) {
	for name, setup := range step5Cases() {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			arrive, release := setup(h)
			defer release()
			h.connect(step5Request())
			h.waitCall(arrive)

			h.e.OnCoreState("error", 0, 12, "fatal: CALL_FULL")
			release()

			st := h.waitPhase(model.PhaseError)
			if st.Code != model.ErrCallFull {
				t.Errorf("Code = %q", st.Code)
			}
			h.wantCalled("fw.disable", "tunnel.close", "core.stop")
			h.wantFirewallOff()
			for _, c := range h.changeLog() {
				if c.Phase == model.PhaseConnected || c.Phase == model.PhaseBlocked {
					t.Errorf("лишняя фаза %s", c.Phase)
				}
			}
		})
	}
}

// Подключение начато из Blocked: блокировка стояла раньше и остаётся, даже если новый запрос
// без kill switch.
func TestFatalDuringStep5FromBlocked(t *testing.T) {
	for _, killSwitch := range []bool{true, false} {
		t.Run(fmt.Sprintf("killSwitch=%v", killSwitch), func(t *testing.T) {
			h := newHarness(t)
			if err := h.e.ArmBlock(model.Options{KillSwitch: true}); err != nil {
				t.Fatal(err)
			}
			release := h.log.hold("net.routes")
			defer release()
			req := testRequest()
			req.Options.KillSwitch = killSwitch
			h.connect(req)
			h.waitCall("net.routes")

			h.e.OnCoreState("error", 0, 12, "fatal: CALL_FULL")
			release()

			st := h.waitPhase(model.PhaseBlocked)
			if st.Code != model.ErrCallFull {
				t.Errorf("Code = %q", st.Code)
			}
			h.wantCalled("net.clear", "tunnel.close", "core.stop")
			h.wantNotCalled("fw.disable")
		})
	}
}

func TestCoreIdleIsFatal(t *testing.T) {
	t.Run("connecting", func(t *testing.T) {
		h := newHarness(t)
		h.core.silent = true
		h.connect(testRequest())
		h.waitCall("core.start")
		h.e.OnCoreState("idle", 0, 0, "")
		st := h.waitPhase(model.PhaseError)
		if st.Code != model.ErrCore || st.Detail == "" {
			t.Errorf("Code = %q, Detail = %q", st.Code, st.Detail)
		}
		h.wantCalled("core.stop")
		h.wantNotCalled("tunnel.open")
	})
	t.Run("connected", func(t *testing.T) {
		h := newHarness(t)
		h.connect(testRequest())
		h.waitPhase(model.PhaseConnected)
		h.e.OnCoreState("idle", 0, 12, "")
		if st := h.waitPhase(model.PhaseBlocked); st.Code != model.ErrCore {
			t.Errorf("Code = %q", st.Code)
		}
	})
}

func TestDisconnectFromBlocked(t *testing.T) {
	h := newHarness(t)
	h.connect(testRequest())
	h.waitPhase(model.PhaseConnected)
	h.e.OnCoreState("error", 0, 12, "fatal: CALL_FULL")
	h.waitPhase(model.PhaseBlocked)

	h.e.Disconnect()

	h.wantCalled("fw.disable")
	st := h.e.Status()
	if st.Phase != model.PhaseIdle || st.Code != "" {
		t.Errorf("статус %+v", st)
	}
}

func TestArmBlock(t *testing.T) {
	h := newHarness(t)
	opts := model.Options{KillSwitch: true, AllowLAN: true}
	if err := h.e.ArmBlock(opts); err != nil {
		t.Fatal(err)
	}
	h.wantLog("fw.enable")
	if o := h.fw.last(); o.TunLUID != 0 || !o.AllowLAN {
		t.Errorf("параметры брандмауэра %+v", o)
	}
	st := h.e.Status()
	if st.Phase != model.PhaseBlocked || !st.AwaitingProfile {
		t.Errorf("статус %+v", st)
	}
}

func TestArmBlockFails(t *testing.T) {
	h := newHarness(t)
	h.log.failOn("fw.enable", errBoom)
	if err := h.e.ArmBlock(model.Options{KillSwitch: true}); !errors.Is(err, errBoom) {
		t.Fatalf("ArmBlock: %v", err)
	}
	if st := h.e.Status(); st.Phase != model.PhaseIdle || !st.AwaitingProfile {
		t.Errorf("статус %+v", st)
	}
	if !slices.ContainsFunc(h.logLines(), func(l string) bool { return strings.HasPrefix(l, "error: ") }) {
		t.Errorf("сбой не в журнале: %v", h.logLines())
	}
	h.wantFirewallOff()
}

func TestArmBlockWhileBusy(t *testing.T) {
	h := newHarness(t)
	h.connect(testRequest())
	h.waitPhase(model.PhaseConnected)
	if err := h.e.ArmBlock(model.Options{KillSwitch: true}); !errors.Is(err, ErrBusy) {
		t.Fatalf("ArmBlock: %v", err)
	}
	if st := h.e.Status(); st.Phase != model.PhaseConnected {
		t.Errorf("статус %+v", st)
	}
}

func TestConnectFromBlockedKeepsBlock(t *testing.T) {
	h := newHarness(t)
	if err := h.e.ArmBlock(model.Options{KillSwitch: true}); err != nil {
		t.Fatal(err)
	}
	h.connect(testRequest())
	st := h.waitPhase(model.PhaseConnected)
	if st.AwaitingProfile {
		t.Error("AwaitingProfile не сброшен")
	}
	h.wantCalled("fw.update")
	h.wantNotCalled("fw.disable")
	if got := h.fw.last().TunLUID; got != testLUID {
		t.Errorf("TunLUID = %#x", got)
	}
	if n := h.log.count("fw.enable"); n != 1 {
		t.Errorf("fw.enable вызван %d раз", n)
	}
}

func TestFailedConnectFromBlockedStaysBlocked(t *testing.T) {
	h := newHarness(t)
	if err := h.e.ArmBlock(model.Options{KillSwitch: true}); err != nil {
		t.Fatal(err)
	}
	h.log.failOn("tunnel.open", errBoom)
	h.connect(testRequest())
	st := h.waitPhase(model.PhaseBlocked)
	if st.Code != model.ErrAdapter || st.AwaitingProfile {
		t.Errorf("статус %+v", st)
	}
	h.wantCalled("core.stop")
	h.wantNotCalled("fw.disable")

	// Сбой на шаге 5 тоже не снимает блокировку.
	h.log.failOn("tunnel.open", nil)
	h.log.failOn("net.routes", errBoom)
	h.connect(testRequest())
	h.waitCall("net.routes")
	h.waitPhase(model.PhaseBlocked)
	h.wantCalled("net.clear", "tunnel.close")
	h.wantNotCalled("fw.disable")

	h.e.Disconnect()
	h.wantCalled("fw.disable")
}

// Новый профиль просит работать без kill switch: блокировка держится, пока туннель
// не доказал работу, и снимается в конце шага 5.
func TestConnectFromBlockedKillSwitchOff(t *testing.T) {
	h := newHarness(t)
	if err := h.e.ArmBlock(model.Options{KillSwitch: true}); err != nil {
		t.Fatal(err)
	}
	req := testRequest()
	req.Options.KillSwitch = false
	h.connect(req)
	h.waitPhase(model.PhaseConnected)
	h.wantLog("fw.enable", "protect.set", "core.start", "tunnel.open", "net.configure",
		"tunnel.handshake", "net.bypass", "net.routes", "fw.disable")

	h.e.OnCoreState("error", 0, 12, "fatal: CALL_FULL")
	h.waitPhase(model.PhaseError)
}

func TestDisconnectWhileConnectingFromBlocked(t *testing.T) {
	h := newHarness(t)
	if err := h.e.ArmBlock(model.Options{KillSwitch: true}); err != nil {
		t.Fatal(err)
	}
	h.core.silent = true
	h.connect(testRequest())
	h.waitCall("core.start")

	h.e.Disconnect()

	h.wantLog("fw.enable", "protect.set", "core.start", "core.stop", "fw.disable")
	if st := h.e.Status(); st.Phase != model.PhaseIdle {
		t.Errorf("статус %+v", st)
	}
}

func TestAwaitProfile(t *testing.T) {
	h := newHarness(t)
	h.e.AwaitProfile()
	st := h.e.Status()
	if st.Phase != model.PhaseIdle || !st.AwaitingProfile {
		t.Errorf("статус %+v", st)
	}
	h.connect(testRequest())
	if st := h.waitPhase(model.PhaseConnected); st.AwaitingProfile {
		t.Error("AwaitingProfile не сброшен")
	}
}

func TestBadWGConfig(t *testing.T) {
	h := newHarness(t)
	req := testRequest()
	req.Profile.WGConfig = "мусор"
	h.connect(req)
	st := h.waitPhase(model.PhaseError)
	if st.Code != model.ErrBadProfile || st.Detail == "" {
		t.Errorf("Code = %q, Detail = %q", st.Code, st.Detail)
	}
	h.wantLog()
}

func TestProfileMissingFields(t *testing.T) {
	h := newHarness(t)
	req := testRequest()
	req.Profile.CallLink = ""
	h.connect(req)
	if st := h.waitPhase(model.PhaseError); st.Code != model.ErrBadProfile {
		t.Errorf("Code = %q", st.Code)
	}
	h.wantLog()
}

func TestDomainNotResolvedIsSkipped(t *testing.T) {
	h := newHarness(t)
	req := testRequest()
	req.Options.Rules = []model.Rule{{Kind: model.RuleDomain, Value: "missing.example.com"}}
	h.connect(req)
	h.waitPhase(model.PhaseConnected)
	h.wantWarning(model.Warning{Code: model.WarnDomainUnresolved, Value: "missing.example.com"})
	h.wantNotCalled("fw.update")
}

func TestOversizedRuleIsSkipped(t *testing.T) {
	h := newHarness(t)
	req := testRequest()
	req.Options.Rules = []model.Rule{
		{Kind: model.RuleSubnet, Value: "0.0.0.0/0"},
		{Kind: model.RuleIP, Value: "198.51.100.9"},
	}
	h.connect(req)
	h.waitPhase(model.PhaseConnected)
	h.wantWarning(model.Warning{Code: model.WarnRuleSkipped, Value: "0.0.0.0/0"})
	want := []netip.Prefix{netip.MustParsePrefix("198.51.100.9/32")}
	if got := h.net.bypassed(); !slices.Equal(got, want) {
		t.Errorf("SetBypass получил %v", got)
	}
}

func TestDomainsReachFirewall(t *testing.T) {
	h := newHarness(t)
	v4 := netip.MustParseAddr("198.51.100.7")
	v6 := netip.MustParseAddr("2001:db8::7")
	h.res.answers["example.com"] = []netip.Addr{v4, v6}
	h.res.answers["example.org"] = []netip.Addr{v4}
	req := testRequest()
	req.Options.Rules = []model.Rule{
		{Kind: model.RuleSubnet, Value: "203.0.113.0/24"},
		{Kind: model.RuleDomain, Value: "example.com"},
		{Kind: model.RuleDomain, Value: "example.org"},
	}
	h.connect(req)
	h.waitPhase(model.PhaseConnected)

	want := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("198.51.100.7/32"),
		netip.MustParsePrefix("2001:db8::7/128"),
	}
	if got := h.net.bypassed(); !slices.Equal(got, want) {
		t.Errorf("SetBypass получил %v", got)
	}
	if got := h.fw.opts[0].Bypass; !slices.Equal(got, want) {
		t.Errorf("Enable получил %v", got)
	}
	h.wantLog("protect.set", "core.start", "tunnel.open", "net.configure", "tunnel.handshake",
		"resolve", "resolve", "fw.enable", "net.bypass", "net.routes")
	if gw := h.net.bypassPh.Gateway4; gw != netip.MustParseAddr("198.51.100.1") {
		t.Errorf("обход через %v", gw)
	}
}

// Домены разрешаются одновременно: второй вызов приходит, пока первый ещё висит.
// Предупреждения всё равно идут в порядке правил.
func TestDomainsResolveConcurrently(t *testing.T) {
	h := newHarness(t)
	release := h.log.hold("resolve")
	defer release()
	h.res.answers["b.example.com"] = []netip.Addr{netip.MustParseAddr("198.51.100.7")}
	req := testRequest()
	req.Options.Rules = []model.Rule{
		{Kind: model.RuleDomain, Value: "a.example.com"},
		{Kind: model.RuleDomain, Value: "b.example.com"},
		{Kind: model.RuleDomain, Value: "c.example.com"},
	}
	h.connect(req)
	h.waitFor("все домены в работе", func() bool { return h.log.count("resolve") == 3 })
	release()

	st := h.waitPhase(model.PhaseConnected)
	want := []model.Warning{
		{Code: model.WarnDomainUnresolved, Value: "a.example.com"},
		{Code: model.WarnDomainUnresolved, Value: "c.example.com"},
	}
	if !slices.Equal(st.Warnings, want) {
		t.Errorf("предупреждения %+v", st.Warnings)
	}
	if got := h.net.bypassed(); !slices.Equal(got, []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32")}) {
		t.Errorf("SetBypass получил %v", got)
	}
}

func TestDomainsWithoutKillSwitchLeaveFirewallAlone(t *testing.T) {
	h := newHarness(t)
	h.res.answers["example.com"] = []netip.Addr{netip.MustParseAddr("198.51.100.7")}
	req := testRequest()
	req.Options.KillSwitch = false
	req.Options.Rules = []model.Rule{{Kind: model.RuleDomain, Value: "example.com"}}
	h.connect(req)
	h.waitPhase(model.PhaseConnected)
	h.wantNotCalled("fw.enable", "fw.update")
	if got := h.net.bypassed(); len(got) != 1 {
		t.Errorf("SetBypass получил %v", got)
	}
}

func secretsOf(p model.Profile) []string {
	raw, _ := base64.StdEncoding.DecodeString(testPrivKey)
	return []string{testPrivKey, hex.EncodeToString(raw), testPSK, p.ObfKey, p.ClientID, p.CallLink}
}

func (h *harness) wantNoSecrets(secrets []string, extra ...string) {
	h.t.Helper()
	lines := append(h.logLines(), extra...)
	for _, st := range h.changeLog() {
		lines = append(lines, st.Detail)
	}
	for _, line := range lines {
		for _, s := range secrets {
			if strings.Contains(line, s) {
				h.t.Errorf("секрет в тексте: %q", line)
			}
		}
	}
}

func TestSecretsNeverLogged(t *testing.T) {
	h := newHarness(t)
	req := testRequest()
	secrets := secretsOf(req.Profile)
	req.Options.Rules = []model.Rule{{Kind: model.RuleDomain, Value: "missing.example.com"}}
	h.net.other = "AmneziaVPN"
	h.connect(req)
	h.waitPhase(model.PhaseConnected)

	msg := "fatal " + strings.Join(secrets, " ")
	h.e.OnCoreState("error", 0, 12, msg)
	st := h.waitPhase(model.PhaseBlocked)
	h.e.Disconnect()

	h.log.failOn("tunnel.open", fmt.Errorf("сбой адаптера: %s", msg))
	h.connect(req)
	st2 := h.waitPhase(model.PhaseError)

	if len(h.logLines()) == 0 {
		t.Fatal("журнал пуст, проверка ничего не доказала")
	}
	if !strings.Contains(st2.Detail, "***") {
		t.Errorf("Detail = %q", st2.Detail)
	}
	h.wantNoSecrets(secrets, st.Detail, st2.Detail)
}

// Текст ошибки разбора цитирует строку конфига, а разобранных ключей ещё нет. С "=" в конце
// ключа строка считается парой и цитируется в нижнем регистре, без него - как есть.
func TestBrokenConfigHidesKey(t *testing.T) {
	bare := strings.TrimRight(testPrivKey, "=")
	for name, line := range map[string]string{"с паддингом": testPrivKey, "без паддинга": bare} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			req := testRequest()
			req.Profile.WGConfig = "[Interface]\nPrivateKey " + line + "\n"
			h.connect(req)
			st := h.waitPhase(model.PhaseError)
			if st.Code != model.ErrBadProfile || st.Detail == "" {
				t.Errorf("Code = %q, Detail = %q", st.Code, st.Detail)
			}
			h.wantNoSecrets([]string{bare, strings.ToLower(bare)}, st.Detail)
		})
	}
}

// fireStaleEvents шлёт всё, что может прийти от ядра с опозданием.
func (h *harness) fireStaleEvents() {
	h.e.OnCoreState("connected", 3, 12, "")
	h.e.OnCoreState("connecting", 0, 12, "")
	h.e.OnCoreState("idle", 0, 0, "")
	h.e.OnCaptcha(captchaURL, true)
	h.e.OnCoreState("error", 0, 12, "fatal: CALL_FULL")
}

// Опоздавшие события не трогают движок, когда сессии нет.
func TestStaleCoreEventsIgnored(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		h := newHarness(t)
		h.fireStaleEvents()
		st := h.e.Status()
		if st.Phase != model.PhaseIdle || st.Streams != 0 || st.CaptchaURL != "" || st.Code != "" {
			t.Errorf("статус %+v", st)
		}
		if len(h.changeLog()) != 0 {
			t.Errorf("OnChange вызван: %+v", h.changeLog())
		}
	})
	t.Run("после ошибки", func(t *testing.T) {
		h := newHarness(t)
		h.log.failOn("tunnel.open", errBoom)
		h.connect(testRequest())
		want := h.waitPhase(model.PhaseError)
		h.fireStaleEvents()
		st := h.e.Status()
		if st.Phase != model.PhaseError || st.Code != want.Code || st.Detail != want.Detail || st.Streams != 0 {
			t.Errorf("статус %+v", st)
		}
	})
	t.Run("после Blocked", func(t *testing.T) {
		h := newHarness(t)
		h.connect(testRequest())
		h.waitPhase(model.PhaseConnected)
		h.e.OnCoreState("error", 0, 12, "fatal: CALL_FULL")
		h.waitPhase(model.PhaseBlocked)
		h.fireStaleEvents()
		if st := h.e.Status(); st.Phase != model.PhaseBlocked || st.CaptchaURL != "" {
			t.Errorf("статус %+v", st)
		}
	})
	// Ядро рапортует idle и error, пока его останавливает откат: это не сбой.
	t.Run("во время отката и после Disconnect", func(t *testing.T) {
		h := newHarness(t)
		h.connect(testRequest())
		h.waitPhase(model.PhaseConnected)
		release := h.log.hold("core.stop")
		defer release()

		done := disconnectAsync(h.e)
		h.waitCall("core.stop")
		h.fireStaleEvents()
		if st := h.e.Status(); st.Phase != model.PhaseConnected || st.CaptchaURL != "" {
			t.Errorf("статус менялся во время отката: %+v", st)
		}
		release()
		<-done
		h.fireStaleEvents()

		st := h.e.Status()
		if st.Phase != model.PhaseIdle || st.Code != "" || st.CaptchaURL != "" {
			t.Errorf("статус %+v", st)
		}
		h.wantFirewallOff()
	})
}

// connected от прошлой сессии, пришедший до core.start, не считается подключением.
func TestEventsBeforeCoreStartIgnored(t *testing.T) {
	h := newHarness(t)
	h.core.silent = true
	release := h.log.hold("protect.set")
	defer release()
	h.connect(testRequest())
	h.waitCall("protect.set")
	h.e.OnCoreState("connected", 3, 12, "")
	release()
	h.waitCall("core.start")
	time.Sleep(10 * time.Millisecond)
	h.wantNotCalled("tunnel.open")
}

func TestConnectedBeforeStartReturns(t *testing.T) {
	h := newHarness(t)
	h.core.silent = true
	h.core.onStart = func() { h.e.OnCoreState("connected", 3, 12, "") }
	h.connect(testRequest())
	h.waitPhase(model.PhaseConnected)
}

// Потоки упали, пока шёл шаг 5: туннель поднят, но это Reconnecting, а не Connected без потоков.
func TestZeroStreamsAtStep6(t *testing.T) {
	h := newHarness(t)
	release := h.log.hold("fw.enable")
	defer release()
	h.connect(testRequest())
	h.waitCall("fw.enable")
	h.e.OnCoreState("connecting", 0, 12, "")
	release()

	h.waitPhase(model.PhaseReconnecting)
	h.e.OnCoreState("connected", 2, 12, "")
	h.waitPhase(model.PhaseConnected)
}

// Команды и события ядра из разных потоков: нет зависания, Disconnect всегда кончается в Idle
// без блокировки, а у каждого запуска есть своя остановка.
func TestCommandsAndEventsStress(t *testing.T) {
	h := newHarness(t)
	var stop atomic.Bool
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Go(func() {
			r := rand.New(rand.NewPCG(uint64(g), 7))
			for !stop.Load() {
				switch r.IntN(6) {
				case 0:
					h.e.OnCoreState("connected", 3, 12, "")
				case 1:
					h.e.OnCoreState("connecting", 0, 12, "")
				case 2:
					h.e.OnCaptcha(captchaURL, true)
				case 3:
					h.e.OnCaptcha("", false)
				case 4:
					h.e.OnCoreState("captcha", 0, 12, "")
				case 5:
					if r.IntN(40) == 0 {
						h.e.OnCoreState("error", 0, 12, "fatal: CALL_FULL")
					}
				}
				_ = h.e.Status()
			}
		})
	}
	for i := range 300 {
		_ = h.e.Connect(testRequest())
		if i%3 == 0 {
			time.Sleep(time.Duration(i%5) * 100 * time.Microsecond)
		}
		h.e.Disconnect()
		if st := h.e.Status(); st.Phase != model.PhaseIdle || st.CaptchaURL != "" {
			t.Errorf("после Disconnect %d: %+v", i, st)
			break
		}
		h.wantFirewallOff()
	}
	stop.Store(true)
	wg.Wait()
	if starts, stops := h.log.count("core.start"), h.log.count("core.stop"); starts != stops {
		t.Errorf("core.start %d, core.stop %d", starts, stops)
	}
	if opens, closes := h.log.count("tunnel.open"), h.log.count("tunnel.close"); opens != closes {
		t.Errorf("tunnel.open %d, tunnel.close %d", opens, closes)
	}
}

func TestOnChangeSeesEveryPhase(t *testing.T) {
	h := newHarness(t)
	h.connect(testRequest())
	h.waitPhase(model.PhaseConnected)
	h.e.Disconnect()

	var phases []model.Phase
	for _, st := range h.changeLog() {
		if len(phases) == 0 || phases[len(phases)-1] != st.Phase {
			phases = append(phases, st.Phase)
		}
	}
	want := []model.Phase{model.PhaseConnecting, model.PhaseConnected, model.PhaseIdle}
	if !slices.Equal(phases, want) {
		t.Errorf("фазы %v", phases)
	}
}

func TestStatusIsSnapshot(t *testing.T) {
	h := newHarness(t)
	h.net.other = "AmneziaVPN"
	h.connect(testRequest())
	st := h.waitPhase(model.PhaseConnected)
	st.Warnings[0].Value = "испорчено"
	h.wantWarning(model.Warning{Code: model.WarnOtherVPN, Value: "AmneziaVPN"})
}

// Опоздавшее обновление разрешений не должно вернуть снятую блокировку.
func TestFirewallRefreshAfterDisableIsNoop(t *testing.T) {
	h := newHarness(t)
	h.connect(testRequest())
	h.waitPhase(model.PhaseConnected)
	h.e.Disconnect()

	if err := h.e.fwRefresh(firewall.Options{}); err != nil {
		t.Fatal(err)
	}
	h.wantNotCalled("fw.update")
}
