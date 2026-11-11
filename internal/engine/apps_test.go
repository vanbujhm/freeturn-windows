package engine

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/vanbujhm/freeturn-windows/internal/firewall"
	"github.com/vanbujhm/freeturn-windows/internal/model"
)

const appOne = `C:\Apps\one.exe`

// appsRequest подключает с одной включённой и одной выключенной программой.
func appsRequest(kill bool) model.ConnectRequest {
	req := testRequest()
	req.Options.KillSwitch = kill
	req.Options.Apps = []model.AppRule{{Path: appOne}, {Path: `C:\Apps\two.exe`, Off: true}}
	return req
}

// fwOpts возвращает аргументы вызовов брандмауэра, их должно быть не меньше n.
func (h *harness) fwOpts(n int) []firewall.Options {
	h.t.Helper()
	h.fw.mu.Lock()
	opts := slices.Clone(h.fw.opts)
	h.fw.mu.Unlock()
	if len(opts) < n {
		h.t.Fatalf("вызовов брандмауэра %d, ожидалось не меньше %d: %v", len(opts), n, h.log.snapshot())
	}
	return opts
}

// wantFW сверяет то, что движок сказал брандмауэру о туннеле, kill switch и программах.
func wantFW(t *testing.T, what string, o firewall.Options, luid uint64, kill bool) {
	t.Helper()
	if o.TunLUID != luid || o.KillSwitch != kill || !slices.Equal(o.Apps, []string{appOne}) {
		t.Errorf("%s: TunLUID %#x, KillSwitch %v, Apps %v; ожидалось %#x, %v, [%s]",
			what, o.TunLUID, o.KillSwitch, o.Apps, luid, kill, appOne)
	}
}

func (h *harness) wantBefore(first, second string) {
	h.t.Helper()
	log := h.log.snapshot()
	i, j := slices.Index(log, first), slices.Index(log, second)
	if i < 0 || j < 0 || i > j {
		h.t.Errorf("%s должен идти раньше %s: %v", first, second, log)
	}
}

func TestAppsWithoutKillSwitch(t *testing.T) {
	h := newHarness(t)
	h.connect(appsRequest(false))
	h.waitPhase(model.PhaseConnected)

	opts := h.fwOpts(2)
	wantFW(t, "шаг 1", opts[0], 0, false)
	if !opts[0].AllowLAN {
		t.Errorf("шаг 1: AllowLAN %v", opts[0].AllowLAN)
	}
	last := h.fw.last()
	wantFW(t, "шаг 5", last, testLUID, false)
	if !last.AllowLAN || len(last.DNS) == 0 {
		t.Errorf("шаг 5: AllowLAN %v, DNS %v", last.AllowLAN, last.DNS)
	}
	h.wantBefore("fw.enable", "core.start")
	h.wantBefore("tunnel.handshake", "fw.update")

	h.e.Disconnect()
	h.wantCalled("fw.disable")
	if st := h.e.Status(); st.Phase != model.PhaseIdle {
		t.Errorf("статус %+v", st)
	}
}

func TestAppsWithKillSwitch(t *testing.T) {
	h := newHarness(t)
	h.connect(appsRequest(true))
	h.waitPhase(model.PhaseConnected)

	wantFW(t, "шаг 1", h.fwOpts(2)[0], 0, false)
	wantFW(t, "шаг 5", h.fw.last(), testLUID, true)
}

func TestAppsAllOffNoSession(t *testing.T) {
	h := newHarness(t)
	req := testRequest()
	req.Options.KillSwitch = false
	req.Options.Apps = []model.AppRule{{Path: appOne, Off: true}}
	h.connect(req)
	h.waitPhase(model.PhaseConnected)
	h.wantNotCalled("fw.enable", "fw.update")
}

func TestAppsFailureBeforeTunnelClearsSession(t *testing.T) {
	h := newHarness(t)
	h.log.failOn("core.start", errBoom)
	h.connect(appsRequest(false))
	h.waitPhase(model.PhaseError)
	h.wantCalled("fw.enable", "fw.disable")
}

func TestAppsFatalClearsSession(t *testing.T) {
	h := newHarness(t)
	h.connect(appsRequest(false))
	h.waitPhase(model.PhaseConnected)

	h.e.OnCoreState("error", 0, 12, "fatal: CALL_FULL")

	h.waitPhase(model.PhaseError)
	h.wantCalled("fw.disable")
}

func TestAppsEnableFailsAbortsConnect(t *testing.T) {
	h := newHarness(t)
	h.log.failOn("fw.enable", errBoom)
	h.connect(appsRequest(false))
	st := h.waitPhase(model.PhaseError)
	if st.Code != model.ErrAdapter {
		t.Errorf("Code = %q", st.Code)
	}
	h.wantNotCalled("core.start")
}

func TestAppsSkippedWarnsOnce(t *testing.T) {
	h := newHarness(t)
	h.fw.skipped = []string{appOne}
	h.connect(appsRequest(false))
	st := h.waitPhase(model.PhaseConnected)

	want := model.Warning{Code: model.WarnAppSkipped, Value: appOne}
	n := 0
	for _, w := range st.Warnings {
		if w == want {
			n++
		}
	}
	if n != 1 {
		t.Errorf("предупреждений о пропуске %d, есть %+v", n, st.Warnings)
	}
	found := false
	for _, line := range h.logLines() {
		found = found || strings.Contains(line, appOne)
	}
	if !found {
		t.Errorf("в журнале нет пути: %v", h.logLines())
	}
}

func TestAppsBadListFailsConnect(t *testing.T) {
	h := newHarness(t)
	req := testRequest()
	req.Options.Apps = []model.AppRule{{Path: "app.exe"}}
	h.connect(req)
	st := h.waitPhase(model.PhaseError)
	if st.Code != model.ErrBadProfile {
		t.Errorf("Code = %q", st.Code)
	}
	h.wantNotCalled("fw.enable", "core.start")
}

// Подключение из блокировки без kill switch: blockAll держится до успеха шага 5 и
// снимается отдельным обновлением, блок программ остаётся.
func TestAppsFromBlockedKillSwitchOff(t *testing.T) {
	h := newHarness(t)
	if err := h.e.ArmBlock(model.Options{KillSwitch: true}); err != nil {
		t.Fatal(err)
	}
	h.connect(appsRequest(false))
	h.waitPhase(model.PhaseConnected)

	opts := h.fwOpts(4)
	if len(opts) != 4 {
		t.Fatalf("вызовов брандмауэра %d: %+v", len(opts), opts)
	}
	wantFW(t, "шаг 1", opts[1], 0, true)
	wantFW(t, "шаг 5", opts[2], testLUID, true)
	wantFW(t, "после шага 5", opts[3], testLUID, false)
	h.wantNotCalled("fw.disable")
}

// Блокировка от прошлого подключения закрывала DNS мимо конфига. Блок программ на шаге 1
// заменяет её сессию и не должен этот запрет снять: иначе при разрешённой LAN запросы ушли
// бы к роутеру.
func TestAppsFromBlockedKeepsDNSDeny(t *testing.T) {
	h := newHarness(t)
	if err := h.e.ArmBlock(model.Options{KillSwitch: true}); err != nil {
		t.Fatal(err)
	}
	h.connect(appsRequest(false))
	h.waitPhase(model.PhaseConnected)

	step1 := h.fwOpts(2)[1]
	wantFW(t, "шаг 1", step1, 0, true)
	if !slices.Equal(step1.DNS, []netip.Addr{netip.MustParseAddr("198.51.100.53")}) {
		t.Errorf("шаг 1: DNS %v, ожидался DNS конфига", step1.DNS)
	}
}

func TestAppsFromBlockedFailureStaysBlocked(t *testing.T) {
	h := newHarness(t)
	if err := h.e.ArmBlock(model.Options{KillSwitch: true}); err != nil {
		t.Fatal(err)
	}
	h.log.failOn("net.bypass", errBoom)
	h.connect(appsRequest(false))
	h.waitPhase(model.PhaseBlocked)
	h.wantNotCalled("fw.disable")
	if !h.fw.last().KillSwitch {
		t.Errorf("блокировка снята: %+v", h.fw.last())
	}
}

func TestAppsSurviveNetworkChange(t *testing.T) {
	h := newHarness(t)
	h.up(appsRequest(false))
	before := h.log.count("fw.update")

	h.net.setPhysical(otherPhysical(), nil)
	h.e.NetworkChanged()

	if h.log.count("fw.update") <= before {
		t.Fatalf("смена сети не пересобрала сессию: %v", h.log.snapshot())
	}
	wantFW(t, "после смены сети", h.fw.last(), testLUID, false)
}
