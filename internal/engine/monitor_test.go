package engine

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/netcfg"
)

const testDomain = "bypass.example.test"

var (
	firstAddr  = netip.MustParseAddr("203.0.113.10")
	secondAddr = netip.MustParseAddr("203.0.113.11")
	ruleSubnet = netip.MustParsePrefix("203.0.113.128/25")
)

// firstPhysical совпадает с интерфейсом, который newHarness отдаёт при подключении.
func firstPhysical() model.Physical {
	return model.Physical{
		LUID: 7, Index4: 11, Index6: 12,
		Gateway4: netip.MustParseAddr("198.51.100.1"),
		DNS:      []netip.Addr{netip.MustParseAddr("198.51.100.2")},
	}
}

func otherPhysical() model.Physical {
	return model.Physical{
		LUID: 8, Index4: 21, Index6: 22,
		Gateway4: netip.MustParseAddr("198.51.100.129"),
		DNS:      []netip.Addr{netip.MustParseAddr("198.51.100.130")},
	}
}

func subnetRequest() model.ConnectRequest {
	req := testRequest()
	req.Options.Rules = []model.Rule{{Kind: model.RuleSubnet, Value: ruleSubnet.String()}}
	return req
}

func domainRequest() model.ConnectRequest {
	req := testRequest()
	req.Options.Rules = []model.Rule{{Kind: model.RuleDomain, Value: testDomain}}
	return req
}

// up подключает и возвращает длину журнала: всё дальше сделал монитор.
func (h *harness) up(req model.ConnectRequest) int {
	h.t.Helper()
	h.connect(req)
	h.waitPhase(model.PhaseConnected)
	return len(h.log.snapshot())
}

func (h *harness) wantSince(from int, want ...string) {
	h.t.Helper()
	if got := h.log.snapshot()[from:]; !slices.Equal(got, want) {
		h.t.Errorf("вызовы после подключения\n got %v\nwant %v", got, want)
	}
}

func (h *harness) wantLogged(part string) {
	h.t.Helper()
	for _, line := range h.logLines() {
		if strings.Contains(line, part) {
			return
		}
	}
	h.t.Errorf("в журнале нет %q: %v", part, h.logLines())
}

// waitCancelled ждёт отмены сессии, откат которой ещё не кончился.
func (h *harness) waitCancelled() {
	h.t.Helper()
	h.waitFor("отмена", func() bool {
		h.e.mu.Lock()
		defer h.e.mu.Unlock()
		return h.e.sess != nil && h.e.sess.ctx.Err() != nil
	})
}

func hasPrefix(list []netip.Prefix, a netip.Addr) bool {
	return slices.Contains(list, netip.PrefixFrom(a, a.BitLen()))
}

// returnsSoon проверяет, что вызов не ждёт идущих подключения и отката.
func returnsSoon(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s завис", what)
	}
}

func TestNetworkChangedUpdatesEverything(t *testing.T) {
	h := newHarness(t)
	from := h.up(subnetRequest())

	ph := otherPhysical()
	h.net.setPhysical(ph, nil)
	h.e.NetworkChanged()

	h.wantSince(from, "protect.set", "net.bypass", "fw.update", "core.reconnect")
	if got := h.net.lastExcluded(); got != testLUID {
		t.Errorf("FindPhysical исключил %x, нужен LUID туннеля", got)
	}
	if h.prot.i4 != ph.Index4 || h.prot.i6 != ph.Index6 {
		t.Errorf("protect: %d, %d", h.prot.i4, h.prot.i6)
	}
	if got := h.net.bypassPhysical(); got.LUID != ph.LUID || got.Gateway4 != ph.Gateway4 {
		t.Errorf("обход ушёл на %+v", got)
	}
	if !slices.Contains(h.net.bypassed(), ruleSubnet) {
		t.Errorf("обход %v", h.net.bypassed())
	}
	if opts := h.fw.last(); !slices.Contains(opts.Bypass, ruleSubnet) || opts.TunLUID != testLUID {
		t.Errorf("брандмауэр %+v", opts)
	}
	if st := h.e.Status(); st.Phase != model.PhaseConnected {
		t.Errorf("статус %+v", st)
	}
}

func TestNetworkChangedKillSwitchOff(t *testing.T) {
	h := newHarness(t)
	req := subnetRequest()
	req.Options.KillSwitch = false
	from := h.up(req)

	h.net.setPhysical(otherPhysical(), nil)
	h.e.NetworkChanged()

	h.wantSince(from, "protect.set", "net.bypass", "core.reconnect")
}

func TestNetworkChangedGatewayMoved(t *testing.T) {
	h := newHarness(t)
	from := h.up(subnetRequest())

	ph := firstPhysical()
	ph.Gateway4 = netip.MustParseAddr("198.51.100.254")
	h.net.setPhysical(ph, nil)
	h.e.NetworkChanged()

	h.wantSince(from, "protect.set", "net.bypass", "fw.update", "core.reconnect")
}

func TestNetworkChangedLostNetwork(t *testing.T) {
	h := newHarness(t)
	from := h.up(subnetRequest())
	before := len(h.changeLog())

	h.net.setPhysical(model.Physical{}, netcfg.ErrNoNetwork)
	h.e.NetworkChanged()
	h.e.NetworkChanged()

	h.wantSince(from)
	if st := h.e.Status(); st.Phase != model.PhaseReconnecting {
		t.Errorf("статус %+v", st)
	}
	if got := len(h.changeLog()) - before; got != 1 {
		t.Errorf("OnChange вызван %d раз", got)
	}
	if got := strings.Count(strings.Join(h.logLines(), "\n"), "физической сети нет"); got != 1 {
		t.Errorf("сообщений о потере сети %d: %v", got, h.logLines())
	}
}

// Ядро ещё считает живые потоки, но сети нет: окно не должно видеть «Подключено».
func TestNetworkLostHoldsPhase(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())
	h.net.setPhysical(model.Physical{}, netcfg.ErrNoNetwork)
	h.e.NetworkChanged()

	h.e.OnCoreState("connected", 2, 12, "")
	if st := h.e.Status(); st.Phase != model.PhaseReconnecting || st.Streams != 2 {
		t.Errorf("статус %+v", st)
	}

	h.e.OnCaptcha(captchaURL, true)
	h.waitPhase(model.PhaseCaptcha)
	h.e.OnCaptcha("", false)
	if st := h.e.Status(); st.Phase != model.PhaseReconnecting {
		t.Errorf("после капчи статус %+v", st)
	}
}

// Windows снимает маршруты вместе с интерфейсом, а SetBypass добавляет только то, чего нет
// в его списке. Поэтому на том же интерфейсе маршруты ставятся заново.
func TestNetworkBackOnSameInterface(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())
	h.net.setPhysical(model.Physical{}, netcfg.ErrNoNetwork)
	h.e.NetworkChanged()
	from := len(h.log.snapshot())

	h.net.setPhysical(firstPhysical(), nil)
	h.e.NetworkChanged()

	h.wantSince(from, "protect.set", "net.bypassClear", "net.bypass", "fw.update", "core.reconnect")
	if st := h.e.Status(); st.Phase != model.PhaseConnected {
		t.Errorf("потоки живы, статус %+v", st)
	}
}

func TestNetworkBackOnOtherInterface(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())
	h.e.OnCoreState("connecting", 0, 12, "")
	h.net.setPhysical(model.Physical{}, netcfg.ErrNoNetwork)
	h.e.NetworkChanged()
	from := len(h.log.snapshot())

	ph := otherPhysical()
	h.net.setPhysical(ph, nil)
	h.e.NetworkChanged()

	h.wantSince(from, "protect.set", "net.bypassClear", "net.bypass", "fw.update", "core.reconnect")
	if got := h.net.bypassPhysical(); got.LUID != ph.LUID {
		t.Errorf("обход ушёл на %+v", got)
	}
	if st := h.e.Status(); st.Phase != model.PhaseReconnecting {
		t.Errorf("потоков нет, статус %+v", st)
	}

	h.e.OnCoreState("connected", 3, 12, "")
	h.waitPhase(model.PhaseConnected)
}

// Ошибка чтения сети это не потеря сети: туннель работает дальше.
func TestNetworkChangedReadFails(t *testing.T) {
	h := newHarness(t)
	from := h.up(subnetRequest())

	h.net.setPhysical(model.Physical{}, errBoom)
	h.e.NetworkChanged()

	h.wantSince(from)
	if st := h.e.Status(); st.Phase != model.PhaseConnected {
		t.Errorf("статус %+v", st)
	}
	h.wantLogged(errBoom.Error())
}

func TestNetworkChangedSameInterface(t *testing.T) {
	h := newHarness(t)
	from := h.up(subnetRequest())
	before := len(h.changeLog())

	h.e.NetworkChanged()
	h.e.NetworkChanged()

	h.wantSince(from)
	if got := len(h.changeLog()); got != before {
		t.Errorf("OnChange вызван: %+v", h.changeLog()[before:])
	}
}

// Роутер сменил DNS, а путь тот же: трогать нечего, но домены идут через новый DNS.
func TestNetworkChangedKeepsNewDNS(t *testing.T) {
	h := newHarness(t)
	h.res.answers[testDomain] = []netip.Addr{firstAddr}
	from := h.up(domainRequest())

	ph := firstPhysical()
	ph.DNS = []netip.Addr{netip.MustParseAddr("198.51.100.3")}
	h.net.setPhysical(ph, nil)
	h.e.NetworkChanged()
	h.wantSince(from)

	h.e.Tick(time.Now().Add(domainRefresh))
	if got := h.res.usedPhysical().DNS; !slices.Equal(got, ph.DNS) {
		t.Errorf("DNS запроса %v", got)
	}
}

// Сбой переноса не останавливает ядро: его сокеты важнее исключений.
func TestNetworkChangedStepFails(t *testing.T) {
	for _, step := range []string{"net.bypass", "fw.update"} {
		t.Run(step, func(t *testing.T) {
			h := newHarness(t)
			h.up(subnetRequest())
			h.log.failOn(step, errBoom)

			h.net.setPhysical(otherPhysical(), nil)
			h.e.NetworkChanged()

			h.wantCalled("core.reconnect")
			h.wantLogged(errBoom.Error())
			if st := h.e.Status(); st.Phase != model.PhaseConnected {
				t.Errorf("статус %+v", st)
			}
		})
	}
}

// Сбой переноса чинится следующей сверкой, а ядро переподключается один раз: иначе постоянная
// ошибка маршрута сбрасывала бы его на каждом такте и обновлении от роутера.
func TestFailedMoveRetriedWithoutReconnect(t *testing.T) {
	cases := map[string]func(*harness){
		"такт":    func(h *harness) { h.e.Tick(time.Now()) },
		"событие": func(h *harness) { h.e.NetworkChanged() },
	}
	for name, again := range cases {
		for _, step := range []string{"net.bypass", "fw.update"} {
			t.Run(name+" "+step, func(t *testing.T) {
				h := newHarness(t)
				h.up(subnetRequest())
				h.log.failOn(step, errBoom)
				h.net.setPhysical(otherPhysical(), nil)
				h.e.NetworkChanged()

				// Ошибка не прошла: попытка повторяется и дальше.
				tries := h.log.count(step)
				again(h)
				if got := h.log.count(step); got != tries+1 {
					t.Errorf("повторов %d", got-tries)
				}

				h.log.failOn(step, nil)
				again(h)
				if got := h.log.count(step); got != tries+2 {
					t.Errorf("повторов %d", got-tries)
				}
				if got := h.log.count("core.reconnect"); got != 1 {
					t.Errorf("core.reconnect %d раз", got)
				}
				if got := h.net.bypassPhysical(); got.LUID != otherPhysical().LUID {
					t.Errorf("обход ушёл на %+v", got)
				}

				// Починилось: больше не трогаем.
				bypasses := h.log.count("net.bypass")
				again(h)
				if got := h.log.count("net.bypass"); got != bypasses {
					t.Errorf("лишний net.bypass: %d", got-bypasses)
				}
			})
		}
	}
}

// Повтор идёт как шаг 5: без разрешения маршрут не ставится.
func TestRetryKeepsFirewallFirst(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())
	h.log.failOn("net.bypass", errBoom)
	h.net.setPhysical(otherPhysical(), nil)
	h.e.NetworkChanged()
	h.log.failOn("net.bypass", nil)
	from := len(h.log.snapshot())

	h.e.Tick(time.Now())

	h.wantSince(from, "fw.update", "net.bypass", "tunnel.stats")
}

// Наблюдатель выжидает 2 с тишины, а ядро за это время успевает восстановиться и открыть
// капчу. Событие о возвращении сети теряется, и без сверки в такте фаза осталась бы
// Reconnecting до конца сессии, а исключения на старом интерфейсе.
func TestNetworkReturnedUnderCaptcha(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())
	h.net.setPhysical(model.Physical{}, netcfg.ErrNoNetwork)
	h.e.NetworkChanged()

	h.e.OnCaptcha(captchaURL, true)
	h.waitPhase(model.PhaseCaptcha)
	ph := otherPhysical()
	h.net.setPhysical(ph, nil)
	h.e.NetworkChanged()
	h.e.OnCaptcha("", false)
	h.e.OnCoreState("connected", 3, 12, "")

	h.e.Tick(time.Now())

	if st := h.e.Status(); st.Phase != model.PhaseConnected || st.Streams != 3 {
		t.Errorf("статус %+v", st)
	}
	if h.prot.i4 != ph.Index4 || h.prot.i6 != ph.Index6 {
		t.Errorf("protect: %d, %d", h.prot.i4, h.prot.i6)
	}
	if got := h.net.bypassPhysical(); got.LUID != ph.LUID {
		t.Errorf("обход ушёл на %+v", got)
	}
	h.wantCalled("net.bypassClear", "core.reconnect")
	h.e.RefreshRates()
	h.wantCalled("core.rates")
}

// Событие о возвращении сети не прочиталось. Следующий такт дочитывает.
func TestNetworkReturnReadFails(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())
	h.net.setPhysical(model.Physical{}, netcfg.ErrNoNetwork)
	h.e.NetworkChanged()
	h.net.setPhysical(model.Physical{}, errBoom)
	h.e.NetworkChanged()
	if st := h.e.Status(); st.Phase != model.PhaseReconnecting {
		t.Fatalf("статус %+v", st)
	}

	h.net.setPhysical(firstPhysical(), nil)
	h.e.Tick(time.Now())

	if st := h.e.Status(); st.Phase != model.PhaseConnected {
		t.Errorf("статус %+v", st)
	}
	h.wantCalled("net.bypassClear", "core.reconnect")
}

// Смена сети под капчей на живом туннеле: событие не действует, такт после капчи догоняет.
func TestNetworkMovedUnderCaptcha(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())
	h.e.OnCaptcha(captchaURL, true)
	h.waitPhase(model.PhaseCaptcha)
	ph := otherPhysical()
	h.net.setPhysical(ph, nil)
	h.e.NetworkChanged()
	h.e.Tick(time.Now())
	h.wantNotCalled("core.reconnect")

	h.e.OnCaptcha("", false)
	h.e.Tick(time.Now())

	if got := h.net.bypassPhysical(); got.LUID != ph.LUID {
		t.Errorf("обход ушёл на %+v", got)
	}
	if got := h.log.count("core.reconnect"); got != 1 {
		t.Errorf("core.reconnect %d раз", got)
	}
}

// Такт замечает потерю сети и без события.
func TestTickNoticesLostNetwork(t *testing.T) {
	h := newHarness(t)
	from := h.up(subnetRequest())
	h.net.setPhysical(model.Physical{}, netcfg.ErrNoNetwork)

	h.e.Tick(time.Now())

	if st := h.e.Status(); st.Phase != model.PhaseReconnecting {
		t.Errorf("статус %+v", st)
	}
	h.wantSince(from)
}

// Отмена во время сверки на шаге 6: окно не должно увидеть Connected у отменённой сессии.
func TestCancelDuringStep6Check(t *testing.T) {
	h := newHarness(t)
	routes := h.log.hold("net.routes")
	defer routes()
	h.connect(subnetRequest())
	h.waitCall("net.routes")
	h.net.setPhysical(otherPhysical(), nil)
	update := h.log.hold("fw.update")
	defer update()
	routes()
	h.waitCall("fw.update")

	stopped := disconnectAsync(h.e)
	h.waitCancelled()
	update()
	<-stopped

	for _, st := range h.changeLog() {
		if st.Phase == model.PhaseConnected {
			t.Errorf("Connected у отменённой сессии: %+v", st)
		}
	}
	if st := h.e.Status(); st.Phase != model.PhaseIdle {
		t.Errorf("статус %+v", st)
	}
	h.wantNotCalled("core.reconnect")
}

func TestNetworkChangedOutsideSession(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		h := newHarness(t)
		h.e.NetworkChanged()
		if h.net.findCount() != 0 {
			t.Error("FindPhysical вызван без сессии")
		}
	})
	t.Run("подключение", func(t *testing.T) {
		h := newHarness(t)
		h.core.silent = true
		h.connect(testRequest())
		h.waitCall("core.start")
		finds := h.net.findCount()
		h.e.NetworkChanged()
		if h.net.findCount() != finds {
			t.Error("FindPhysical вызван во время подключения")
		}
	})
	t.Run("капча", func(t *testing.T) {
		h := newHarness(t)
		h.up(subnetRequest())
		h.e.OnCaptcha(captchaURL, true)
		finds := h.net.findCount()
		h.e.NetworkChanged()
		if h.net.findCount() != finds {
			t.Error("FindPhysical вызван при открытой капче")
		}
	})
	t.Run("после отключения", func(t *testing.T) {
		h := newHarness(t)
		h.up(subnetRequest())
		h.e.Disconnect()
		from := len(h.log.snapshot())
		finds := h.net.findCount()
		h.e.NetworkChanged()
		h.wantSince(from)
		if h.net.findCount() != finds {
			t.Error("FindPhysical вызван после отключения")
		}
	})
	t.Run("блокировка", func(t *testing.T) {
		h := newHarness(t)
		h.up(subnetRequest())
		h.e.OnCoreState("error", 0, 12, "fatal: CALL_FULL")
		h.waitPhase(model.PhaseBlocked)
		from := len(h.log.snapshot())
		h.e.NetworkChanged()
		h.wantSince(from)
	})
}

// NetworkChanged на шагах 3-5 ничего не делает, поэтому шаг 6 сверяет сеть сам.
func TestNetworkMovedDuringConnect(t *testing.T) {
	h := newHarness(t)
	release := h.log.hold("net.routes")
	defer release()
	h.connect(subnetRequest())
	h.waitCall("net.routes")

	ph := otherPhysical()
	h.net.setPhysical(ph, nil)
	h.e.NetworkChanged()
	h.wantNotCalled("core.reconnect")
	release()
	h.waitPhase(model.PhaseConnected)

	if got := h.net.bypassPhysical(); got.LUID != ph.LUID {
		t.Errorf("обход ушёл на %+v", got)
	}
	if h.prot.i4 != ph.Index4 {
		t.Errorf("protect: %d", h.prot.i4)
	}
	if got := h.log.count("core.reconnect"); got != 1 {
		t.Errorf("core.reconnect %d раз", got)
	}
}

func TestNetworkLostDuringConnect(t *testing.T) {
	h := newHarness(t)
	release := h.log.hold("net.routes")
	defer release()
	h.connect(subnetRequest())
	h.waitCall("net.routes")

	h.net.setPhysical(model.Physical{}, netcfg.ErrNoNetwork)
	release()
	h.waitPhase(model.PhaseReconnecting)

	h.wantNotCalled("core.reconnect", "net.clear", "net.bypassClear")
	for _, st := range h.changeLog() {
		if st.Phase == model.PhaseConnected {
			t.Errorf("окно увидело Connected без сети: %+v", st)
		}
	}
}

// Сеть на месте: шаг 6 ничего не трогает, журнал подключения остаётся прежним.
func TestConnectSameNetworkLeftAlone(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())

	h.wantNotCalled("core.reconnect")
	if got := h.log.count("protect.set"); got != 1 {
		t.Errorf("protect.set %d раз", got)
	}
	if got := h.net.findCount(); got != 2 {
		t.Errorf("FindPhysical %d раз", got)
	}
}

// Откат не начинается, пока монитор меняет маршруты, а после отмены монитор останавливается.
// Иначе опоздавший SetBypass оставил бы маршруты после ClearBypass.
func TestRollbackWaitsForNetworkMove(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())
	release := h.log.hold("net.bypass")
	defer release()

	h.net.setPhysical(otherPhysical(), nil)
	moved := make(chan struct{})
	go func() {
		defer close(moved)
		h.e.NetworkChanged()
	}()
	h.waitFor("перенос начался", func() bool { return h.log.count("net.bypass") == 2 })

	stopped := disconnectAsync(h.e)
	time.Sleep(20 * time.Millisecond)
	h.wantNotCalled("net.clear", "net.bypassClear", "tunnel.close", "core.stop")

	release()
	<-moved
	<-stopped

	h.wantNotCalled("fw.update", "core.reconnect")
	got := h.log.snapshot()
	if lastIndex(got, "net.bypass") > lastIndex(got, "net.bypassClear") {
		t.Errorf("обход поставлен после отката: %v", got)
	}
}

// Откат ждёт монитор, а монитор завис в брандмауэре. Человек всё равно не остаётся без
// интернета: после FirewallGrace Disconnect снимает блокировку мимо зависшего вызова.
func TestDisconnectHungFirewallDuringNetworkMove(t *testing.T) {
	h := newHarness(t, withFirewallGrace(5*time.Millisecond))
	h.up(subnetRequest())
	release := h.log.hold("fw.update")
	defer release()

	h.net.setPhysical(otherPhysical(), nil)
	moved := make(chan struct{})
	go func() {
		defer close(moved)
		h.e.NetworkChanged()
	}()
	h.waitCall("fw.update")

	stopped := disconnectAsync(h.e)
	h.waitCall("fw.disable")
	h.wantNotCalled("net.clear", "tunnel.close", "core.reconnect")

	release()
	<-moved
	<-stopped
	if st := h.e.Status(); st.Phase != model.PhaseIdle {
		t.Errorf("статус %+v", st)
	}
	h.wantNotCalled("core.reconnect")
}

// Вызов, успевший пройти проверку фазы до отмены, ждёт netMu. Дождавшись, он не должен
// попасть в ядро: оно уже останавливается, а следующее подключение это другая сессия.
func TestLateNudgeDropped(t *testing.T) {
	cases := map[string]struct {
		call func(*harness)
		name string
	}{
		"сон":         {func(h *harness) { h.e.Woke() }, "core.wake"},
		"рукопожатие": {func(h *harness) { h.e.Tick(time.Now()) }, "tunnel.stats"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.up(subnetRequest())
			h.dev.setHandshake(time.Now().Add(-time.Hour), nil)
			release := h.log.hold("net.bypass")
			defer release()
			h.net.setPhysical(otherPhysical(), nil)
			moved := make(chan struct{})
			go func() {
				defer close(moved)
				h.e.NetworkChanged()
			}()
			h.waitFor("перенос начался", func() bool { return h.log.count("net.bypass") == 2 })

			late := make(chan struct{})
			go func() {
				defer close(late)
				c.call(h)
			}()
			time.Sleep(20 * time.Millisecond) // дать вызову дойти до netMu
			stopped := disconnectAsync(h.e)
			time.Sleep(20 * time.Millisecond)

			release()
			<-moved
			<-late
			<-stopped
			h.wantNotCalled(c.name, "core.reconnect")
		})
	}
}

// Сеть вернулась одновременно с отключением: откат идёт, а фаза уже не меняется.
func TestPhaseFrozenDuringRollback(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())
	h.net.setPhysical(model.Physical{}, netcfg.ErrNoNetwork)
	h.e.NetworkChanged()
	h.net.setPhysical(firstPhysical(), nil)

	moving := h.log.hold("net.bypass")
	defer moving()
	moved := make(chan struct{})
	go func() {
		defer close(moved)
		h.e.NetworkChanged()
	}()
	h.waitFor("перенос начался", func() bool { return h.log.count("net.bypass") == 2 })

	stopping := h.log.hold("core.stop")
	defer stopping()
	stopped := disconnectAsync(h.e)
	h.waitFor("отмена", func() bool { return h.e.watched(model.PhaseReconnecting) == nil })
	moving()
	<-moved
	h.waitCall("core.stop")

	if st := h.e.Status(); st.Phase != model.PhaseReconnecting {
		t.Errorf("статус %+v", st)
	}
	stopping()
	<-stopped
}

func TestWokeCallsWake(t *testing.T) {
	h := newHarness(t)
	from := h.up(subnetRequest())

	h.e.Woke()
	h.wantSince(from, "core.wake")

	h.e.OnCoreState("connecting", 0, 12, "")
	h.waitPhase(model.PhaseReconnecting)
	h.e.Woke()
	if got := h.log.count("core.wake"); got != 2 {
		t.Errorf("core.wake в Reconnecting: %d", got)
	}
}

func TestWokeOutsideSession(t *testing.T) {
	h := newHarness(t)
	h.e.Woke()
	h.core.silent = true
	h.connect(testRequest())
	h.waitCall("core.start")
	h.e.Woke()
	h.wantNotCalled("core.wake")
}

func TestRefreshRates(t *testing.T) {
	h := newHarness(t)
	h.e.RefreshRates()
	h.wantNotCalled("core.rates")

	h.up(subnetRequest())
	before := len(h.changeLog())
	h.core.setRates(1000, 2000, 30, 40)
	h.e.RefreshRates()

	st := h.e.Status()
	if st.TxTotal != 1000 || st.RxTotal != 2000 || st.TxRate != 30 || st.RxRate != 40 {
		t.Errorf("статус %+v", st)
	}
	if got := len(h.changeLog()); got != before+1 {
		t.Errorf("OnChange вызван %d раз", got-before)
	}

	h.e.RefreshRates()
	if got := len(h.changeLog()); got != before+1 {
		t.Errorf("OnChange без изменений: %d", got-before)
	}
}

// Ядро отвечало, пока шёл откат. Скорости закончившейся сессии в статус не попадают.
func TestRatesLateForRollback(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())
	h.core.setRates(1000, 2000, 30, 40)
	reading := h.log.hold("core.rates")
	defer reading()
	read := make(chan struct{})
	go func() {
		defer close(read)
		h.e.RefreshRates()
	}()
	h.waitCall("core.rates")

	stopping := h.log.hold("core.stop")
	defer stopping()
	stopped := disconnectAsync(h.e)
	h.waitCall("core.stop")
	reading()
	<-read

	if st := h.e.Status(); st.TxTotal != 0 {
		t.Errorf("статус %+v", st)
	}
	stopping()
	<-stopped
}

func TestRefreshRatesOnlyConnected(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())
	h.e.OnCoreState("connecting", 0, 12, "")
	h.waitPhase(model.PhaseReconnecting)

	h.e.RefreshRates()

	h.wantNotCalled("core.rates")
}

func TestStaleHandshakeReconnects(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())
	now := time.Now()
	h.dev.setHandshake(now.Add(-staleHandshake-time.Second), nil)

	// Первый такт только запоминает счётчик: сравнивать ещё не с чем.
	h.e.Tick(now)
	h.wantNotCalled("core.reconnect")

	h.dev.send(1500)
	h.e.Tick(now.Add(30 * time.Second))
	if got := h.log.count("core.reconnect"); got != 1 {
		t.Fatalf("core.reconnect %d раз", got)
	}
	h.wantWarning(model.Warning{Code: model.WarnStaleHandshake})
	h.wantLogged("рукопожатия нет")

	h.dev.send(1500)
	h.e.Tick(now.Add(time.Minute))
	if got := h.log.count("core.reconnect"); got != 1 {
		t.Errorf("повтор в ту же минуту: %d", got)
	}

	// Рукопожатия так и нет: через срок пробуем снова, но предупреждение одно.
	h.dev.send(1500)
	h.e.Tick(now.Add(30*time.Second + staleHandshake))
	if got := h.log.count("core.reconnect"); got != 2 {
		t.Errorf("повтор после срока: %d", got)
	}
	n := 0
	for _, w := range h.e.Status().Warnings {
		if w.Code == model.WarnStaleHandshake {
			n++
		}
	}
	if n != 1 {
		t.Errorf("предупреждений %d", n)
	}
}

// На простаивающем туннеле WireGuard рукопожатий не делает, это не сбой.
func TestIdleTunnelNotStale(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())
	now := time.Now()
	h.dev.send(1500) // трафик был раньше, счётчик не нулевой
	h.dev.setHandshake(now.Add(-10*time.Minute), nil)

	for i := range 4 {
		h.e.Tick(now.Add(time.Duration(i) * 30 * time.Second))
	}

	h.wantNotCalled("core.reconnect")
	if w := h.e.Status().Warnings; len(w) != 0 {
		t.Errorf("предупреждения %+v", w)
	}
}

// Счётчик запоминается и во время паузы после Reconnect: рост, случившийся в паузу, не
// должен сработать на первом такте после неё, когда туннель уже простаивает.
func TestStaleCheckComparesAdjacentTicks(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())
	now := time.Now()
	h.dev.setHandshake(now.Add(-time.Hour), nil)
	h.e.Tick(now)
	h.dev.send(1500)
	h.e.Tick(now.Add(30 * time.Second))
	h.dev.send(1500)
	h.e.Tick(now.Add(time.Minute))
	if got := h.log.count("core.reconnect"); got != 1 {
		t.Fatalf("core.reconnect %d раз", got)
	}

	h.e.Tick(now.Add(time.Hour))

	if got := h.log.count("core.reconnect"); got != 1 {
		t.Errorf("сработал старый рост: %d", got)
	}
}

// Пока ядро переподключалось, туннель слал повторы рукопожатия. После восстановления ему
// нужен такт, чтобы договориться, иначе Reconnect сбил бы только что поднятые потоки.
func TestStaleCheckRestartsAfterReconnecting(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())
	now := time.Now()
	h.dev.setHandshake(now.Add(-time.Hour), nil)
	h.e.Tick(now)

	h.e.OnCoreState("connecting", 0, 12, "")
	h.e.Tick(now.Add(10 * time.Second))
	h.dev.send(1500)
	h.e.OnCoreState("connected", 3, 12, "")
	h.e.Tick(now.Add(30 * time.Second))
	h.wantNotCalled("core.reconnect")

	h.dev.send(1500)
	h.e.Tick(now.Add(time.Minute))
	if got := h.log.count("core.reconnect"); got != 1 {
		t.Errorf("core.reconnect %d раз", got)
	}
}

// Нулевое время значит «неизвестно», а не «давно»: шаг 4 уже дождался рукопожатия.
func TestUnknownHandshakeLeftAlone(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())
	now := time.Now()
	h.dev.setHandshake(time.Time{}, nil)
	h.e.Tick(now)

	h.dev.send(1500)
	h.e.Tick(now.Add(30 * time.Second))

	h.wantNotCalled("core.reconnect")
}

func TestFreshHandshakeLeftAlone(t *testing.T) {
	h := newHarness(t)
	from := h.up(subnetRequest())
	now := time.Now()
	h.dev.setHandshake(now.Add(-staleHandshake), nil)
	h.e.Tick(now.Add(-time.Second))

	h.dev.send(1500)
	h.e.Tick(now)

	h.wantSince(from, "tunnel.stats", "tunnel.stats")
	if len(h.e.Status().Warnings) != 0 {
		t.Errorf("предупреждения %+v", h.e.Status().Warnings)
	}
}

func TestHandshakeStatsFail(t *testing.T) {
	h := newHarness(t)
	from := h.up(subnetRequest())
	h.dev.setHandshake(time.Time{}, errBoom)

	h.e.Tick(time.Now())

	h.wantSince(from, "tunnel.stats")
	h.wantLogged(errBoom.Error())
}

// staleSetup готовит туннель, где не хватает только роста счётчика: рукопожатие старое,
// а первый такт уже запомнил отправленное. Возвращает длину журнала после него.
func (h *harness) staleSetup(now time.Time) int {
	h.t.Helper()
	h.up(subnetRequest())
	h.dev.setHandshake(now.Add(-time.Hour), nil)
	h.e.Tick(now.Add(-30 * time.Second))
	return len(h.log.snapshot())
}

// Проверка нужна только там, где ядро считает себя подключённым.
func TestStaleHandshakeOnlyWhenCoreConnected(t *testing.T) {
	cases := map[string]string{"подключается": "connecting", "капча": "captcha"}
	for name, state := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			now := time.Now()
			from := h.staleSetup(now)

			// Автоматическая капча идёт при живых потоках, фаза остаётся Connected.
			h.e.OnCoreState(state, 1, 12, "")
			h.dev.send(1500)
			h.e.Tick(now)

			h.wantSince(from)
		})
	}
}

func TestStaleHandshakeWaitsWhileReconnecting(t *testing.T) {
	h := newHarness(t)
	now := time.Now()
	from := h.staleSetup(now)
	h.e.OnCoreState("connecting", 0, 12, "")
	h.waitPhase(model.PhaseReconnecting)

	h.dev.send(1500)
	h.e.Tick(now)

	h.wantSince(from)
}

// Без сети ядро ещё считает себя подключённым, но переподключаться ему не через что.
func TestStaleHandshakeSkippedWithoutNetwork(t *testing.T) {
	h := newHarness(t)
	now := time.Now()
	from := h.staleSetup(now)
	h.net.setPhysical(model.Physical{}, netcfg.ErrNoNetwork)
	h.e.NetworkChanged()

	h.dev.send(1500)
	h.e.Tick(now)

	h.wantSince(from)
}

// Сон старит рукопожатие, а Wake сам решает, живы ли аллокации. Reconnect поверх него
// пересоздал бы живой канал ценой похода за реквизитами и капчи.
func TestWakeDefersStaleCheck(t *testing.T) {
	h := newHarness(t)
	now := time.Now()
	h.staleSetup(now)

	h.e.Woke()
	h.dev.send(1500)
	h.e.Tick(now.Add(30 * time.Second))

	h.wantNotCalled("core.reconnect")
}

func TestNetworkChangeDefersStaleCheck(t *testing.T) {
	h := newHarness(t)
	now := time.Now()
	h.staleSetup(now)

	h.net.setPhysical(otherPhysical(), nil)
	h.e.NetworkChanged()
	h.dev.send(1500)
	h.e.Tick(now.Add(30 * time.Second))

	if got := h.log.count("core.reconnect"); got != 1 {
		t.Errorf("core.reconnect %d раз", got)
	}
}

func TestDomainRefreshEveryFiveMinutes(t *testing.T) {
	h := newHarness(t)
	h.res.answers[testDomain] = []netip.Addr{firstAddr}
	from := h.up(domainRequest())
	start := time.Now()

	h.res.answer(testDomain, secondAddr)
	h.e.Tick(start.Add(domainRefresh - time.Minute))
	h.wantSince(from, "tunnel.stats")

	h.e.Tick(start.Add(domainRefresh))

	h.wantSince(from, "tunnel.stats", "tunnel.stats", "resolve", "fw.update", "net.bypass")
	for _, a := range []netip.Addr{firstAddr, secondAddr} {
		if !hasPrefix(h.net.bypassed(), a) {
			t.Errorf("в обходе нет %s: %v", a, h.net.bypassed())
		}
		if !hasPrefix(h.fw.last().Bypass, a) {
			t.Errorf("в брандмауэре нет %s: %v", a, h.fw.last().Bypass)
		}
	}
	if got := h.net.bypassPhysical(); got.LUID != firstPhysical().LUID {
		t.Errorf("обход ушёл на %+v", got)
	}

	// Следующий срок считается от этого обновления.
	h.e.Tick(start.Add(2*domainRefresh - time.Minute))
	if got := h.log.count("resolve"); got != 2 {
		t.Errorf("resolve %d раз", got)
	}
}

func TestDomainRefreshKeepsOldAddresses(t *testing.T) {
	h := newHarness(t)
	h.res.answers[testDomain] = []netip.Addr{firstAddr}
	from := h.up(domainRequest())

	h.res.answer(testDomain)
	h.e.Tick(time.Now().Add(domainRefresh))

	h.wantSince(from, "tunnel.stats", "resolve")
	if !hasPrefix(h.net.bypassed(), firstAddr) {
		t.Errorf("обход %v", h.net.bypassed())
	}

	// Старый адрес живёт и в следующем наборе.
	h.res.answer(testDomain, secondAddr)
	h.e.Tick(time.Now().Add(2 * domainRefresh))
	if !hasPrefix(h.net.bypassed(), firstAddr) || !hasPrefix(h.net.bypassed(), secondAddr) {
		t.Errorf("обход %v", h.net.bypassed())
	}
}

func TestDomainRefreshSameAddresses(t *testing.T) {
	h := newHarness(t)
	h.res.answers[testDomain] = []netip.Addr{firstAddr}
	from := h.up(domainRequest())

	h.e.Tick(time.Now().Add(domainRefresh))

	h.wantSince(from, "tunnel.stats", "resolve")
}

func TestDomainRefreshNoDomains(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())

	h.e.Tick(time.Now().Add(domainRefresh))

	h.wantNotCalled("resolve")
}

func TestDomainRefreshKillSwitchOff(t *testing.T) {
	h := newHarness(t)
	h.res.answers[testDomain] = []netip.Addr{firstAddr}
	req := domainRequest()
	req.Options.KillSwitch = false
	h.up(req)

	h.res.answer(testDomain, secondAddr)
	h.e.Tick(time.Now().Add(domainRefresh))

	h.wantNotCalled("fw.update", "fw.enable")
	if !hasPrefix(h.net.bypassed(), secondAddr) {
		t.Errorf("обход %v", h.net.bypassed())
	}
}

func TestDomainRefreshWhileReconnecting(t *testing.T) {
	h := newHarness(t)
	h.res.answers[testDomain] = []netip.Addr{firstAddr}
	h.up(domainRequest())
	h.e.OnCoreState("connecting", 0, 12, "")
	h.waitPhase(model.PhaseReconnecting)

	h.res.answer(testDomain, secondAddr)
	h.e.Tick(time.Now().Add(domainRefresh))

	if !hasPrefix(h.net.bypassed(), secondAddr) {
		t.Errorf("обход %v", h.net.bypassed())
	}
}

func TestDomainRefreshSkippedWithoutNetwork(t *testing.T) {
	h := newHarness(t)
	h.res.answers[testDomain] = []netip.Addr{firstAddr}
	h.up(domainRequest())
	h.net.setPhysical(model.Physical{}, netcfg.ErrNoNetwork)
	h.e.NetworkChanged()
	resolved := h.log.count("resolve")

	h.e.Tick(time.Now().Add(domainRefresh))
	if got := h.log.count("resolve"); got != resolved {
		t.Errorf("resolve без сети: %d", got-resolved)
	}

	// Срок не сгорел: сеть вернулась, и обновление идёт на первом же такте.
	h.net.setPhysical(firstPhysical(), nil)
	h.e.NetworkChanged()
	h.e.Tick(time.Now().Add(domainRefresh))
	if got := h.log.count("resolve"); got != resolved+1 {
		t.Errorf("resolve после возврата сети: %d", got-resolved)
	}
}

// Адреса держатся до отключения: сбой их не забывает, следующий такт повторяет применение
// сам, без нового разрешения и без Reconnect.
func TestDomainRefreshFailureRetries(t *testing.T) {
	for _, step := range []string{"fw.update", "net.bypass"} {
		t.Run(step, func(t *testing.T) {
			h := newHarness(t)
			h.res.answers[testDomain] = []netip.Addr{firstAddr}
			h.up(domainRequest())
			h.res.answer(testDomain, secondAddr)
			h.log.failOn(step, errBoom)
			at := time.Now().Add(domainRefresh)

			h.e.Tick(at)
			h.wantLogged(errBoom.Error())
			if st := h.e.Status(); st.Phase != model.PhaseConnected {
				t.Errorf("статус %+v", st)
			}

			// Домен больше не отвечает, но адрес уже получен и никуда не делся.
			h.res.answer(testDomain)
			resolved := h.log.count("resolve")
			bypasses := h.log.count("net.bypass")
			h.log.failOn(step, nil)
			h.e.Tick(at.Add(30 * time.Second))

			// Заглушка запоминает аргументы и при сбое, поэтому важен именно новый вызов.
			if got := h.log.count("net.bypass"); got != bypasses+1 {
				t.Errorf("повторов net.bypass: %d", got-bypasses)
			}
			for _, a := range []netip.Addr{firstAddr, secondAddr} {
				if !hasPrefix(h.net.bypassed(), a) || !hasPrefix(h.fw.last().Bypass, a) {
					t.Errorf("нет %s: обход %v, брандмауэр %v", a, h.net.bypassed(), h.fw.last().Bypass)
				}
			}
			if got := h.log.count("resolve"); got != resolved {
				t.Errorf("лишний resolve: %d", got-resolved)
			}
			h.wantNotCalled("core.reconnect")

			from := len(h.log.snapshot())
			h.e.Tick(at.Add(time.Minute))
			h.wantSince(from, "tunnel.stats")
		})
	}
}

// Без разрешения в блокировке маршрут увёл бы адрес из работающего туннеля в никуда.
func TestDomainRefreshFirewallFirst(t *testing.T) {
	h := newHarness(t)
	h.res.answers[testDomain] = []netip.Addr{firstAddr}
	h.up(domainRequest())
	bypasses := h.log.count("net.bypass")
	h.res.answer(testDomain, secondAddr)
	h.log.failOn("fw.update", errBoom)

	h.e.Tick(time.Now().Add(domainRefresh))

	if got := h.log.count("net.bypass"); got != bypasses {
		t.Errorf("маршрут поставлен без разрешения: %v", h.log.snapshot())
	}
}

func TestDisconnectDuringDomainRefresh(t *testing.T) {
	h := newHarness(t)
	h.res.answers[testDomain] = []netip.Addr{firstAddr}
	h.up(domainRequest())
	h.res.setHang(true)
	resolved := h.log.count("resolve")

	ticked := make(chan struct{})
	go func() {
		defer close(ticked)
		h.e.Tick(time.Now().Add(domainRefresh))
	}()
	h.waitFor("обновление началось", func() bool { return h.log.count("resolve") > resolved })

	returnsSoon(t, "Disconnect", h.e.Disconnect)
	returnsSoon(t, "Tick", func() { <-ticked })

	h.wantNotCalled("fw.update")
	if got := h.log.snapshot(); got[len(got)-1] != "core.stop" {
		t.Errorf("журнал %v", got)
	}
}

// Отмена между блокировкой и маршрутами: откат всё равно их снимет, ставить незачем.
func TestDisconnectStopsAddressApply(t *testing.T) {
	h := newHarness(t)
	h.res.answers[testDomain] = []netip.Addr{firstAddr}
	h.up(domainRequest())
	h.res.answer(testDomain, secondAddr)
	bypasses := h.log.count("net.bypass")
	release := h.log.hold("fw.update")
	defer release()

	ticked := make(chan struct{})
	go func() {
		defer close(ticked)
		h.e.Tick(time.Now().Add(domainRefresh))
	}()
	h.waitCall("fw.update")

	stopped := disconnectAsync(h.e)
	h.waitCancelled()
	release()
	<-ticked
	<-stopped

	if got := h.log.count("net.bypass"); got != bypasses {
		t.Errorf("маршруты поставлены после отмены: %v", h.log.snapshot())
	}
}

// Блокировка пережила сбой сессии, опоздавшее обновление не должно её трогать.
func TestFatalDuringDomainRefresh(t *testing.T) {
	h := newHarness(t)
	h.res.answers[testDomain] = []netip.Addr{firstAddr}
	h.up(domainRequest())
	h.res.answer(testDomain, secondAddr)
	resolved := h.log.count("resolve")
	release := h.log.hold("resolve")
	defer release()

	ticked := make(chan struct{})
	go func() {
		defer close(ticked)
		h.e.Tick(time.Now().Add(domainRefresh))
	}()
	h.waitFor("обновление началось", func() bool { return h.log.count("resolve") > resolved })

	h.e.OnCoreState("error", 0, 12, "fatal: CALL_FULL")
	h.waitPhase(model.PhaseBlocked)
	release()
	<-ticked

	h.wantNotCalled("fw.update")
}

// Два такта подряд не запускают обновление дважды.
func TestDomainRefreshNotDoubled(t *testing.T) {
	h := newHarness(t)
	h.res.answers[testDomain] = []netip.Addr{firstAddr}
	h.up(domainRequest())
	h.res.setHang(true)
	resolved := h.log.count("resolve")
	at := time.Now().Add(domainRefresh)

	ticked := make(chan struct{})
	go func() {
		defer close(ticked)
		h.e.Tick(at)
	}()
	h.waitFor("обновление началось", func() bool { return h.log.count("resolve") > resolved })

	h.e.Tick(at.Add(time.Second))

	if got := h.log.count("resolve"); got != resolved+1 {
		t.Errorf("resolve %d раз", got-resolved)
	}
	h.e.Disconnect()
	<-ticked
}

func TestTimersIdleOutsideSession(t *testing.T) {
	h := newHarness(t)
	h.e.Tick(time.Now().Add(time.Hour))
	h.e.RefreshRates()
	if got := h.log.snapshot(); len(got) != 0 {
		t.Errorf("журнал %v", got)
	}
}

func TestTimersNeverWaitForConnect(t *testing.T) {
	h := newHarness(t)
	release := h.log.hold("core.start")
	defer release()
	h.connect(testRequest())
	h.waitCall("core.start")

	returnsSoon(t, "Tick", func() { h.e.Tick(time.Now().Add(time.Hour)) })
	returnsSoon(t, "RefreshRates", h.e.RefreshRates)
	returnsSoon(t, "NetworkChanged", h.e.NetworkChanged)
	returnsSoon(t, "Woke", h.e.Woke)
	h.wantNotCalled("core.rates", "tunnel.stats", "core.wake")
}

func TestTimersNeverWaitForRollback(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())
	release := h.log.hold("core.stop")
	defer release()

	stopped := disconnectAsync(h.e)
	h.waitCall("core.stop")

	returnsSoon(t, "Tick", func() { h.e.Tick(time.Now().Add(time.Hour)) })
	returnsSoon(t, "RefreshRates", h.e.RefreshRates)
	returnsSoon(t, "NetworkChanged", h.e.NetworkChanged)
	returnsSoon(t, "Woke", h.e.Woke)
	h.wantNotCalled("core.rates", "tunnel.stats", "core.wake", "core.reconnect")

	release()
	<-stopped
}

// OnChange идёт без блокировок монитора: он может читать Status, а Disconnect не ждёт его.
func TestOnChangeFromMonitorCanReadStatus(t *testing.T) {
	var h *harness
	h = newHarness(t, func(d *Deps) {
		d.OnChange = func(model.Status) {
			if h != nil {
				_ = h.e.Status()
			}
		}
	})
	h.up(subnetRequest())

	returnsSoon(t, "NetworkChanged", func() {
		h.net.setPhysical(model.Physical{}, netcfg.ErrNoNetwork)
		h.e.NetworkChanged()
	})
	h.core.setRates(1, 2, 3, 4)
	h.e.OnCoreState("connected", 2, 12, "")
	h.net.setPhysical(firstPhysical(), nil)
	returnsSoon(t, "NetworkChanged", h.e.NetworkChanged)
	returnsSoon(t, "RefreshRates", h.e.RefreshRates)
}

func TestReconnectingPhase(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())

	h.e.OnCoreState("connecting", 0, 12, "")

	if st := h.e.Status(); st.Phase != model.PhaseReconnecting {
		t.Errorf("статус %+v", st)
	}
	h.wantNotCalled("net.clear", "net.bypassClear", "tunnel.close", "fw.disable", "core.stop")
}

func TestReconnectedPhase(t *testing.T) {
	h := newHarness(t)
	h.up(subnetRequest())
	h.e.OnCoreState("connecting", 0, 12, "")

	h.e.OnCoreState("connected", 3, 12, "")

	if st := h.e.Status(); st.Phase != model.PhaseConnected || st.Streams != 3 {
		t.Errorf("статус %+v", st)
	}
}

// Таймеры и смена сети идут вперемешку с командами. Опоздавший монитор не должен оставить
// маршруты после отката и не должен застрять на блокировках.
func TestMonitorStress(t *testing.T) {
	h := newHarness(t)
	h.res.answers[testDomain] = []netip.Addr{firstAddr}
	var stop atomic.Bool
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Go(func() {
			r := rand.New(rand.NewPCG(uint64(g), 11))
			for !stop.Load() {
				switch r.IntN(7) {
				case 0:
					h.net.setPhysical(otherPhysical(), nil)
				case 1:
					h.net.setPhysical(firstPhysical(), nil)
				case 2:
					h.net.setPhysical(model.Physical{}, netcfg.ErrNoNetwork)
				case 3:
					h.e.NetworkChanged()
				case 4:
					h.e.Woke()
				case 5:
					h.e.RefreshRates()
				case 6:
					h.e.Tick(time.Now().Add(time.Duration(r.IntN(10)) * time.Minute))
				}
			}
		})
	}
	for range 200 {
		_ = h.e.Connect(domainRequest())
		h.waitFor("подключение или ошибка", func() bool {
			p := h.e.Status().Phase
			return p != model.PhaseConnecting && p != model.PhaseIdle
		})
		h.e.Disconnect()
		got := h.log.snapshot()
		if i, j := lastIndex(got, "net.bypass"), lastIndex(got, "net.bypassClear"); i > j {
			stop.Store(true)
			t.Fatalf("обход поставлен после отката: %v", got[max(0, j-3):])
		}
	}
	stop.Store(true)
	wg.Wait()
}

func lastIndex(list []string, name string) int {
	for i, got := range slices.Backward(list) {
		if got == name {
			return i
		}
	}
	return -1
}
