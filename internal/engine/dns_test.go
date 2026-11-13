package engine

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/vanbujhm/freeturn-windows/internal/dnsproxy"
	"github.com/vanbujhm/freeturn-windows/internal/model"
)

var (
	proxyAddr  = netip.MustParseAddr("127.0.0.53")
	configDNS  = netip.MustParseAddr("198.51.100.53")
	dynamicOne = netip.MustParseAddr("203.0.113.9")
	dynamicTwo = netip.MustParseAddr("203.0.113.10")
	dynamicSix = netip.MustParseAddr("203.0.113.11")
)

// fakeDNSProxy записывает запуск, смену серверов и остановку прокси в общий журнал вызовов.
type fakeDNSProxy struct {
	log       *calls
	mu        sync.Mutex
	cfg       dnsproxy.Config
	ups       []dnsproxy.Upstreams
	failStart error
}

func (f *fakeDNSProxy) Start(c dnsproxy.Config) (RunningProxy, error) {
	f.mu.Lock()
	f.cfg = c
	fail := f.failStart
	f.mu.Unlock()
	_ = f.log.hit("dns.start")
	if fail != nil {
		return nil, fail
	}
	return f, nil
}

func (f *fakeDNSProxy) SetUpstreams(u dnsproxy.Upstreams) {
	f.mu.Lock()
	f.ups = append(f.ups, u)
	f.mu.Unlock()
	_ = f.log.hit("dns.upstreams")
}

func (f *fakeDNSProxy) Close() { _ = f.log.hit("dns.close") }

func (f *fakeDNSProxy) config() dnsproxy.Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg
}

func (f *fakeDNSProxy) upstreams() []dnsproxy.Upstreams {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.ups)
}

// proxyHarness - стенд с прокси сеанса.
func proxyHarness(t *testing.T, tune ...func(*fakeDNSProxy)) (*harness, *fakeDNSProxy) {
	t.Helper()
	var p *fakeDNSProxy
	h := newHarness(t, func(d *Deps) {
		p = &fakeDNSProxy{}
		for _, f := range tune {
			f(p)
		}
		d.DNSProxy = p
		d.QueryLog = dnsproxy.NewLog()
		d.TunnelIndexes = func(uint64) (uint32, uint32) { return 31, 32 }
	})
	p.log = h.log
	return h, p
}

func domainRules(req model.ConnectRequest) model.ConnectRequest {
	req.Options.Rules = []model.Rule{{Kind: model.RuleDomain, Value: "example.com"}}
	return req
}

func (h *harness) sink(p *fakeDNSProxy) dnsproxy.Sink {
	h.t.Helper()
	s := p.config().Sink
	if s == nil {
		h.t.Fatal("прокси запущен без Sink")
	}
	return s
}

func TestDNSProxyStartOrder(t *testing.T) {
	h, p := proxyHarness(t)
	h.connect(domainRules(testRequest()))
	h.waitPhase(model.PhaseConnected)

	h.wantBefore("tunnel.handshake", "dns.start")
	h.wantBefore("dns.start", "fw.enable")
	h.wantBefore("net.routes", "net.nrpt")
	h.net.mu.Lock()
	dns := slices.Clone(h.net.dns)
	h.net.mu.Unlock()
	if !slices.Equal(dns, []netip.Addr{proxyAddr}) {
		t.Errorf("DNS адаптера %v", dns)
	}
	if fw := h.fw.last().DNS; !slices.Contains(fw, configDNS) || !slices.Contains(fw, proxyAddr) {
		t.Errorf("DNS брандмауэра %v", fw)
	}
	c := p.config()
	if c.Listen != dnsproxy.Listen || !slices.Equal(c.Domains, []string{"example.com"}) || c.TunnelOnly || c.SplitOff {
		t.Errorf("Config %+v", c)
	}
	u := c.Upstreams
	if !slices.Equal(u.Tunnel, []netip.Addr{configDNS}) || !slices.Equal(u.Direct, firstPhysical().DNS) ||
		u.Direct4 != 11 || u.Direct6 != 12 || u.Tunnel4 != 31 || u.Tunnel6 != 32 {
		t.Errorf("Upstreams %+v", u)
	}
	if c.Log == nil || c.Logf == nil {
		t.Error("прокси без журнала")
	}
	if !h.e.ProxyActive() {
		t.Error("ProxyActive false при работающем прокси")
	}
}

func TestDNSProxyRollbackOrder(t *testing.T) {
	h, _ := proxyHarness(t)
	h.connect(domainRules(testRequest()))
	h.waitPhase(model.PhaseConnected)
	before := len(h.log.snapshot())

	h.e.Disconnect()

	got := h.log.snapshot()[before:]
	i, j, k := slices.Index(got, "net.nrptClear"), slices.Index(got, "net.clear"), slices.Index(got, "dns.close")
	if i < 0 || j < 0 || k < 0 || !(i < j && j < k) {
		t.Fatalf("порядок отката %v", got)
	}
	if h.e.ProxyActive() {
		t.Error("ProxyActive после отключения")
	}
}

func TestDNSProxyTunnelOnly(t *testing.T) {
	h, p := proxyHarness(t)
	req := domainRules(testRequest())
	req.Options.SplitMode = model.SplitOnly
	h.connect(req)
	h.waitPhase(model.PhaseConnected)

	h.wantNotCalled("net.routes")
	h.wantCalled("net.tunDNS", "net.nrpt")
	h.net.mu.Lock()
	dns := slices.Clone(h.net.tunDNS)
	h.net.mu.Unlock()
	if !slices.Equal(dns, []netip.Addr{proxyAddr}) {
		t.Errorf("DNS адаптера %v", dns)
	}
	if !p.config().TunnelOnly {
		t.Error("прокси не знает режим «только список»")
	}
}

func TestDNSProxyStartFails(t *testing.T) {
	h, _ := proxyHarness(t, func(p *fakeDNSProxy) { p.failStart = errors.New("порт занят") })
	h.connect(domainRules(testRequest()))
	h.waitPhase(model.PhaseConnected)

	h.wantWarning(model.Warning{Code: model.WarnDNSProxy, Value: "порт занят"})
	h.wantNotCalled("net.nrpt", "net.tunDNS")
	h.net.mu.Lock()
	dns := slices.Clone(h.net.dns)
	h.net.mu.Unlock()
	if !slices.Equal(dns, []netip.Addr{configDNS}) {
		t.Errorf("DNS адаптера %v", dns)
	}
	if slices.Contains(h.fw.last().DNS, proxyAddr) {
		t.Errorf("брандмауэр разрешает прокси, которого нет: %v", h.fw.last().DNS)
	}
	if h.e.ProxyActive() {
		t.Error("ProxyActive без прокси")
	}
}

func TestDNSProxyNRPTFails(t *testing.T) {
	h, _ := proxyHarness(t)
	h.log.failOn("net.nrpt", errBoom)
	h.connect(domainRules(testRequest()))
	st := h.waitPhase(model.PhaseConnected)

	found := false
	for _, w := range st.Warnings {
		found = found || w.Code == model.WarnDNSProxy
	}
	if !found {
		t.Errorf("нет предупреждения dns_proxy: %+v", st.Warnings)
	}
}

func TestDNSProxyNilKeepsOldScheme(t *testing.T) {
	h := newHarness(t)
	h.connect(domainRules(testRequest()))
	st := h.waitPhase(model.PhaseConnected)
	h.wantNotCalled("dns.start", "net.nrpt", "net.tunDNS")
	for _, w := range st.Warnings {
		if w.Code == model.WarnDNSProxy {
			t.Errorf("предупреждение о прокси без прокси: %+v", w)
		}
	}
	h.net.mu.Lock()
	dns := slices.Clone(h.net.dns)
	h.net.mu.Unlock()
	if !slices.Equal(dns, []netip.Addr{configDNS}) {
		t.Errorf("DNS адаптера %v", dns)
	}
}

func TestDNSProxyNetworkChange(t *testing.T) {
	h, p := proxyHarness(t)
	h.up(domainRules(testRequest()))

	h.net.setPhysical(otherPhysical(), nil)
	h.e.NetworkChanged()

	ups := p.upstreams()
	if len(ups) == 0 {
		t.Fatal("серверы прокси не обновлены")
	}
	u := ups[len(ups)-1]
	if !slices.Equal(u.Direct, otherPhysical().DNS) || u.Direct4 != 21 || u.Direct6 != 22 ||
		!slices.Equal(u.Tunnel, []netip.Addr{configDNS}) || u.Tunnel4 != 31 {
		t.Errorf("Upstreams %+v", u)
	}
}

func TestApplyNewAddrs(t *testing.T) {
	h, p := proxyHarness(t)
	h.up(domainRules(testRequest()))
	from := len(h.log.snapshot())

	if err := h.sink(p).Apply(context.Background(), []netip.Addr{dynamicOne}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(h.net.bypassed(), netip.PrefixFrom(dynamicOne, 32)) {
		t.Errorf("обход %v", h.net.bypassed())
	}
	h.wantSince(from, "fw.update", "net.bypass")
}

func TestApplyKnownAddrsReturnsAtOnce(t *testing.T) {
	h, p := proxyHarness(t)
	h.up(domainRules(testRequest()))
	if err := h.sink(p).Apply(context.Background(), []netip.Addr{dynamicOne}); err != nil {
		t.Fatal(err)
	}
	from := len(h.log.snapshot())
	if err := h.sink(p).Apply(context.Background(), []netip.Addr{dynamicOne}); err != nil {
		t.Fatal(err)
	}
	h.wantSince(from)
}

func TestApplyCoalesces(t *testing.T) {
	h, p := proxyHarness(t)
	h.up(domainRules(testRequest()))
	before := h.log.count("net.bypass")
	release := h.log.hold("net.bypass")
	t.Cleanup(release) // иначе при провале откат ждал бы зажатый шаг
	sink := h.sink(p)

	errs := make(chan error, 3)
	go func() { errs <- sink.Apply(context.Background(), []netip.Addr{dynamicOne}) }()
	h.waitFor("первая партия", func() bool { return h.log.count("net.bypass") == before+1 })
	go func() { errs <- sink.Apply(context.Background(), []netip.Addr{dynamicTwo}) }()
	go func() { errs <- sink.Apply(context.Background(), []netip.Addr{dynamicSix}) }()
	time.Sleep(50 * time.Millisecond) // обе встают в следующую партию
	release()
	for range 3 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if n := h.log.count("net.bypass") - before; n != 2 {
		t.Errorf("применений %d, ожидалось 2", n)
	}
	for _, a := range []netip.Addr{dynamicOne, dynamicTwo, dynamicSix} {
		if !slices.Contains(h.net.bypassed(), netip.PrefixFrom(a, 32)) {
			t.Errorf("%s не в обходе: %v", a, h.net.bypassed())
		}
	}
}

func TestApplyWaitsOwnBatch(t *testing.T) {
	h, p := proxyHarness(t)
	h.up(domainRules(testRequest()))
	before := h.log.count("net.bypass")
	release := h.log.hold("net.bypass")
	t.Cleanup(release) // иначе при провале откат ждал бы зажатый шаг
	sink := h.sink(p)

	first := make(chan error, 1)
	go func() { first <- sink.Apply(context.Background(), []netip.Addr{dynamicOne}) }()
	h.waitFor("первая партия", func() bool { return h.log.count("net.bypass") == before+1 })
	second := make(chan error, 1)
	go func() { second <- sink.Apply(context.Background(), []netip.Addr{dynamicOne}) }()
	select {
	case err := <-second:
		t.Fatalf("повтор вернулся до применения своей партии: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	release()
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	if n := h.log.count("net.bypass") - before; n != 1 {
		t.Errorf("применений %d", n)
	}
}

func TestApplyLimit(t *testing.T) {
	h, p := proxyHarness(t)
	h.up(domainRules(testRequest()))
	from := len(h.log.snapshot())
	many := make([]netip.Addr, 0, MaxDynamicAddrs+1)
	for i := range MaxDynamicAddrs + 1 {
		many = append(many, netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}))
	}
	for range 2 {
		if err := h.sink(p).Apply(context.Background(), many); !errors.Is(err, ErrDNSLimit) {
			t.Fatalf("ошибка %v", err)
		}
	}
	h.wantSince(from)
	n := 0
	for _, w := range h.e.Status().Warnings {
		if w.Code == model.WarnDNSLimit {
			n++
		}
	}
	if n != 1 {
		t.Errorf("предупреждений dns_limit %d", n)
	}
}

func TestApplyAfterStop(t *testing.T) {
	h, p := proxyHarness(t)
	h.up(domainRules(testRequest()))
	sink := h.sink(p)
	h.e.Disconnect()
	from := len(h.log.snapshot())
	if err := sink.Apply(context.Background(), []netip.Addr{dynamicOne}); err == nil {
		t.Fatal("Apply после отключения без ошибки")
	}
	h.wantSince(from)
}

func TestApplyCtxExpires(t *testing.T) {
	h, p := proxyHarness(t)
	h.up(domainRules(testRequest()))
	release := h.log.hold("net.bypass")
	t.Cleanup(release) // иначе при провале откат ждал бы зажатый шаг
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := h.sink(p).Apply(ctx, []netip.Addr{dynamicOne}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ошибка %v", err)
	}
	release()
	h.waitFor("партия применена", func() bool {
		return slices.Contains(h.net.bypassed(), netip.PrefixFrom(dynamicOne, 32))
	})
}

// После неудачного подключения откат снял маршруты. Опоздавшая партия адресов не должна
// поставить их снова.
func TestApplyAfterFailedConnect(t *testing.T) {
	h, p := proxyHarness(t)
	h.log.failOn("net.routes", errBoom)
	h.connect(domainRules(testRequest()))
	h.waitPhase(model.PhaseError)
	sink := h.sink(p)
	from := len(h.log.snapshot())
	if err := sink.Apply(context.Background(), []netip.Addr{dynamicOne}); err == nil {
		t.Fatal("Apply после сбоя подключения без ошибки")
	}
	h.wantSince(from)
}

// В режиме «только список» у адаптера нет маршрута по умолчанию: DNS конфига получает свой
// маршрут в туннель, иначе привязанным к адаптеру сокетам прокси некуда идти.
func TestDNSProxyTunnelOnlyRoutesConfigDNS(t *testing.T) {
	h, _ := proxyHarness(t)
	req := domainRules(testRequest())
	req.Options.SplitMode = model.SplitOnly
	h.connect(req)
	h.waitPhase(model.PhaseConnected)
	if got := h.net.tunnelListed(); !slices.Contains(got, netip.PrefixFrom(configDNS, 32)) {
		t.Fatalf("маршруты списка %v без DNS конфига", got)
	}
}
