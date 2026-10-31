package engine

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vanbujhm/freeturn-windows/internal/firewall"
	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/tunnel"
	"github.com/vanbujhm/freeturn-windows/internal/wgconf"
)

// calls - общий журнал вызовов всех заглушек. Через него же задаётся поведение шага:
// fail заставляет его упасть, gate держит его до закрытия канала.
type calls struct {
	mu   sync.Mutex
	list []string
	fail map[string]error
	gate map[string]chan struct{}
}

func newCalls() *calls {
	return &calls{fail: map[string]error{}, gate: map[string]chan struct{}{}}
}

// hit записывает вызов, ждёт gate шага и возвращает его ошибку.
func (c *calls) hit(name string) error {
	c.mu.Lock()
	c.list = append(c.list, name)
	gate := c.gate[name]
	err := c.fail[name]
	c.mu.Unlock()
	if gate != nil {
		<-gate
	}
	return err
}

func (c *calls) failOn(name string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fail[name] = err
}

// hold ставит шаг на ожидание и возвращает функцию, которая его отпускает.
func (c *calls) hold(name string) (release func()) {
	gate := make(chan struct{})
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gate[name] = gate
	return sync.OnceFunc(func() { close(gate) })
}

func (c *calls) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.list)
}

func (c *calls) has(name string) bool {
	return slices.Contains(c.snapshot(), name)
}

func (c *calls) count(name string) int {
	n := 0
	for _, got := range c.snapshot() {
		if got == name {
			n++
		}
	}
	return n
}

type fakeCore struct {
	log     *calls
	engine  *Engine
	silent  bool   // ядро молчит: connected не приходит сам
	onStart func() // вызывается до возврата Start, как событие, обогнавшее его

	mu    sync.Mutex
	rates [4]int64 // txTotal, rxTotal, txRate, rxRate
}

func (f *fakeCore) Start(model.Profile, netip.AddrPort) error {
	if err := f.log.hit("core.start"); err != nil {
		return err
	}
	if f.onStart != nil {
		f.onStart()
	}
	// mobile.Start возвращается сразу, события идут из другой горутины.
	if !f.silent {
		go f.engine.OnCoreState("connected", 3, 12, "")
	}
	return nil
}

func (f *fakeCore) Stop()      { _ = f.log.hit("core.stop") }
func (f *fakeCore) Reconnect() { _ = f.log.hit("core.reconnect") }
func (f *fakeCore) Wake()      { _ = f.log.hit("core.wake") }
func (f *fakeCore) Rates() (int64, int64, int64, int64) {
	_ = f.log.hit("core.rates")
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rates[0], f.rates[1], f.rates[2], f.rates[3]
}

func (f *fakeCore) setRates(txTotal, rxTotal, txRate, rxRate int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rates = [4]int64{txTotal, rxTotal, txRate, rxRate}
}

type fakeDevice struct {
	log       *calls
	hang      bool // WaitHandshake ждёт отмены ctx
	cancelled chan struct{}

	mu       sync.Mutex
	stats    tunnel.Stats
	statsErr error
}

func (f *fakeDevice) LUID() uint64 { return testLUID }

func (f *fakeDevice) WaitHandshake(ctx context.Context) error {
	if err := f.log.hit("tunnel.handshake"); err != nil {
		return err
	}
	if !f.hang {
		return nil
	}
	<-ctx.Done()
	close(f.cancelled)
	return ctx.Err()
}

func (f *fakeDevice) Stats() (tunnel.Stats, error) {
	_ = f.log.hit("tunnel.stats")
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stats, f.statsErr
}

func (f *fakeDevice) setHandshake(at time.Time, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stats.LastHandshake, f.statsErr = at, err
}

func (f *fakeDevice) Close() { _ = f.log.hit("tunnel.close") }

type fakeTunnels struct {
	log *calls
	dev *fakeDevice
}

func (f *fakeTunnels) Open(*wgconf.Config, netip.AddrPort) (TunnelDevice, error) {
	if err := f.log.hit("tunnel.open"); err != nil {
		return nil, err
	}
	return f.dev, nil
}

type fakeNet struct {
	log      *calls
	physical model.Physical
	physErr  error
	other    string

	mu       sync.Mutex
	finds    int // сколько раз вызван FindPhysical
	excluded uint64
	bypass   []netip.Prefix
	bypassPh model.Physical
	allowed  []netip.Prefix
	dns      []netip.Addr
}

func (f *fakeNet) FindPhysical(exclude uint64) (model.Physical, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finds++
	f.excluded = exclude
	return f.physical, f.physErr
}

// setPhysical меняет то, что вернёт следующий FindPhysical.
func (f *fakeNet) setPhysical(ph model.Physical, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.physical, f.physErr = ph, err
}

func (f *fakeNet) findCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.finds
}

func (f *fakeNet) lastExcluded() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.excluded
}

func (f *fakeNet) bypassPhysical() model.Physical {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bypassPh
}

func (f *fakeNet) ConfigureInterface(uint64, []netip.Prefix, int) error {
	return f.log.hit("net.configure")
}

func (f *fakeNet) ApplyTunnelRoutes(_ uint64, allowed []netip.Prefix, dns []netip.Addr) error {
	f.mu.Lock()
	f.allowed, f.dns = allowed, dns
	f.mu.Unlock()
	return f.log.hit("net.routes")
}

func (f *fakeNet) ClearTunnel(uint64) error { return f.log.hit("net.clear") }

func (f *fakeNet) SetBypass(ph model.Physical, p []netip.Prefix) error {
	f.mu.Lock()
	f.bypassPh, f.bypass = ph, p
	f.mu.Unlock()
	return f.log.hit("net.bypass")
}

func (f *fakeNet) ClearBypass() error { return f.log.hit("net.bypassClear") }

func (f *fakeNet) OtherTunnel(uint64) (string, bool) { return f.other, f.other != "" }

func (f *fakeNet) bypassed() []netip.Prefix {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.bypass)
}

type fakeFirewall struct {
	log  *calls
	mu   sync.Mutex
	opts []firewall.Options // аргументы Enable и Update по порядку
}

func (f *fakeFirewall) save(o firewall.Options) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opts = append(f.opts, o)
}

func (f *fakeFirewall) Enable(o firewall.Options) error {
	f.save(o)
	return f.log.hit("fw.enable")
}

func (f *fakeFirewall) Update(o firewall.Options) error {
	f.save(o)
	return f.log.hit("fw.update")
}

func (f *fakeFirewall) Disable() { _ = f.log.hit("fw.disable") }

func (f *fakeFirewall) last() firewall.Options {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.opts) == 0 {
		return firewall.Options{}
	}
	return f.opts[len(f.opts)-1]
}

type fakeProtector struct {
	log *calls
	mu  sync.Mutex
	i4  uint32
	i6  uint32
}

func (f *fakeProtector) SetInterface(i4, i6 uint32) {
	f.mu.Lock()
	f.i4, f.i6 = i4, i6
	f.mu.Unlock()
	_ = f.log.hit("protect.set")
}

type fakeResolver struct {
	log     *calls
	answers map[string][]netip.Addr
	hang    bool // Resolve ждёт отмены ctx

	mu   sync.Mutex
	used model.Physical // с каким интерфейсом шёл последний запрос
}

func (f *fakeResolver) Resolve(ctx context.Context, domains []string, ph model.Physical) []netip.Addr {
	_ = f.log.hit("resolve")
	f.mu.Lock()
	f.used = ph
	hang := f.hang
	var out []netip.Addr
	for _, d := range domains {
		out = append(out, f.answers[d]...)
	}
	f.mu.Unlock()
	if hang {
		<-ctx.Done()
		return nil
	}
	return out
}

// answer задаёт ответ для домена, пока движок работает.
func (f *fakeResolver) answer(domain string, addrs ...netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[domain] = addrs
}

func (f *fakeResolver) setHang(hang bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hang = hang
}

func (f *fakeResolver) usedPhysical() model.Physical {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.used
}

const testLUID uint64 = 0xF00D

var (
	testPrivKey = testKey(1)
	testPSK     = testKey(3)
)

// testKey собирает ключ из 32 одинаковых байтов.
func testKey(b byte) string {
	raw := make([]byte, wgconf.KeyLen)
	for i := range raw {
		raw[i] = b
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// wgConfig собирает конфиг теста. dns может быть пустым.
func wgConfig(dns string) string {
	var sb strings.Builder
	sb.WriteString("[Interface]\nPrivateKey = " + testPrivKey + "\nAddress = 10.0.0.2/32\n")
	if dns != "" {
		sb.WriteString("DNS = " + dns + "\n")
	}
	sb.WriteString("\n[Peer]\nPublicKey = " + testKey(2) + "\nPresharedKey = " + testPSK +
		"\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.1:51820\nPersistentKeepalive = 25\n")
	return sb.String()
}

func testProfile() model.Profile {
	return model.Profile{
		ID:       "p1",
		Name:     "тест",
		Provider: "vk",
		Peer:     "203.0.113.1:56000",
		ObfKey:   "test-obf-key-000000000000",
		ClientID: "test-client-id-00000000",
		CallLink: "https://call.example.test/call/join/testlinksegment000",
		WGConfig: wgConfig("198.51.100.53"),
	}
}

func testRequest() model.ConnectRequest {
	return model.ConnectRequest{
		Profile: testProfile(),
		Options: model.Options{KillSwitch: true, AllowLAN: true},
	}
}

type harness struct {
	t    *testing.T
	log  *calls
	core *fakeCore
	dev  *fakeDevice
	net  *fakeNet
	fw   *fakeFirewall
	prot *fakeProtector
	res  *fakeResolver
	e    *Engine

	mu      sync.Mutex
	logged  []string
	changes []model.Status
}

// newHarness собирает движок на заглушках. Таймауты по умолчанию большие: зависнуть
// на них тест может только из-за ошибки, отдельные тесты ставят свои в tune.
func newHarness(t *testing.T, tune ...func(*Deps)) *harness {
	t.Helper()
	log := newCalls()
	h := &harness{
		t:    t,
		log:  log,
		core: &fakeCore{log: log},
		dev:  &fakeDevice{log: log, cancelled: make(chan struct{})},
		net: &fakeNet{log: log, physical: model.Physical{
			LUID: 7, Index4: 11, Index6: 12,
			Gateway4: netip.MustParseAddr("198.51.100.1"),
			DNS:      []netip.Addr{netip.MustParseAddr("198.51.100.2")},
		}},
		fw:   &fakeFirewall{log: log},
		prot: &fakeProtector{log: log},
		res:  &fakeResolver{log: log, answers: map[string][]netip.Addr{}},
	}
	d := Deps{
		Core:     h.core,
		Tunnels:  &fakeTunnels{log: log, dev: h.dev},
		Net:      h.net,
		FW:       h.fw,
		Protect:  h.prot,
		Resolver: h.res,
		FreePort: func() (netip.AddrPort, error) {
			return netip.MustParseAddrPort("127.0.0.1:45000"), nil
		},
		Classify: func(msg string) model.ErrorCode {
			if strings.Contains(msg, "CALL_FULL") {
				return model.ErrCallFull
			}
			return model.ErrCore
		},
		OnChange: func(st model.Status) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.changes = append(h.changes, st)
		},
		Logf: func(level, msg string) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.logged = append(h.logged, level+": "+msg)
		},
		Now:              time.Now,
		CoreTimeout:      time.Minute,
		HandshakeTimeout: time.Minute,
		FirewallGrace:    time.Minute,
	}
	for _, f := range tune {
		f(&d)
	}
	h.e = New(d)
	h.core.engine = h.e
	t.Cleanup(h.e.Disconnect)
	return h
}

func (h *harness) connect(req model.ConnectRequest) {
	h.t.Helper()
	if err := h.e.Connect(req); err != nil {
		h.t.Fatalf("Connect: %v", err)
	}
}

// waitFor ждёт условие, опрашивая каждую миллисекунду.
func (h *harness) waitFor(what string, cond func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			h.t.Fatalf("не дождались: %s; статус %+v, журнал %v", what, h.e.Status(), h.log.snapshot())
		}
		time.Sleep(time.Millisecond)
	}
}

func (h *harness) waitPhase(want model.Phase) model.Status {
	h.t.Helper()
	h.waitFor(fmt.Sprintf("фаза %s", want), func() bool { return h.e.Status().Phase == want })
	return h.e.Status()
}

func (h *harness) waitCall(name string) {
	h.t.Helper()
	h.waitFor("вызов "+name, func() bool { return h.log.has(name) })
}

func (h *harness) wantCalled(names ...string) {
	h.t.Helper()
	for _, n := range names {
		if !h.log.has(n) {
			h.t.Errorf("нет вызова %s, журнал %v", n, h.log.snapshot())
		}
	}
}

func (h *harness) wantNotCalled(names ...string) {
	h.t.Helper()
	for _, n := range names {
		if h.log.has(n) {
			h.t.Errorf("лишний вызов %s, журнал %v", n, h.log.snapshot())
		}
	}
}

func (h *harness) wantLog(want ...string) {
	h.t.Helper()
	if got := h.log.snapshot(); !slices.Equal(got, want) {
		h.t.Errorf("журнал\n got %v\nwant %v", got, want)
	}
}

func (h *harness) wantWarning(w model.Warning) {
	h.t.Helper()
	if st := h.e.Status(); !slices.Contains(st.Warnings, w) {
		h.t.Errorf("нет предупреждения %+v, есть %+v", w, st.Warnings)
	}
}

func (h *harness) logLines() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.logged)
}

func (h *harness) changeLog() []model.Status {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.changes)
}

var errBoom = errors.New("сбой заглушки")

func withCoreTimeout(d time.Duration) func(*Deps) {
	return func(deps *Deps) { deps.CoreTimeout = d }
}

func withHandshakeTimeout(d time.Duration) func(*Deps) {
	return func(deps *Deps) { deps.HandshakeTimeout = d }
}

func withFirewallGrace(d time.Duration) func(*Deps) {
	return func(deps *Deps) { deps.FirewallGrace = d }
}
