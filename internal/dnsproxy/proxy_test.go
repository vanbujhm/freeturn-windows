package dnsproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

var (
	addrA    = netip.MustParseAddr("203.0.113.7")
	addrAAAA = netip.MustParseAddr("2001:db8::7")
	addrZero = netip.MustParseAddr("0.0.0.0")
	addrFake = netip.MustParseAddr("198.18.0.1")
)

// reply - ответ поддельного сервера. silent: сервер молчит.
type reply struct {
	rcode    dnsmessage.RCode
	addrs    []netip.Addr
	truncate bool
	silent   bool
	delay    time.Duration
}

// upstream - поддельный DNS-сервер на 127.0.0.x по UDP и TCP на общем порту.
type upstream struct {
	ip      netip.Addr
	udp     net.PacketConn
	tcp     net.Listener
	answer  func(dnsmessage.Question) reply
	queries atomic.Int32
	mu      sync.Mutex
	seen    []string // "udp:имя" и "tcp:имя"
}

func startUpstream(t *testing.T, ip string, port uint16, answer func(dnsmessage.Question) reply) *upstream {
	t.Helper()
	u := &upstream{ip: netip.MustParseAddr(ip), answer: answer}
	udp, err := net.ListenPacket("udp4", netip.AddrPortFrom(u.ip, port).String())
	if err != nil {
		t.Fatalf("сервер UDP: %v", err)
	}
	port = uint16(udp.LocalAddr().(*net.UDPAddr).Port)
	tcp, err := net.Listen("tcp4", netip.AddrPortFrom(u.ip, port).String())
	if err != nil {
		udp.Close()
		t.Fatalf("сервер TCP: %v", err)
	}
	u.udp, u.tcp = udp, tcp
	t.Cleanup(func() { udp.Close(); tcp.Close() })
	go u.serveUDP()
	go u.serveTCP()
	return u
}

func (u *upstream) port() uint16 { return uint16(u.udp.LocalAddr().(*net.UDPAddr).Port) }

func (u *upstream) names() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.seen)
}

func (u *upstream) respond(network string, raw []byte) []byte {
	u.queries.Add(1)
	var req dnsmessage.Message
	if err := req.Unpack(raw); err != nil || len(req.Questions) != 1 {
		return nil
	}
	q := req.Questions[0]
	u.mu.Lock()
	u.seen = append(u.seen, network+":"+strings.TrimSuffix(q.Name.String(), "."))
	u.mu.Unlock()
	r := u.answer(q)
	if r.silent {
		return nil
	}
	time.Sleep(r.delay)
	return buildReply(req.ID, q, r)
}

func buildReply(id uint16, q dnsmessage.Question, r reply) []byte {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, Response: true, RecursionDesired: true, RecursionAvailable: true,
			RCode: r.rcode, Truncated: r.truncate},
		Questions: []dnsmessage.Question{q},
	}
	for _, a := range r.addrs {
		h := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
		if a.Is4() {
			h.Type = dnsmessage.TypeA
			msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.AResource{A: a.As4()}})
		} else {
			h.Type = dnsmessage.TypeAAAA
			msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.AAAAResource{AAAA: a.As16()}})
		}
	}
	b, _ := msg.Pack()
	return b
}

func (u *upstream) serveUDP() {
	buf := make([]byte, 65535)
	for {
		n, from, err := u.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		if b := u.respond("udp", slices.Clone(buf[:n])); b != nil {
			_, _ = u.udp.WriteTo(b, from)
		}
	}
}

func (u *upstream) serveTCP() {
	for {
		c, err := u.tcp.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			for {
				raw, err := readFrame(c)
				if err != nil {
					return
				}
				if b := u.respond("tcp", raw); b != nil {
					_ = writeFrame(c, b)
				}
			}
		}()
	}
}

func readFrame(c net.Conn) ([]byte, error) {
	var n [2]byte
	if _, err := io.ReadFull(c, n[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(n[:]))
	_, err := io.ReadFull(c, b)
	return b, err
}

func writeFrame(c net.Conn, b []byte) error {
	_, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...))
	return err
}

func answerAll(r reply) func(dnsmessage.Question) reply {
	return func(dnsmessage.Question) reply { return r }
}

// fakeSink записывает адреса Apply. gate, если задан, держит Apply до закрытия.
type fakeSink struct {
	mu    sync.Mutex
	calls [][]netip.Addr
	gate  chan struct{}
	err   error
}

func (s *fakeSink) Apply(ctx context.Context, addrs []netip.Addr) error {
	s.mu.Lock()
	s.calls = append(s.calls, slices.Clone(addrs))
	gate, err := s.gate, s.err
	s.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

func (s *fakeSink) applied() [][]netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

// logLines собирает строки Logf.
type logLines struct {
	mu    sync.Mutex
	lines []string
}

func (l *logLines) logf(_, msg string) {
	l.mu.Lock()
	l.lines = append(l.lines, msg)
	l.mu.Unlock()
}

func (l *logLines) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.lines)
}

// harness - прокси на 127.0.0.1:0 с поддельной привязкой сокетов.
type harness struct {
	t     *testing.T
	p     *Proxy
	addr  netip.AddrPort
	log   *Log
	lines *logLines
	mu    sync.Mutex
	binds []Side
}

func startHarness(t *testing.T, cfg Config, port uint16, tune ...func(*options)) *harness {
	t.Helper()
	h := &harness{t: t, log: NewLog(), lines: &logLines{}}
	cfg.Listen = netip.MustParseAddrPort("127.0.0.1:0")
	cfg.Log = h.log
	cfg.Logf = h.lines.logf
	o := options{
		port:      port,
		applyWait: ApplyWait,
		timeout:   QueryTimeout,
		bind: func(side Side, _ Upstreams, _ uintptr) error {
			h.mu.Lock()
			h.binds = append(h.binds, side)
			h.mu.Unlock()
			return nil
		},
	}
	for _, f := range tune {
		f(&o)
	}
	p, err := start(cfg, o)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(p.Close)
	h.p, h.addr = p, p.Addr()
	return h
}

func (h *harness) bound() []Side {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.binds)
}

func query(id uint16, name string, qtype dnsmessage.Type) []byte {
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name + "."), Type: qtype, Class: dnsmessage.ClassINET}},
	}
	b, _ := msg.Pack()
	return b
}

func (h *harness) askUDP(raw []byte, wait time.Duration) (dnsmessage.Message, error) {
	h.t.Helper()
	c, err := net.Dial("udp4", h.addr.String())
	if err != nil {
		h.t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(wait))
	if _, err := c.Write(raw); err != nil {
		h.t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		return dnsmessage.Message{}, err
	}
	var m dnsmessage.Message
	return m, m.Unpack(buf[:n])
}

func (h *harness) mustUDP(raw []byte) dnsmessage.Message {
	h.t.Helper()
	m, err := h.askUDP(raw, 5*time.Second)
	if err != nil {
		h.t.Fatalf("ответ прокси: %v", err)
	}
	return m
}

func addrsOf(m dnsmessage.Message) []netip.Addr {
	var out []netip.Addr
	for _, a := range m.Answers {
		switch b := a.Body.(type) {
		case *dnsmessage.AResource:
			out = append(out, netip.AddrFrom4(b.A))
		case *dnsmessage.AAAAResource:
			out = append(out, netip.AddrFrom16(b.AAAA))
		}
	}
	return out
}

func lo(ip string) []netip.Addr { return []netip.Addr{netip.MustParseAddr(ip)} }

func bypassConfig(direct, tunnel string, sink Sink) Config {
	return Config{
		Domains:   []string{"example.com"},
		Upstreams: Upstreams{Direct: lo(direct), Tunnel: lo(tunnel)},
		Sink:      sink,
	}
}

func TestProxyPicksServerBySide(t *testing.T) {
	a := startUpstream(t, "127.0.0.2", 0, answerAll(reply{addrs: []netip.Addr{addrA}}))
	b := startUpstream(t, "127.0.0.3", a.port(), answerAll(reply{addrs: []netip.Addr{addrA}}))
	h := startHarness(t, bypassConfig("127.0.0.2", "127.0.0.3", &fakeSink{}), a.port())

	h.mustUDP(query(1, "www.example.com", dnsmessage.TypeA))
	h.mustUDP(query(2, "other.net", dnsmessage.TypeA))

	if got := a.names(); !slices.Equal(got, []string{"udp:www.example.com"}) {
		t.Errorf("физический DNS получил %v", got)
	}
	if got := b.names(); !slices.Equal(got, []string{"udp:other.net"}) {
		t.Errorf("DNS туннеля получил %v", got)
	}
	if got := h.bound(); !slices.Equal(got, []Side{SideDirect, SideTunnel}) {
		t.Errorf("привязки %v", got)
	}
}

func TestProxyWaitsForApply(t *testing.T) {
	a := startUpstream(t, "127.0.0.2", 0, answerAll(reply{addrs: []netip.Addr{addrA, addrAAAA, addrZero, addrFake}}))
	sink := &fakeSink{gate: make(chan struct{})}
	h := startHarness(t, bypassConfig("127.0.0.2", "127.0.0.3", sink), a.port())

	got := make(chan dnsmessage.Message, 1)
	go func() { got <- h.mustUDP(query(7, "www.example.com", dnsmessage.TypeA)) }()
	deadline := time.Now().Add(2 * time.Second)
	for len(sink.applied()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case <-got:
		t.Fatal("ответ ушёл раньше, чем Apply вернулся")
	case <-time.After(100 * time.Millisecond):
	}
	close(sink.gate)
	m := <-got
	if len(addrsOf(m)) != 4 {
		t.Errorf("программа получила не весь ответ сервера: %v", addrsOf(m))
	}
	if calls := sink.applied(); len(calls) != 1 || !slices.Equal(calls[0], []netip.Addr{addrA, addrAAAA}) {
		t.Errorf("Apply получил %v", calls)
	}
	entries, _ := h.log.Since(0)
	if len(entries) != 1 || entries[0].Late {
		t.Errorf("журнал %+v", entries)
	}
}

func TestProxyLateAfterApplyWait(t *testing.T) {
	a := startUpstream(t, "127.0.0.2", 0, answerAll(reply{addrs: []netip.Addr{addrA}}))
	sink := &fakeSink{gate: make(chan struct{})}
	defer close(sink.gate)
	h := startHarness(t, bypassConfig("127.0.0.2", "127.0.0.3", sink), a.port(),
		func(o *options) { o.applyWait = 50 * time.Millisecond })

	h.mustUDP(query(8, "secret.example.com", dnsmessage.TypeA))

	entries, _ := h.log.Since(0)
	if len(entries) != 1 || !entries[0].Late {
		t.Fatalf("журнал %+v", entries)
	}
	lines := h.lines.all()
	if len(lines) != 1 {
		t.Fatalf("строк журнала службы %d: %v", len(lines), lines)
	}
	if strings.Contains(lines[0], "secret") {
		t.Errorf("в журнале службы имя запроса: %q", lines[0])
	}
}

func TestProxyApplyErrorIsLate(t *testing.T) {
	a := startUpstream(t, "127.0.0.2", 0, answerAll(reply{addrs: []netip.Addr{addrA}}))
	sink := &fakeSink{err: errors.New("отказ")}
	h := startHarness(t, bypassConfig("127.0.0.2", "127.0.0.3", sink), a.port())

	h.mustUDP(query(9, "example.com", dnsmessage.TypeA))

	if entries, _ := h.log.Since(0); len(entries) != 1 || !entries[0].Late {
		t.Fatalf("журнал %+v", entries)
	}
}

func TestProxyNoSinkForUnlisted(t *testing.T) {
	b := startUpstream(t, "127.0.0.3", 0, answerAll(reply{addrs: []netip.Addr{addrA}}))
	sink := &fakeSink{}
	h := startHarness(t, bypassConfig("127.0.0.2", "127.0.0.3", sink), b.port())

	h.mustUDP(query(3, "iana.org", dnsmessage.TypeA))

	if calls := sink.applied(); len(calls) != 0 {
		t.Errorf("Apply для имени без правила: %v", calls)
	}
}

func TestProxyTCP(t *testing.T) {
	a := startUpstream(t, "127.0.0.2", 0, answerAll(reply{addrs: []netip.Addr{addrA}}))
	h := startHarness(t, bypassConfig("127.0.0.2", "127.0.0.3", &fakeSink{}), a.port())

	c, err := net.Dial("tcp4", h.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	for i, name := range []string{"example.com", "www.example.com"} {
		if err := writeFrame(c, query(uint16(20+i), name, dnsmessage.TypeA)); err != nil {
			t.Fatal(err)
		}
		raw, err := readFrame(c)
		if err != nil {
			t.Fatalf("ответ %d: %v", i, err)
		}
		var m dnsmessage.Message
		if err := m.Unpack(raw); err != nil || m.ID != uint16(20+i) || len(addrsOf(m)) != 1 {
			t.Fatalf("ответ %d: %+v, %v", i, m.Header, err)
		}
	}
	if got := a.names(); !slices.Equal(got, []string{"tcp:example.com", "tcp:www.example.com"}) {
		t.Errorf("сервер получил %v", got)
	}
}

func TestProxyTruncated(t *testing.T) {
	a := startUpstream(t, "127.0.0.2", 0, answerAll(reply{truncate: true}))
	h := startHarness(t, bypassConfig("127.0.0.2", "127.0.0.3", &fakeSink{}), a.port())

	m := h.mustUDP(query(4, "example.com", dnsmessage.TypeA))
	if !m.Truncated || m.ID != 4 {
		t.Fatalf("заголовок %+v", m.Header)
	}
}

func TestProxyFormErr(t *testing.T) {
	h := startHarness(t, bypassConfig("127.0.0.2", "127.0.0.3", &fakeSink{}), 1)
	two := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 11},
		Questions: []dnsmessage.Question{
			{Name: dnsmessage.MustNewName("a.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			{Name: dnsmessage.MustNewName("b.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		},
	}
	none := dnsmessage.Message{Header: dnsmessage.Header{ID: 12}}
	for _, msg := range []dnsmessage.Message{two, none} {
		raw, _ := msg.Pack()
		m := h.mustUDP(raw)
		if m.RCode != dnsmessage.RCodeFormatError || m.ID != msg.ID || !m.Response {
			t.Errorf("запрос %d: %+v", msg.ID, m.Header)
		}
	}
}

func TestProxyServFail(t *testing.T) {
	silent := answerAll(reply{silent: true})
	a := startUpstream(t, "127.0.0.2", 0, silent)
	b := startUpstream(t, "127.0.0.4", a.port(), silent)
	cfg := bypassConfig("127.0.0.2", "127.0.0.3", &fakeSink{})
	cfg.Upstreams.Direct = append(lo("127.0.0.2"), lo("127.0.0.4")...)
	h := startHarness(t, cfg, a.port(), func(o *options) { o.timeout = 200 * time.Millisecond })

	start := time.Now()
	m := h.mustUDP(query(5, "example.com", dnsmessage.TypeA))
	if m.RCode != dnsmessage.RCodeServerFailure || m.ID != 5 {
		t.Fatalf("заголовок %+v", m.Header)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("SERVFAIL через %v", took)
	}
	if a.queries.Load() != 1 || b.queries.Load() != 1 {
		t.Errorf("опрошено %d и %d", a.queries.Load(), b.queries.Load())
	}
}

func TestProxyNXDomainStops(t *testing.T) {
	a := startUpstream(t, "127.0.0.2", 0, answerAll(reply{rcode: dnsmessage.RCodeNameError}))
	b := startUpstream(t, "127.0.0.4", a.port(), answerAll(reply{addrs: []netip.Addr{addrA}}))
	cfg := bypassConfig("127.0.0.2", "127.0.0.3", &fakeSink{})
	cfg.Upstreams.Direct = append(lo("127.0.0.2"), lo("127.0.0.4")...)
	h := startHarness(t, cfg, a.port())

	m := h.mustUDP(query(6, "missing.example.com", dnsmessage.TypeA))
	if m.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("заголовок %+v", m.Header)
	}
	if b.queries.Load() != 0 {
		t.Errorf("второй сервер опрошен %d раз", b.queries.Load())
	}
}

func TestProxyOtherTypesForwarded(t *testing.T) {
	a := startUpstream(t, "127.0.0.2", 0, answerAll(reply{}))
	sink := &fakeSink{}
	h := startHarness(t, bypassConfig("127.0.0.2", "127.0.0.3", sink), a.port())

	m := h.mustUDP(query(13, "www.example.com", dnsmessage.TypeHTTPS))
	if m.RCode != dnsmessage.RCodeSuccess || a.queries.Load() != 1 {
		t.Fatalf("заголовок %+v, запросов %d", m.Header, a.queries.Load())
	}
	if calls := sink.applied(); len(calls) != 0 {
		t.Errorf("Apply без адресов: %v", calls)
	}
	if entries, _ := h.log.Since(0); len(entries) != 1 || entries[0].Type != "HTTPS" {
		t.Errorf("журнал %+v", entries)
	}
}

func TestProxyLogEntry(t *testing.T) {
	a := startUpstream(t, "127.0.0.2", 0, answerAll(reply{addrs: []netip.Addr{addrA}, delay: 20 * time.Millisecond}))
	h := startHarness(t, bypassConfig("127.0.0.2", "127.0.0.3", &fakeSink{}), a.port())

	h.mustUDP(query(14, "www.example.com", dnsmessage.TypeA))

	entries, _ := h.log.Since(0)
	if len(entries) != 1 {
		t.Fatalf("записей %d", len(entries))
	}
	e := entries[0]
	want := model.QueryEntry{Seq: 1, Name: "www.example.com", Type: "A", Addrs: []netip.Addr{addrA},
		Upstream: "direct", Route: "direct", Rule: "example.com", RCode: "NOERROR"}
	if e.Name != want.Name || e.Type != want.Type || !slices.Equal(e.Addrs, want.Addrs) || e.Upstream != want.Upstream ||
		e.Route != want.Route || e.Rule != want.Rule || e.RCode != want.RCode || e.Took < 15*time.Millisecond || e.Time.IsZero() || e.Late {
		t.Fatalf("запись %+v", e)
	}
}

func TestProxySetUpstreams(t *testing.T) {
	a := startUpstream(t, "127.0.0.2", 0, answerAll(reply{addrs: []netip.Addr{addrA}}))
	c := startUpstream(t, "127.0.0.5", a.port(), answerAll(reply{addrs: []netip.Addr{addrA}}))
	h := startHarness(t, bypassConfig("127.0.0.2", "127.0.0.3", &fakeSink{}), a.port())

	h.p.SetUpstreams(Upstreams{Direct: lo("127.0.0.5"), Tunnel: lo("127.0.0.3")})
	h.mustUDP(query(15, "example.com", dnsmessage.TypeA))

	if a.queries.Load() != 0 || c.queries.Load() != 1 {
		t.Errorf("старый сервер %d, новый %d", a.queries.Load(), c.queries.Load())
	}
}

func TestProxyListenBusy(t *testing.T) {
	h := startHarness(t, bypassConfig("127.0.0.2", "127.0.0.3", &fakeSink{}), 1)
	cfg := bypassConfig("127.0.0.2", "127.0.0.3", &fakeSink{})
	cfg.Listen = h.addr
	if p, err := Start(cfg); err == nil {
		p.Close()
		t.Fatal("второй прокси занял тот же адрес")
	}
}

func TestProxyCloseDuringQuery(t *testing.T) {
	a := startUpstream(t, "127.0.0.2", 0, answerAll(reply{addrs: []netip.Addr{addrA}}))
	sink := &fakeSink{gate: make(chan struct{})}
	defer close(sink.gate)
	h := startHarness(t, bypassConfig("127.0.0.2", "127.0.0.3", sink), a.port())

	go func() { _, _ = h.askUDP(query(16, "example.com", dnsmessage.TypeA), 3*time.Second) }()
	deadline := time.Now().Add(2 * time.Second)
	for len(sink.applied()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	done := make(chan struct{})
	go func() { h.p.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(ApplyWait):
		t.Fatal("Close ждал Apply")
	}
}
