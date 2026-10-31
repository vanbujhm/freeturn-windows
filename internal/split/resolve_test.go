package split

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

const (
	knownName = "bypass.example.test"
	otherName = "second.example.test"
)

var (
	realV4 = netip.MustParseAddr("203.0.113.7")
	realV6 = netip.MustParseAddr("2001:db8::7")
	fakeV4 = netip.MustParseAddr("198.18.0.5")
)

// dnsServer - локальный UDP DNS-сервер. Неизвестное имя получает NXDOMAIN, а сервер без
// ответов (zone == nil) молчит, как недоступный.
type dnsServer struct {
	conn    net.PacketConn
	zone    map[string][]netip.Addr
	queries atomic.Int32
}

func startDNS(t *testing.T, addr string, zone map[string][]netip.Addr) *dnsServer {
	t.Helper()
	conn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		t.Fatalf("сервер DNS: %v", err)
	}
	s := &dnsServer{conn: conn, zone: zone}
	t.Cleanup(func() { _ = conn.Close() })
	go s.serve()
	return s
}

func (s *dnsServer) port() uint16 {
	return uint16(s.conn.LocalAddr().(*net.UDPAddr).Port)
}

func (s *dnsServer) serve() {
	buf := make([]byte, 1500)
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		s.queries.Add(1)
		if s.zone == nil {
			continue
		}
		var req dnsmessage.Message
		if err := req.Unpack(buf[:n]); err != nil || len(req.Questions) != 1 {
			continue
		}
		reply, err := s.reply(req)
		if err != nil {
			continue
		}
		_, _ = s.conn.WriteTo(reply, from)
	}
}

func (s *dnsServer) reply(req dnsmessage.Message) ([]byte, error) {
	q := req.Questions[0]
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: req.ID, Response: true, RecursionDesired: true, RecursionAvailable: true,
		},
		Questions: req.Questions,
	}
	addrs, known := s.zone[q.Name.String()]
	if !known {
		msg.RCode = dnsmessage.RCodeNameError
	}
	head := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class, TTL: 60}
	for _, a := range addrs {
		switch {
		case a.Is4() && q.Type == dnsmessage.TypeA:
			msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: head, Body: &dnsmessage.AResource{A: a.As4()}})
		case a.Is6() && q.Type == dnsmessage.TypeAAAA:
			msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: head, Body: &dnsmessage.AAAAResource{AAAA: a.As16()}})
		}
	}
	return msg.Pack()
}

// allowAll - protect, который считает вызовы и всегда разрешает.
func allowAll() (func(int) bool, *atomic.Int32) {
	var n atomic.Int32
	return func(int) bool {
		n.Add(1)
		return true
	}, &n
}

func localDNS() model.Physical {
	return model.Physical{DNS: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
}

func newLocalResolver(srv *dnsServer, protect func(int) bool) *DNSResolver {
	r := NewResolver(protect)
	r.port = srv.port()
	return r
}

func zone(name string, addrs ...netip.Addr) map[string][]netip.Addr {
	return map[string][]netip.Addr{name + ".": addrs}
}

func TestResolverUsesPhysicalDNS(t *testing.T) {
	srv := startDNS(t, "127.0.0.1:0", zone(knownName, realV4))
	protect, calls := allowAll()
	r := newLocalResolver(srv, protect)

	got := r.Resolve(context.Background(), []string{knownName}, localDNS())

	if !slices.Equal(got, []netip.Addr{realV4}) {
		t.Fatalf("ответ %v", got)
	}
	if calls.Load() == 0 {
		t.Error("protect не вызван")
	}
	if srv.queries.Load() == 0 {
		t.Error("запрос не дошёл до сервера физического интерфейса")
	}
}

func TestResolverReturnsBothFamilies(t *testing.T) {
	srv := startDNS(t, "127.0.0.1:0", zone(knownName, realV4, realV6))
	protect, _ := allowAll()
	r := newLocalResolver(srv, protect)

	got := r.Resolve(context.Background(), []string{knownName}, localDNS())

	if !slices.Contains(got, realV4) || !slices.Contains(got, realV6) || len(got) != 2 {
		t.Fatalf("ответ %v", got)
	}
}

func TestResolverSeveralDomains(t *testing.T) {
	addrs := zone(knownName, realV4)
	addrs[otherName+"."] = []netip.Addr{realV4, realV6}
	srv := startDNS(t, "127.0.0.1:0", addrs)
	protect, _ := allowAll()
	r := newLocalResolver(srv, protect)

	got := r.Resolve(context.Background(), []string{knownName, otherName}, localDNS())

	if !slices.Contains(got, realV4) || !slices.Contains(got, realV6) {
		t.Fatalf("ответ %v", got)
	}
}

func TestResolverUnknownDomain(t *testing.T) {
	srv := startDNS(t, "127.0.0.1:0", zone(knownName, realV4))
	protect, _ := allowAll()
	r := newLocalResolver(srv, protect)

	if got := r.Resolve(context.Background(), []string{"missing.example.test"}, localDNS()); len(got) != 0 {
		t.Fatalf("ответ %v", got)
	}
}

// NXDOMAIN окончателен: другой сервер той же сети ответит так же, а ждать его незачем.
func TestResolverUnknownDomainStopsAtFirstServer(t *testing.T) {
	first := startDNS(t, "127.0.0.1:0", zone(knownName, realV4))
	second := startDNS(t, "127.0.0.2:"+portString(first), zone(knownName, realV4))
	protect, _ := allowAll()
	r := newLocalResolver(first, protect)
	ph := model.Physical{DNS: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")}}

	r.Resolve(context.Background(), []string{"missing.example.test"}, ph)

	if second.queries.Load() != 0 {
		t.Errorf("запросов ко второму серверу: %d", second.queries.Load())
	}
}

// Mihomo отвечает подставными адресами из 198.18.0.0/15. Такой адрес не должен стать
// маршрутом обхода: он существует только внутри его TUN-адаптера.
func TestResolverDropsFakeIP(t *testing.T) {
	cases := map[string][]netip.Addr{
		"вперемешку":     {fakeV4, realV4},
		"край диапазона": {netip.MustParseAddr("198.19.255.255"), realV4},
	}
	for name, answer := range cases {
		t.Run(name, func(t *testing.T) {
			srv := startDNS(t, "127.0.0.1:0", zone(knownName, answer...))
			protect, _ := allowAll()
			r := newLocalResolver(srv, protect)

			got := r.Resolve(context.Background(), []string{knownName}, localDNS())

			if !slices.Equal(got, []netip.Addr{realV4}) {
				t.Fatalf("ответ %v", got)
			}
		})
	}
}

func TestResolverOnlyFakeIPIsEmpty(t *testing.T) {
	srv := startDNS(t, "127.0.0.1:0", zone(knownName, fakeV4))
	protect, _ := allowAll()
	r := newLocalResolver(srv, protect)

	if got := r.Resolve(context.Background(), []string{knownName}, localDNS()); len(got) != 0 {
		t.Fatalf("ответ %v", got)
	}
}

// Адрес рядом с диапазоном настоящий.
func TestResolverKeepsNeighboursOfFakeRange(t *testing.T) {
	neighbours := []netip.Addr{netip.MustParseAddr("198.17.255.255"), netip.MustParseAddr("198.20.0.0")}
	srv := startDNS(t, "127.0.0.1:0", zone(knownName, neighbours...))
	protect, _ := allowAll()
	r := newLocalResolver(srv, protect)

	got := r.Resolve(context.Background(), []string{knownName}, localDNS())

	if !slices.Contains(got, neighbours[0]) || !slices.Contains(got, neighbours[1]) {
		t.Fatalf("ответ %v", got)
	}
}

func TestResolverProtectRefused(t *testing.T) {
	srv := startDNS(t, "127.0.0.1:0", zone(knownName, realV4))
	r := newLocalResolver(srv, func(int) bool { return false })

	if got := r.Resolve(context.Background(), []string{knownName}, localDNS()); len(got) != 0 {
		t.Fatalf("ответ %v", got)
	}
	// Сокет без защиты ушёл бы в туннель, поэтому запроса быть не должно.
	if srv.queries.Load() != 0 {
		t.Errorf("запросов к серверу: %d", srv.queries.Load())
	}
}

func TestResolverNoServers(t *testing.T) {
	protect, calls := allowAll()
	r := NewResolver(protect)

	if got := r.Resolve(context.Background(), []string{knownName}, model.Physical{}); len(got) != 0 {
		t.Fatalf("ответ %v", got)
	}
	if calls.Load() != 0 {
		t.Error("без серверов сокет не нужен")
	}
}

func TestResolverSecondServer(t *testing.T) {
	silent := startDNS(t, "127.0.0.2:0", nil)
	srv := startDNS(t, "127.0.0.1:"+portString(silent), zone(knownName, realV4))
	protect, _ := allowAll()
	r := newLocalResolver(srv, protect)
	r.timeout = 200 * time.Millisecond
	ph := model.Physical{DNS: []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")}}

	got := r.Resolve(context.Background(), []string{knownName}, ph)

	if !slices.Equal(got, []netip.Addr{realV4}) {
		t.Fatalf("ответ %v", got)
	}
	if silent.queries.Load() == 0 {
		t.Error("первый сервер не опрошен")
	}
}

func portString(s *dnsServer) string {
	_, port, _ := net.SplitHostPort(s.conn.LocalAddr().String())
	return port
}

func TestResolverTimeout(t *testing.T) {
	silent := startDNS(t, "127.0.0.1:0", nil)
	protect, _ := allowAll()
	r := newLocalResolver(silent, protect)
	r.timeout = 100 * time.Millisecond

	start := time.Now()
	got := r.Resolve(context.Background(), []string{knownName}, localDNS())

	if len(got) != 0 {
		t.Fatalf("ответ %v", got)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("ждали %s", took)
	}
}

func TestResolverDefaultTimeout(t *testing.T) {
	if got := NewResolver(func(int) bool { return true }).timeout; got != 3*time.Second {
		t.Errorf("таймаут на домен %s", got)
	}
}

func TestResolverCancel(t *testing.T) {
	silent := startDNS(t, "127.0.0.1:0", nil)
	protect, _ := allowAll()
	r := newLocalResolver(silent, protect)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan []netip.Addr, 1)
	go func() { done <- r.Resolve(ctx, []string{knownName}, localDNS()) }()
	for silent.queries.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()

	select {
	case got := <-done:
		if len(got) != 0 {
			t.Fatalf("ответ %v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("Resolve не заметил отмену")
	}
}

// Task 8 вызывает Resolve на каждый домен из отдельной горутины.
func TestResolverConcurrent(t *testing.T) {
	srv := startDNS(t, "127.0.0.1:0", zone(knownName, realV4))
	protect, _ := allowAll()
	r := newLocalResolver(srv, protect)

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			got := r.Resolve(context.Background(), []string{knownName}, localDNS())
			if !slices.Equal(got, []netip.Addr{realV4}) {
				t.Errorf("ответ %v", got)
			}
		})
	}
	wg.Wait()
}
