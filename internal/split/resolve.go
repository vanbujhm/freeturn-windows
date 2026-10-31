package split

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"time"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

const (
	dnsPort = 53
	// resolveTimeout - срок на один домен по всем серверам вместе.
	resolveTimeout = 3 * time.Second
)

// fakeIPRange - подставные адреса Mihomo. Они живут только внутри его TUN-адаптера, поэтому
// маршрут обхода на такой адрес никуда не ведёт.
var fakeIPRange = netip.MustParsePrefix("198.18.0.0/15")

// errNotProtected: сокет нельзя вывести из туннеля, запрос ушёл бы через него.
var errNotProtected = errors.New("split: сокет DNS не защищён")

// DNSResolver разрешает домены через DNS-серверы физического интерфейса по защищённым
// сокетам. После создания не меняется, поэтому Resolve можно вызывать одновременно.
type DNSResolver struct {
	protect func(fd int) bool
	port    uint16 // тесты поднимают свой сервер на свободном порту
	timeout time.Duration
}

// NewResolver создаёт разрешитель. protect выводит сокет из туннеля, отказ срывает запрос.
func NewResolver(protect func(fd int) bool) *DNSResolver {
	return &DNSResolver{protect: protect, port: dnsPort, timeout: resolveTimeout}
}

// Resolve возвращает адреса A и AAAA, кроме тех, что не годятся для маршрута, см. unroutable.
// Домен, который не разрешился, просто не попадает в результат. Без DNS-серверов у интерфейса
// разрешать нечем.
func (r *DNSResolver) Resolve(ctx context.Context, domains []string, ph model.Physical) []netip.Addr {
	if len(ph.DNS) == 0 {
		return nil
	}
	var out []netip.Addr
	for _, domain := range domains {
		out = append(out, r.lookup(ctx, domain, ph.DNS)...)
	}
	return out
}

// lookup опрашивает серверы по очереди, каждому достаётся равная доля срока домена. Встроенный
// перебор Go здесь не годится: срок попытки у него больше всего срока домена, и до второго
// сервера дело бы не дошло. NXDOMAIN окончателен, другие серверы не спрашиваем.
func (r *DNSResolver) lookup(ctx context.Context, domain string, servers []netip.Addr) []netip.Addr {
	share := r.timeout / time.Duration(len(servers))
	// Точка в конце: имя полное, системные суффиксы поиска к нему не добавляются.
	name := domain + "."
	for _, server := range servers {
		try, done := context.WithTimeout(ctx, share)
		addrs, err := r.client(server).LookupNetIP(try, "ip", name)
		done()
		if err == nil {
			return routable(addrs)
		}
		var dnsErr *net.DNSError
		if ctx.Err() != nil || (errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
			return nil
		}
	}
	return nil
}

// client собирает разрешитель, который ходит только на server. Адрес, который выбрал
// разрешитель Go, отбрасывается: это системный DNS, а он может указывать на туннель.
func (r *DNSResolver) client(server netip.Addr) *net.Resolver {
	address := netip.AddrPortFrom(server, r.port).String()
	dialer := net.Dialer{Control: r.protectSocket}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
	}
}

// protectSocket выводит сокет из туннеля до того, как он отправит хоть один пакет.
func (r *DNSResolver) protectSocket(_, _ string, c syscall.RawConn) error {
	ok := false
	if err := c.Control(func(fd uintptr) { ok = r.protect(int(fd)) }); err != nil {
		return err
	}
	if !ok {
		return errNotProtected
	}
	return nil
}

func routable(addrs []netip.Addr) []netip.Addr {
	for i, a := range addrs {
		addrs[i] = a.Unmap()
	}
	return slices.DeleteFunc(addrs, unroutable)
}

// unroutable: маршрут обхода через шлюз на такой адрес никуда не ведёт. DNS с блокировкой
// рекламы отвечает 0.0.0.0, а Mihomo подставными адресами.
func unroutable(a netip.Addr) bool {
	return fakeIPRange.Contains(a) || a.IsUnspecified() || a.IsLoopback() ||
		a.IsMulticast() || a.IsLinkLocalUnicast()
}
