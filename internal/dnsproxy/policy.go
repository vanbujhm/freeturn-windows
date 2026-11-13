package dnsproxy

import (
	"context"
	"net/netip"

	"github.com/vanbujhm/freeturn-windows/internal/split"
)

// Side - сторона: туннель или физическая сеть.
type Side string

const (
	SideTunnel Side = "tunnel"
	SideDirect Side = "direct"
)

// Sink применяет адреса имени под правилом до того, как ответ уйдёт программе.
type Sink interface {
	// Apply ставит разрешения и маршруты для адресов имени под правилом. Возвращается, когда
	// всё применено или ctx истёк.
	Apply(ctx context.Context, addrs []netip.Addr) error
}

// Upstreams - DNS-серверы обеих сторон и интерфейсы, к которым привязываются их сокеты.
type Upstreams struct {
	Direct           []netip.Addr // DNS физического интерфейса
	Tunnel           []netip.Addr // DNS конфига
	Direct4, Direct6 uint32       // индексы физического интерфейса для IP_UNICAST_IF
	Tunnel4, Tunnel6 uint32       // индексы адаптера туннеля
}

// Config - параметры прокси сеанса.
type Config struct {
	Listen     netip.AddrPort
	Domains    []string // split.Compiled.Domains сеанса
	TunnelOnly bool
	SplitOff   bool
	Upstreams  Upstreams
	Sink       Sink
	Log        *Log
	Logf       func(level, msg string)
}

// Choice - куда идёт имя: правило, сторона трафика его адресов и сторона DNS-сервера.
type Choice struct {
	Rule     string
	Route    Side
	Upstream Side
}

// Choose выбирает стороны для имени по режиму и правилам. Имя спрашивается там же, куда пойдёт
// его трафик. Без DNS в конфиге сторона туннеля спрашивает DNS физического интерфейса: система
// без прокси делала бы так же.
func Choose(c Config, name string) Choice {
	var ch Choice
	if c.SplitOff {
		ch.Route = SideTunnel
	} else {
		rule, listed := split.MatchDomain(c.Domains, name)
		ch.Rule = rule
		if listed == c.TunnelOnly {
			ch.Route = SideTunnel
		} else {
			ch.Route = SideDirect
		}
	}
	ch.Upstream = ch.Route
	if ch.Upstream == SideTunnel && len(c.Upstreams.Tunnel) == 0 {
		ch.Upstream = SideDirect
	}
	return ch
}
