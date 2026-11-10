package engine

import (
	"context"
	"errors"
	"net/netip"
	"slices"

	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/split"
)

// ErrNotConnected: проверять маршрут не у чего, туннель не подключён. Текст ошибки канал
// передаёт окну как код.
var ErrNotConnected = errors.New(model.ProbeNotConnected)

// Probe узнаёт, через какой интерфейс Windows отправит трафик адреса или домена сейчас.
// Домен разрешается на той стороне, куда пойдёт его трафик (см. viaTunnel): иначе имя, которое
// человек собирается открыть через VPN, ушло бы провайдеру открытым текстом. Сеть не
// меняется, журнал не пишется.
func (e *Engine) Probe(ctx context.Context, value string) ([]model.ProbeHop, error) {
	in, err := split.Classify(value)
	if err != nil {
		return nil, err
	}
	if in.Kind == model.RuleSubnet {
		return nil, split.ErrSubnetInput
	}
	e.mu.Lock()
	s := e.sess
	ok := s != nil && s.established
	var luid uint64
	var ph model.Physical
	var allowed []netip.Prefix
	var dns []netip.Addr
	tunnelOnly, tunnelSide := false, false
	if ok {
		luid, ph = s.luid, s.ph
		allowed = s.cfg.AllowedPrefixes()
		dns = slices.Clone(s.cfg.DNS)
		tunnelOnly = s.req.Options.TunnelOnly()
		tunnelSide = viaTunnel(s.req.Options, s.rules, in.Value)
	}
	e.mu.Unlock()
	if !ok {
		return nil, ErrNotConnected
	}

	var addrs []netip.Addr
	switch {
	case in.Kind != model.RuleDomain:
		addrs = []netip.Addr{netip.MustParseAddr(in.Value)}
	case tunnelSide && len(dns) > 0:
		if e.d.TunnelResolver != nil {
			addrs = e.d.TunnelResolver.ResolveTunnel(ctx, in.Value, luid, dns)
		}
	default:
		// Имя идёт мимо туннеля, или в конфиге нет DNS и система и так спрашивает физический.
		addrs = e.d.Resolver.Resolve(ctx, []string{in.Value}, ph)
	}
	hops := make([]model.ProbeHop, 0, len(addrs))
	for _, a := range addrs {
		hop := model.ProbeHop{Addr: a, Outside: !tunnelOnly && !covered(allowed, a)}
		if got, onLink, err := e.d.Net.BestRoute(a); err == nil {
			switch got {
			case luid:
				hop.Via = model.ViaTunnel
			case ph.LUID:
				hop.Via = model.ViaDirect
				hop.Local = onLink
			default:
				hop.Via = model.ViaOther
			}
		}
		hops = append(hops, hop)
	}
	return hops, nil
}

// covered сообщает, что адрес попадает в один из префиксов.
func covered(ps []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// viaTunnel сообщает, что трафик имени идёт через туннель: раздельное туннелирование
// выключено, или имя не в списке обхода, или в режиме «только список» оно в списке.
func viaTunnel(o model.Options, rules split.Compiled, name string) bool {
	if o.SplitOff {
		return true
	}
	return slices.Contains(rules.Domains, name) == o.TunnelOnly()
}
