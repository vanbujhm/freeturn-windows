package engine

import (
	"context"
	"errors"
	"net/netip"

	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/split"
)

// ErrNotConnected: проверять маршрут не у чего, туннель не подключён. Текст совпадает с
// кодом, который канал передаёт окну.
var ErrNotConnected = errors.New("not_connected")

// Probe узнаёт, через какой интерфейс Windows отправит трафик адреса или домена сейчас.
// Домен разрешается тем же разрешителем, что и правила. Сеть не меняется, журнал не пишется.
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
	tunnelOnly := false
	if ok {
		luid, ph = s.luid, s.ph
		allowed = s.cfg.AllowedPrefixes()
		tunnelOnly = s.req.Options.TunnelOnly()
	}
	e.mu.Unlock()
	if !ok {
		return nil, ErrNotConnected
	}

	var addrs []netip.Addr
	if in.Kind == model.RuleDomain {
		addrs = e.d.Resolver.Resolve(ctx, []string{in.Value}, ph)
	} else {
		addrs = []netip.Addr{netip.MustParseAddr(in.Value)}
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
