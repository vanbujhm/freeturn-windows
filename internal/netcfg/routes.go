package netcfg

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// Полные маршруты заменяются парами /1: пара точнее любого /0 другого адаптера
// (например, TUN Mihomo), поэтому FreeTurn выигрывает при равных метриках.
var (
	defaultV4 = netip.MustParsePrefix("0.0.0.0/0")
	defaultV6 = netip.MustParsePrefix("::/0")
	halvesV4  = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
	halvesV6  = []netip.Prefix{netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")}
)

const minIPv6MTU = 1280

// planRoutes строит маршруты туннеля из AllowedIPs. 0.0.0.0/0 и ::/0 раскрываются в пары /1,
// остальные префиксы проходят как есть (с обнулёнными битами хоста), дубли убираются.
// Если разрешён весь IPv4, а IPv6-маршрутов в конфиге нет, добавляется пара ::/1 и 8000::/1:
// трафик IPv6 уходит на адаптер без IPv6-адреса и отбрасывается, а не течёт мимо туннеля.
func planRoutes(allowed []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	add := func(p netip.Prefix) {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	fullV4, anyV6 := false, false
	for _, p := range allowed {
		if !p.IsValid() {
			continue
		}
		p = p.Masked()
		switch {
		case p == defaultV4:
			fullV4 = true
			for _, h := range halvesV4 {
				add(h)
			}
		case p == defaultV6:
			anyV6 = true
			for _, h := range halvesV6 {
				add(h)
			}
		default:
			if p.Addr().Is6() {
				anyV6 = true
			}
			add(p)
		}
	}
	if fullV4 && !anyV6 {
		for _, h := range halvesV6 {
			add(h)
		}
	}
	return out
}

// ipv6SinkOnly: IPv6-маршруты плана состоят только из заглушки, добавленной planRoutes
// (полный IPv4 без единого IPv6-префикса в конфиге).
func ipv6SinkOnly(allowed []netip.Prefix) bool {
	full4 := false
	for _, p := range allowed {
		if !p.IsValid() {
			continue
		}
		if p.Addr().Is6() {
			return false
		}
		if p.Masked() == defaultV4 {
			full4 = true
		}
	}
	return full4
}

// ConfigureInterface ставит адреса адаптера, метрику 0 (без автоматической) и MTU.
func ConfigureInterface(luid uint64, addrs []netip.Prefix, mtu int) error {
	l := winipcfg.LUID(luid)
	if err := l.SetIPAddressesForFamily(windows.AF_INET, addrs); err != nil {
		return fmt.Errorf("адрес IPv4: %w", err)
	}
	if err := l.SetIPAddressesForFamily(windows.AF_INET6, addrs); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
		return fmt.Errorf("адрес IPv6: %w", err)
	}
	if err := setInterface(l, windows.AF_INET, mtu); err != nil {
		return fmt.Errorf("параметры IPv4: %w", err)
	}
	// На адаптере без стека IPv6 параметров нет, это не ошибка.
	if err := setInterface(l, windows.AF_INET6, max(mtu, minIPv6MTU)); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
		return fmt.Errorf("параметры IPv6: %w", err)
	}
	return nil
}

func setInterface(l winipcfg.LUID, family winipcfg.AddressFamily, mtu int) error {
	row, err := l.IPInterface(family)
	if err != nil {
		return err
	}
	row.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	row.DadTransmits = 0
	row.ManagedAddressConfigurationSupported = false
	row.OtherStatefulConfigurationSupported = false
	row.NLMTU = uint32(mtu)
	row.UseAutomaticMetric = false
	row.Metric = 0
	return row.Set()
}

// ApplyTunnelRoutes ставит маршруты туннеля из AllowedIPs и DNS адаптера (шаг 5 подключения).
// Следующий узел маршрутов нулевой: трафик уходит прямо на адаптер.
func ApplyTunnelRoutes(luid uint64, allowed []netip.Prefix, dns []netip.Addr) error {
	l := winipcfg.LUID(luid)
	var routes4, routes6 []*winipcfg.RouteData
	for _, p := range planRoutes(allowed) {
		if p.Addr().Is4() {
			routes4 = append(routes4, &winipcfg.RouteData{Destination: p, NextHop: netip.IPv4Unspecified()})
		} else {
			routes6 = append(routes6, &winipcfg.RouteData{Destination: p, NextHop: netip.IPv6Unspecified()})
		}
	}
	if err := l.SetRoutesForFamily(windows.AF_INET, routes4); err != nil {
		return fmt.Errorf("маршруты IPv4: %w", err)
	}
	// IPv6 ставится всегда, даже пустым: повторный вызов с меньшим конфигом снимает старые маршруты.
	// Нет стека IPv6 (ERROR_NOT_FOUND): терпим, если маршрутов нет или это только заглушка ::/1 + 8000::/1,
	// которую добавил planRoutes. Свои IPv6-префиксы конфига без стека IPv6 дают ошибку.
	if err := l.SetRoutesForFamily(windows.AF_INET6, routes6); err != nil {
		if !(errors.Is(err, windows.ERROR_NOT_FOUND) && (len(routes6) == 0 || ipv6SinkOnly(allowed))) {
			return fmt.Errorf("маршруты IPv6: %w", err)
		}
	}
	for _, fam := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		var servers []netip.Addr
		for _, d := range dns {
			if (fam == windows.AF_INET) == d.Is4() {
				servers = append(servers, d)
			}
		}
		if len(servers) == 0 {
			continue
		}
		if err := l.SetDNS(fam, servers, nil); err != nil {
			return fmt.Errorf("DNS: %w", err)
		}
	}
	return nil
}

// ClearTunnel снимает с адаптера маршруты, DNS и адреса. Отсутствие семейства или
// записи ошибкой не считается.
func ClearTunnel(luid uint64) error {
	l := winipcfg.LUID(luid)
	var errs []error
	keep := func(err error) {
		if err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			errs = append(errs, err)
		}
	}
	for _, fam := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		keep(l.FlushRoutes(fam))
		keep(l.FlushDNS(fam))
		keep(l.FlushIPAddresses(fam))
	}
	return errors.Join(errs...)
}

// bypassRoute — маршрут обхода через физический интерфейс.
type bypassRoute struct {
	LUID    uint64
	Prefix  netip.Prefix
	NextHop netip.Addr
}

// bypassFor строит маршруты обхода через физический шлюз. Нулевой Gateway4 значит
// прямой интерфейс: следующий узел 0.0.0.0. IPv6 без Gateway6 пропускается.
func bypassFor(ph model.Physical, prefixes []netip.Prefix) []bypassRoute {
	var out []bypassRoute
	for _, p := range prefixes {
		if !p.IsValid() {
			continue
		}
		p = p.Masked()
		var nh netip.Addr
		if p.Addr().Is4() {
			nh = ph.Gateway4
			if !nh.IsValid() {
				nh = netip.IPv4Unspecified()
			}
		} else {
			nh = ph.Gateway6
			if !nh.IsValid() {
				continue
			}
		}
		r := bypassRoute{LUID: ph.LUID, Prefix: p, NextHop: nh}
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}

// diffBypass возвращает маршруты, которые надо удалить и добавить, чтобы перейти от old к want.
func diffBypass(old, want []bypassRoute) (del, add []bypassRoute) {
	for _, r := range old {
		if !slices.Contains(want, r) {
			del = append(del, r)
		}
	}
	for _, r := range want {
		if !slices.Contains(old, r) {
			add = append(add, r)
		}
	}
	return del, add
}

// Последний применённый набор обхода. Нужен, чтобы убрать устаревшие маршруты
// и чтобы ClearBypass знал, что удалять.
var (
	bypassMu      sync.Mutex
	bypassApplied []bypassRoute
)

// SetBypass заменяет набор маршрутов обхода: лишние прошлые удаляются, новые добавляются.
// Маршрут, который уже есть в системе, не наш и не записывается, поэтому не будет удалён.
// Ошибки отдельных маршрутов не прерывают остальные и возвращаются вместе.
func SetBypass(ph model.Physical, prefixes []netip.Prefix) error {
	bypassMu.Lock()
	defer bypassMu.Unlock()

	del, add := diffBypass(bypassApplied, bypassFor(ph, prefixes))
	errs := dropRoutes(&bypassApplied, del, deleteRoute)
	for _, r := range add {
		err := winipcfg.LUID(r.LUID).AddRoute(r.Prefix, r.NextHop, 0)
		switch {
		case err == nil:
			bypassApplied = append(bypassApplied, r)
		case errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS):
			// Такой маршрут уже есть, не наш.
		default:
			errs = append(errs, fmt.Errorf("обход %s: %w", r.Prefix, err))
		}
	}
	return errors.Join(errs...)
}

// ClearBypass удаляет все маршруты обхода, добавленные SetBypass.
func ClearBypass() error {
	bypassMu.Lock()
	defer bypassMu.Unlock()

	errs := dropRoutes(&bypassApplied, slices.Clone(bypassApplied), deleteRoute)
	return errors.Join(errs...)
}

// dropRoutes удаляет маршруты через rm и убирает из applied только удалённые.
// Маршрут, который не удалось удалить, остаётся в списке: его повторят при следующем вызове,
// а не потеряют навсегда.
func dropRoutes(applied *[]bypassRoute, del []bypassRoute, rm func(bypassRoute) error) []error {
	var errs []error
	for _, r := range del {
		if err := rm(r); err != nil {
			errs = append(errs, err)
			continue
		}
		*applied = slices.DeleteFunc(*applied, func(x bypassRoute) bool { return x == r })
	}
	return errs
}

// deleteRoute удаляет маршрут; если его уже нет, это не ошибка.
func deleteRoute(r bypassRoute) error {
	err := winipcfg.LUID(r.LUID).DeleteRoute(r.Prefix, r.NextHop)
	if err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
		return fmt.Errorf("удаление обхода %s: %w", r.Prefix, err)
	}
	return nil
}
