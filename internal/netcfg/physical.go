// Package netcfg настраивает сеть Windows: адрес и маршруты туннеля, DNS,
// маршруты обхода и наблюдение за маршрутом по умолчанию. Работает поверх winipcfg.
package netcfg

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// ErrNoNetwork: физического интерфейса с маршрутом по умолчанию нет.
var ErrNoNetwork = errors.New("netcfg: нет физической сети")

// Типы интерфейсов IANA, которые не считаются физической сетью.
const (
	ifTypePropVirtual = 53  // IF_TYPE_PROP_VIRTUAL: Wintun, TUN-адаптеры Mihomo и подобные
	ifTypeTunnel      = 131 // IF_TYPE_TUNNEL
)

// routeRow — строка таблицы маршрутов вместе со сведениями об адаптере.
// Чистые функции работают с такими строками, поэтому тестам не нужны системные вызовы.
type routeRow struct {
	LUID        uint64
	IfIndex     uint32
	IfType      uint32
	Name, Desc  string
	Dest        netip.Prefix
	NextHop     netip.Addr
	RouteMetric uint32
	IfMetric    uint32
}

// isTunnelAdapter: адаптер виртуальный или туннельный, физической сетью быть не может.
func (r routeRow) isTunnelAdapter() bool {
	if r.IfType == ifTypePropVirtual || r.IfType == ifTypeTunnel {
		return true
	}
	d := strings.ToLower(r.Desc)
	return strings.Contains(d, "wintun") || strings.Contains(d, "meta tunnel")
}

// pickDefault выбирает физический интерфейс среди маршрутов по умолчанию:
// туннели и исключённый LUID пропускаются, побеждает наименьшая сумма метрик
// маршрута и интерфейса. Строки с другим префиксом, кроме /0, игнорируются.
func pickDefault(rows []routeRow, exclude uint64) (routeRow, error) {
	var best routeRow
	found := false
	for _, r := range rows {
		if r.Dest.Bits() != 0 || r.LUID == exclude || r.isTunnelAdapter() {
			continue
		}
		if !found || r.RouteMetric+r.IfMetric < best.RouteMetric+best.IfMetric {
			best, found = r, true
		}
	}
	if !found {
		return routeRow{}, ErrNoNetwork
	}
	return best, nil
}

// findTunnel ищет другой туннель: виртуальный или туннельный адаптер (не exclude),
// который держит маршрут по умолчанию. Пара 0.0.0.0/1 тоже считается таким маршрутом,
// потому что так делают VPN, обходящие приоритет /0.
func findTunnel(rows []routeRow, exclude uint64) (string, bool) {
	half := netip.MustParsePrefix("0.0.0.0/1")
	for _, r := range rows {
		if r.LUID == exclude {
			continue
		}
		if r.IfType != ifTypePropVirtual && r.IfType != ifTypeTunnel {
			continue
		}
		if r.Dest.Bits() == 0 || r.Dest == half {
			return r.Name, true
		}
	}
	return "", false
}

// adapterInfo — сведения об адаптере из GetAdaptersAddresses.
type adapterInfo struct {
	luid             uint64
	ifIndex          uint32
	ifType           uint32
	name, desc       string
	metric4, metric6 uint32
	dns              []netip.Addr
}

// listAdapters возвращает работающие адаптеры по LUID.
func listAdapters() (map[uint64]adapterInfo, error) {
	list, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagDefault)
	if err != nil {
		return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
	}
	out := make(map[uint64]adapterInfo, len(list))
	for _, a := range list {
		if a.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		info := adapterInfo{
			luid:    uint64(a.LUID),
			ifIndex: a.IfIndex,
			ifType:  uint32(a.IfType),
			name:    a.FriendlyName(),
			desc:    a.Description(),
			metric4: a.Ipv4Metric,
			metric6: a.Ipv6Metric,
		}
		for d := a.FirstDNSServerAddress; d != nil; d = d.Next {
			ip, ok := netip.AddrFromSlice(d.Address.IP())
			// Пустые адреса и устаревшие fec0::/10 из списка не берём.
			if !ok || ip.IsUnspecified() || isSiteLocal(ip) {
				continue
			}
			info.dns = append(info.dns, ip.Unmap())
		}
		out[info.luid] = info
	}
	return out, nil
}

func isSiteLocal(a netip.Addr) bool {
	return a.Is6() && a.As16()[0] == 0xfe && a.As16()[1]&0xc0 == 0xc0
}

// routeRows читает таблицу маршрутов семейства и склеивает её со сведениями об адаптерах.
// Маршруты неработающих и неизвестных адаптеров отбрасываются.
func routeRows(family winipcfg.AddressFamily, adapters map[uint64]adapterInfo) ([]routeRow, error) {
	table, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return nil, fmt.Errorf("GetIPForwardTable2: %w", err)
	}
	rows := make([]routeRow, 0, len(table))
	for i := range table {
		t := &table[i]
		ad, ok := adapters[uint64(t.InterfaceLUID)]
		if !ok {
			continue
		}
		metric := ad.metric4
		if family == windows.AF_INET6 {
			metric = ad.metric6
		}
		rows = append(rows, routeRow{
			LUID:        ad.luid,
			IfIndex:     ad.ifIndex,
			IfType:      ad.ifType,
			Name:        ad.name,
			Desc:        ad.desc,
			Dest:        t.DestinationPrefix.Prefix(),
			NextHop:     t.NextHop.Addr(),
			RouteMetric: t.Metric,
			IfMetric:    metric,
		})
	}
	return rows, nil
}

// FindPhysical находит физический интерфейс: наименьшая сумма метрик среди
// маршрутов по умолчанию, без туннелей и без адаптера exclude.
// Если маршрута IPv4 нет, берётся IPv6. Нет ни одного: ErrNoNetwork.
func FindPhysical(exclude uint64) (model.Physical, error) {
	adapters, err := listAdapters()
	if err != nil {
		return model.Physical{}, err
	}
	rows4, err := routeRows(windows.AF_INET, adapters)
	if err != nil {
		return model.Physical{}, err
	}
	rows6, err := routeRows(windows.AF_INET6, adapters)
	if err != nil {
		return model.Physical{}, err
	}

	var ph model.Physical
	p4, err4 := pickDefault(rows4, exclude)
	if err4 == nil {
		ph.LUID = p4.LUID
		ph.Index4 = p4.IfIndex
		ph.Index6 = p4.IfIndex
		ph.Gateway4 = gatewayOf(p4.NextHop)
		// IPv6 берём с того же интерфейса, чтобы обход шёл одним путём.
		if p6, err := pickDefault(sameLUID(rows6, p4.LUID), exclude); err == nil {
			ph.Index6 = p6.IfIndex
			ph.Gateway6 = gatewayOf(p6.NextHop)
		}
	} else {
		p6, err6 := pickDefault(rows6, exclude)
		if err6 != nil {
			return model.Physical{}, ErrNoNetwork
		}
		ph.LUID = p6.LUID
		ph.Index4 = p6.IfIndex
		ph.Index6 = p6.IfIndex
		ph.Gateway6 = gatewayOf(p6.NextHop)
	}
	ph.DNS = adapters[ph.LUID].dns
	return ph, nil
}

func sameLUID(rows []routeRow, luid uint64) []routeRow {
	var out []routeRow
	for _, r := range rows {
		if r.LUID == luid {
			out = append(out, r)
		}
	}
	return out
}

// gatewayOf превращает следующий узел маршрута в шлюз. Нулевой адрес (on-link) даёт
// нулевой Addr, как у model.Physical без шлюза.
func gatewayOf(nh netip.Addr) netip.Addr {
	if !nh.IsValid() || nh.IsUnspecified() {
		return netip.Addr{}
	}
	return nh
}

// OtherTunnel возвращает имя другого туннеля с маршрутом по умолчанию (кроме exclude).
// Ошибки чтения сети считаются отсутствием туннеля: это только предупреждение.
func OtherTunnel(exclude uint64) (name string, found bool) {
	adapters, err := listAdapters()
	if err != nil {
		return "", false
	}
	var rows []routeRow
	for _, fam := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		r, err := routeRows(fam, adapters)
		if err != nil {
			continue
		}
		rows = append(rows, r...)
	}
	return findTunnel(rows, exclude)
}
