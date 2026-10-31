package netcfg

import (
	"errors"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

func pfx(t *testing.T, s ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(s))
	for _, v := range s {
		out = append(out, netip.MustParsePrefix(v))
	}
	return out
}

func strs(p []netip.Prefix) []string {
	out := make([]string, 0, len(p))
	for _, v := range p {
		out = append(out, v.String())
	}
	return out
}

func TestPlanRoutesFullV4AddsV6Sink(t *testing.T) {
	got := strs(planRoutes(pfx(t, "0.0.0.0/0")))
	want := []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if slices.Contains(got, "0.0.0.0/0") {
		t.Fatal("маршрут /0 не должен попадать в план")
	}
}

func TestPlanRoutesFullBoth(t *testing.T) {
	got := strs(planRoutes(pfx(t, "0.0.0.0/0", "::/0")))
	want := []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestPlanRoutesSplit(t *testing.T) {
	got := strs(planRoutes(pfx(t, "10.0.0.0/24")))
	want := []string{"10.0.0.0/24"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestPlanRoutesFullV6Only(t *testing.T) {
	got := strs(planRoutes(pfx(t, "::/0")))
	want := []string{"::/1", "8000::/1"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestPlanRoutesFullV4WithOwnV6NoSink(t *testing.T) {
	got := strs(planRoutes(pfx(t, "0.0.0.0/0", "fd00::/8")))
	want := []string{"0.0.0.0/1", "128.0.0.0/1", "fd00::/8"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestPlanRoutesDedupAndMask(t *testing.T) {
	got := strs(planRoutes(pfx(t, "10.0.0.5/24", "10.0.0.0/24", "203.0.113.0/24", "10.0.0.0/24")))
	want := []string{"10.0.0.0/24", "203.0.113.0/24"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestPlanRoutesEmpty(t *testing.T) {
	if got := planRoutes(nil); len(got) != 0 {
		t.Fatalf("got %v, want пусто", got)
	}
}

func defRow(luid uint64, ifType uint32, desc string, routeMetric, ifMetric uint32) routeRow {
	return routeRow{
		LUID: luid, IfIndex: uint32(luid), IfType: ifType, Desc: desc,
		Dest:        netip.MustParsePrefix("0.0.0.0/0"),
		NextHop:     netip.MustParseAddr("192.0.2.1"),
		RouteMetric: routeMetric, IfMetric: ifMetric,
	}
}

func TestPickDefault(t *testing.T) {
	rows := []routeRow{
		defRow(1, 6, "Ethernet", 0, 50),
		defRow(2, 71, "Wi-Fi", 0, 25),
		defRow(3, 6, "USB Ethernet", 10, 20),
	}
	got, err := pickDefault(rows, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.LUID != 2 {
		t.Fatalf("выбран LUID %d, ожидался 2 (сумма метрик 25)", got.LUID)
	}
	// Исключённый LUID пропускается.
	got, err = pickDefault(rows, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got.LUID != 3 {
		t.Fatalf("выбран LUID %d, ожидался 3 (сумма метрик 30)", got.LUID)
	}
}

func TestPickDefaultSkipsTunnelTypes(t *testing.T) {
	rows := []routeRow{
		defRow(1, ifTypePropVirtual, "Virtual", 0, 0),
		defRow(2, ifTypeTunnel, "Tunnel", 0, 0),
		defRow(3, 71, "Wi-Fi", 50, 50),
		defRow(4, 6, "Wintun Userspace Tunnel", 0, 0),
		defRow(5, 6, "Meta Tunnel", 0, 0),
		defRow(6, 6, "WINTUN adapter", 0, 0),
		defRow(7, 6, "Ethernet", 100, 100),
	}
	// Туннельные типы и описания пропускаются, даже при метрике 0.
	got, err := pickDefault(rows, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.LUID != 3 {
		t.Fatalf("выбран LUID %d, ожидался 3", got.LUID)
	}
	rows = slices.DeleteFunc(rows, func(r routeRow) bool { return r.LUID == 3 })
	got, err = pickDefault(rows, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.LUID != 7 {
		t.Fatalf("выбран LUID %d, ожидался физический 7", got.LUID)
	}
}

func TestPickDefaultNoRoutes(t *testing.T) {
	if _, err := pickDefault(nil, 0); !errors.Is(err, ErrNoNetwork) {
		t.Fatalf("err = %v, ожидался ErrNoNetwork", err)
	}
	// Остались только туннели: физической сети нет.
	rows := []routeRow{defRow(1, ifTypePropVirtual, "Meta Tunnel", 0, 0)}
	if _, err := pickDefault(rows, 0); !errors.Is(err, ErrNoNetwork) {
		t.Fatalf("err = %v, ожидался ErrNoNetwork", err)
	}
	// Единственный физический исключён.
	rows = []routeRow{defRow(1, 6, "Ethernet", 0, 0)}
	if _, err := pickDefault(rows, 1); !errors.Is(err, ErrNoNetwork) {
		t.Fatalf("err = %v, ожидался ErrNoNetwork", err)
	}
}

func TestPickDefaultIgnoresNonDefaultRows(t *testing.T) {
	r := defRow(1, 6, "Ethernet", 0, 0)
	r.Dest = netip.MustParsePrefix("192.0.2.0/24")
	if _, err := pickDefault([]routeRow{r}, 0); !errors.Is(err, ErrNoNetwork) {
		t.Fatalf("err = %v, ожидался ErrNoNetwork", err)
	}
}

func TestFindTunnel(t *testing.T) {
	mk := func(luid uint64, ifType uint32, name, dest string) routeRow {
		r := defRow(luid, ifType, "", 0, 0)
		r.Name = name
		r.Dest = netip.MustParsePrefix(dest)
		return r
	}
	rows := []routeRow{
		mk(1, 6, "Ethernet", "0.0.0.0/0"),
		mk(2, ifTypePropVirtual, "Mihomo", "0.0.0.0/0"),
		mk(3, ifTypeTunnel, "Teredo", "::/0"),
		mk(4, ifTypePropVirtual, "Split", "0.0.0.0/1"),
		mk(5, ifTypePropVirtual, "Lan", "10.0.0.0/24"),
	}
	if name, ok := findTunnel(rows, 0); !ok || name != "Mihomo" {
		t.Fatalf("got %q %v, ожидался Mihomo", name, ok)
	}
	if name, ok := findTunnel(rows, 2); !ok || name != "Teredo" {
		t.Fatalf("got %q %v, ожидался Teredo", name, ok)
	}
	if name, ok := findTunnel(rows[:1], 0); ok {
		t.Fatalf("физический адаптер принят за туннель: %q", name)
	}
	// Виртуальный адаптер с 0.0.0.0/1 считается держателем маршрута по умолчанию.
	if name, ok := findTunnel([]routeRow{rows[3]}, 0); !ok || name != "Split" {
		t.Fatalf("got %q %v, ожидался Split", name, ok)
	}
	// Обычный маршрут виртуального адаптера не считается.
	if _, ok := findTunnel([]routeRow{rows[4]}, 0); ok {
		t.Fatal("маршрут /24 принят за маршрут по умолчанию")
	}
}

func TestBypassFor(t *testing.T) {
	ph := model.Physical{
		LUID:     7,
		Gateway4: netip.MustParseAddr("192.0.2.1"),
	}
	got := bypassFor(ph, pfx(t, "203.0.113.0/24", "2001:db8::/32", "203.0.113.0/24", "198.51.100.7/32"))
	want := []bypassRoute{
		{LUID: 7, Prefix: netip.MustParsePrefix("203.0.113.0/24"), NextHop: ph.Gateway4},
		{LUID: 7, Prefix: netip.MustParsePrefix("198.51.100.7/32"), NextHop: ph.Gateway4},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v (IPv6 без шлюза пропускается, дубли убираются)", got, want)
	}

	ph.Gateway6 = netip.MustParseAddr("fe80::1")
	got = bypassFor(ph, pfx(t, "2001:db8::/32"))
	if len(got) != 1 || got[0].NextHop != ph.Gateway6 {
		t.Fatalf("got %v, ожидался один IPv6-маршрут через Gateway6", got)
	}

	// Нулевой Gateway4 означает прямой интерфейс: нулевой следующий узел.
	ph = model.Physical{LUID: 7}
	got = bypassFor(ph, pfx(t, "203.0.113.0/24"))
	if len(got) != 1 || got[0].NextHop != netip.IPv4Unspecified() {
		t.Fatalf("got %v, ожидался следующий узел 0.0.0.0", got)
	}
}

func TestDiffBypass(t *testing.T) {
	a := bypassRoute{LUID: 1, Prefix: netip.MustParsePrefix("203.0.113.0/24"), NextHop: netip.MustParseAddr("192.0.2.1")}
	b := bypassRoute{LUID: 1, Prefix: netip.MustParsePrefix("198.51.100.0/24"), NextHop: netip.MustParseAddr("192.0.2.1")}
	// Тот же префикс, но другой шлюз после смены сети: старый удаляется, новый добавляется.
	a2 := a
	a2.LUID = 2
	a2.NextHop = netip.MustParseAddr("192.0.2.254")

	del, add := diffBypass([]bypassRoute{a, b}, []bypassRoute{b, a2})
	if !slices.Equal(del, []bypassRoute{a}) {
		t.Fatalf("del = %v", del)
	}
	if !slices.Equal(add, []bypassRoute{a2}) {
		t.Fatalf("add = %v", add)
	}

	del, add = diffBypass(nil, []bypassRoute{a})
	if len(del) != 0 || !slices.Equal(add, []bypassRoute{a}) {
		t.Fatalf("del = %v, add = %v", del, add)
	}
}

func TestDebouncerFiresOnceAfterQuiet(t *testing.T) {
	var n atomic.Int32
	d := newDebouncer(200*time.Millisecond, func() { n.Add(1) })
	for range 5 {
		d.trigger()
		time.Sleep(20 * time.Millisecond)
	}
	if n.Load() != 0 {
		t.Fatal("обратный вызов сработал до окончания тишины")
	}
	time.Sleep(500 * time.Millisecond)
	if n.Load() != 1 {
		t.Fatalf("вызовов %d, ожидался один", n.Load())
	}
}

func TestDebouncerStop(t *testing.T) {
	var n atomic.Int32
	d := newDebouncer(30*time.Millisecond, func() { n.Add(1) })
	d.trigger()
	d.stop()
	time.Sleep(120 * time.Millisecond)
	if n.Load() != 0 {
		t.Fatal("обратный вызов сработал после stop")
	}
	d.trigger() // после stop ничего не планируется
	time.Sleep(120 * time.Millisecond)
	if n.Load() != 0 {
		t.Fatal("trigger после stop запланировал вызов")
	}
}

func TestIPv6SinkOnly(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want bool
	}{
		{"полный IPv4", []string{"0.0.0.0/0"}, true},
		{"полный обоих семейств", []string{"0.0.0.0/0", "::/0"}, false},
		{"полный IPv4 и свой IPv6", []string{"0.0.0.0/0", "fd00::/8"}, false},
		{"частичный IPv4", []string{"10.0.0.0/24"}, false},
		{"пусто", nil, false},
	}
	for _, c := range cases {
		if got := ipv6SinkOnly(pfx(t, c.in...)); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDropRoutesKeepsFailed(t *testing.T) {
	a := bypassRoute{LUID: 1, Prefix: netip.MustParsePrefix("203.0.113.0/24"), NextHop: netip.MustParseAddr("192.0.2.1")}
	b := bypassRoute{LUID: 1, Prefix: netip.MustParsePrefix("198.51.100.0/24"), NextHop: netip.MustParseAddr("192.0.2.1")}
	c := bypassRoute{LUID: 1, Prefix: netip.MustParsePrefix("192.0.2.0/24"), NextHop: netip.MustParseAddr("192.0.2.1")}
	applied := []bypassRoute{a, b, c}
	errs := dropRoutes(&applied, []bypassRoute{a, b}, func(r bypassRoute) error {
		if r == b {
			return errors.New("отказ")
		}
		return nil
	})
	if len(errs) != 1 {
		t.Fatalf("errs = %v", errs)
	}
	if !slices.Equal(applied, []bypassRoute{b, c}) {
		t.Fatalf("applied = %v, ожидались b и c: неудалённый маршрут должен остаться", applied)
	}
}
