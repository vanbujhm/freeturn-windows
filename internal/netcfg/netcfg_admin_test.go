//go:build admin

package netcfg

import (
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Отдельный GUID тестового адаптера, не совпадающий с GUID адаптера FreeTurn.
var testAdapterGUID = windows.GUID{
	Data1: 0x7E0B0F52, Data2: 0x5C3D, Data3: 0x4F1B,
	Data4: [8]byte{0x9A, 0x6E, 0x3D, 0x1C, 0x2B, 0x7A, 0x4F, 0x11},
}

// loadWintun подгружает wintun.dll из репозитория: бинарник теста лежит во временной
// папке, а wintun ищет библиотеку рядом с exe. Уже загруженный модуль находится по имени.
func loadWintun(t *testing.T) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dll := filepath.Join(filepath.Dir(file), "..", "..", "third_party", "wintun", "wintun.dll")
	if _, err := os.Stat(dll); err != nil {
		t.Skipf("нет %s (появляется в Task 6): адаптер создать нечем", dll)
	}
	if _, err := windows.LoadLibrary(dll); err != nil {
		t.Fatalf("LoadLibrary %s: %v", dll, err)
	}
}

func hasRoute(t *testing.T, luid uint64, p netip.Prefix) bool {
	t.Helper()
	table, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		t.Fatalf("GetIPForwardTable2: %v", err)
	}
	for i := range table {
		if uint64(table[i].InterfaceLUID) == luid && table[i].DestinationPrefix.Prefix() == p {
			return true
		}
	}
	return false
}

// Маршрут по умолчанию тест не трогает: на проводе меняются только документационные
// подсети, поэтому согласие на обрыв сети не нужно.
func TestAdapterRoutesAndBypass(t *testing.T) {
	loadWintun(t)

	dev, err := tun.CreateTUNWithRequestedGUID("FreeTurnTest", &testAdapterGUID, 1280)
	if err != nil {
		t.Fatalf("создание адаптера FreeTurnTest: %v", err)
	}
	t.Cleanup(func() { dev.Close() })
	luid := dev.(*tun.NativeTun).LUID()
	t.Cleanup(func() { _ = ClearBypass() })

	addr := netip.MustParsePrefix("10.255.77.2/24")
	if err := ConfigureInterface(luid, []netip.Prefix{addr}, 1280); err != nil {
		t.Fatalf("ConfigureInterface: %v", err)
	}
	if _, err := winipcfg.LUID(luid).IPAddress(addr.Addr()); err != nil {
		t.Fatalf("адрес %s не найден на адаптере: %v", addr, err)
	}
	ipif, err := winipcfg.LUID(luid).IPInterface(windows.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	if ipif.UseAutomaticMetric || ipif.Metric != 0 || ipif.NLMTU != 1280 {
		t.Fatalf("параметры интерфейса: авто=%v метрика=%d MTU=%d", ipif.UseAutomaticMetric, ipif.Metric, ipif.NLMTU)
	}

	tunnelRoute := netip.MustParsePrefix("198.51.100.0/24")
	dns := netip.MustParseAddr("203.0.113.53")
	if err := ApplyTunnelRoutes(luid, []netip.Prefix{tunnelRoute}, []netip.Addr{dns}); err != nil {
		t.Fatalf("ApplyTunnelRoutes: %v", err)
	}
	if !hasRoute(t, luid, tunnelRoute) {
		t.Fatalf("маршрута %s нет в таблице", tunnelRoute)
	}
	got, err := winipcfg.LUID(luid).DNS()
	if err != nil || len(got) != 1 || got[0] != dns {
		t.Fatalf("DNS адаптера = %v, %v; ожидался %s", got, err, dns)
	}

	ph, err := FindPhysical(luid)
	if err != nil {
		t.Fatalf("FindPhysical: %v", err)
	}
	if ph.LUID == luid || ph.LUID == 0 {
		t.Fatalf("физический LUID %d", ph.LUID)
	}

	bypass := netip.MustParsePrefix("203.0.113.0/24")
	stale := netip.MustParsePrefix("192.0.2.0/24")
	if err := SetBypass(ph, []netip.Prefix{bypass, stale}); err != nil {
		t.Fatalf("SetBypass: %v", err)
	}
	if !hasRoute(t, ph.LUID, bypass) || !hasRoute(t, ph.LUID, stale) {
		t.Fatal("маршруты обхода не появились в таблице")
	}
	// Новый набор заменяет прошлый: лишний маршрут уходит.
	if err := SetBypass(ph, []netip.Prefix{bypass}); err != nil {
		t.Fatalf("SetBypass (замена): %v", err)
	}
	if !hasRoute(t, ph.LUID, bypass) || hasRoute(t, ph.LUID, stale) {
		t.Fatal("после замены набора устаревший маршрут остался или нужный пропал")
	}
	if err := ClearBypass(); err != nil {
		t.Fatalf("ClearBypass: %v", err)
	}
	if hasRoute(t, ph.LUID, bypass) {
		t.Fatal("маршрут обхода остался после ClearBypass")
	}

	if err := ClearTunnel(luid); err != nil {
		t.Fatalf("ClearTunnel: %v", err)
	}
	if hasRoute(t, luid, tunnelRoute) {
		t.Fatal("маршрут туннеля остался после ClearTunnel")
	}

	// Вызовы наблюдения и поиска другого туннеля не должны падать.
	name, found := OtherTunnel(luid)
	t.Logf("другой туннель: %q найден=%v", name, found)
	stop, err := WatchDefaultRoute(func() {})
	if err != nil {
		t.Fatalf("WatchDefaultRoute: %v", err)
	}
	stop()
	stop() // повторный вызов безопасен
}
