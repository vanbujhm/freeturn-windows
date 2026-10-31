//go:build admin

package firewall

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const (
	blockedTarget = "1.1.1.1:443"

	// Подсеть для исключения подобрана под порядок байт. 1.1.1.1/32 и 1.1.1.0/24 его не
	// проверяют: с переставленными байтами адрес из них всё равно совпал бы. У 8.8.4.0/24
	// переставленная запись не совпадает с 8.8.4.4, и проверка упала бы.
	bypassSubnet = "8.8.4.0/24"
	bypassTarget = "8.8.4.4:443"
	bypassDNS    = "8.8.4.4:53"
)

func probe(target string, timeout time.Duration) error {
	c, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return err
	}
	return c.Close()
}

// setup проверяет, что цели доступны до блокировки, готовит запуск вне службы и ставит
// страховку: блокировка снимается через 10 с, даже если тест завис.
//
// Разрешение службы привязывается к чужому SID. У процесса теста нет SID службы, поэтому
// настоящий поиск вернул бы ERROR_NO_SUCH_GROUP. Свой SID тоже нельзя: тогда правило
// разрешило бы тесту всё, и проверка блокировки ничего бы не значила.
func setup(t *testing.T, targets ...string) {
	t.Helper()
	for _, target := range targets {
		if err := probe(target, 5*time.Second); err != nil {
			t.Fatalf("%s недоступен ещё до блокировки: %v", target, err)
		}
	}

	realSID := serviceSID
	serviceSID = func() (*windows.SID, error) {
		return windows.CreateWellKnownSid(windows.WinLocalServiceSid)
	}
	safety := time.AfterFunc(10*time.Second, Disable)
	t.Cleanup(func() {
		safety.Stop()
		Disable()
		serviceSID = realSID
	})
}

func TestEnableBlocksAndDisableRestores(t *testing.T) {
	setup(t, blockedTarget)

	if err := Enable(Options{AllowLAN: true}); err != nil {
		t.Fatal(err)
	}
	if !Enabled() {
		t.Fatal("Enabled() false после Enable")
	}
	if err := probe(blockedTarget, 3*time.Second); err == nil {
		t.Fatal("соединение прошло через блокировку")
	}

	Disable()
	if Enabled() {
		t.Fatal("Enabled() true после Disable")
	}
	if err := probe(blockedTarget, 5*time.Second); err != nil {
		t.Fatalf("соединение не восстановилось: %v", err)
	}
}

// Update подряд заменяет разрешения на настоящем WFP. Исключение открывает подсеть,
// запрет DNS с весом 14 перекрывает его разрешение с весом 12, а следующий Update
// закрывает подсеть обратно. Непрерывность блокировки в момент смены здесь не проверяется.
func TestUpdateReplacesPermits(t *testing.T) {
	setup(t, bypassTarget, bypassDNS)

	if err := Enable(Options{AllowLAN: true}); err != nil {
		t.Fatal(err)
	}

	err := Update(Options{
		AllowLAN: true,
		DNS:      []netip.Addr{netip.MustParseAddr("203.0.113.53")},
		Bypass:   []netip.Prefix{netip.MustParsePrefix(bypassSubnet)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := probe(bypassTarget, 3*time.Second); err != nil {
		t.Fatalf("исключение не сработало: %v", err)
	}
	if err := probe(bypassDNS, 3*time.Second); err == nil {
		t.Fatal("DNS прошёл через запрет на адрес из исключения")
	}

	if err := Update(Options{AllowLAN: true}); err != nil {
		t.Fatal(err)
	}
	if err := probe(bypassTarget, 3*time.Second); err == nil {
		t.Fatal("после второго Update соединение прошло через блокировку")
	}
}
