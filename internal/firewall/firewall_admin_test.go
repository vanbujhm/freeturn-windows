//go:build admin

package firewall

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const probeAddress = "1.1.1.1:443"

func probe(timeout time.Duration) error {
	c, err := net.DialTimeout("tcp", probeAddress, timeout)
	if err != nil {
		return err
	}
	return c.Close()
}

// setup готовит запуск вне службы и ставит страховку: блокировка снимается через 10 с,
// даже если тест завис.
//
// Разрешение службы привязывается к чужому SID. У процесса теста нет SID службы, поэтому
// настоящий поиск вернул бы ERROR_NO_SUCH_GROUP. Свой SID тоже нельзя: тогда правило
// разрешило бы тесту всё, и проверка блокировки ничего бы не значила.
func setup(t *testing.T) {
	t.Helper()
	if err := probe(5 * time.Second); err != nil {
		t.Fatalf("сеть недоступна ещё до блокировки: %v", err)
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
	setup(t)

	if err := Enable(Options{AllowLAN: true}); err != nil {
		t.Fatal(err)
	}
	if !Enabled() {
		t.Fatal("Enabled() false после Enable")
	}
	if err := probe(3 * time.Second); err == nil {
		t.Fatal("соединение прошло через блокировку")
	}

	Disable()
	if Enabled() {
		t.Fatal("Enabled() true после Disable")
	}
	if err := probe(5 * time.Second); err != nil {
		t.Fatalf("соединение не восстановилось: %v", err)
	}
}

// Update проверяется на настоящем WFP: две сессии подряд пересекаются, а исключение
// открывает адрес и закрывает его обратно.
func TestUpdateChangesPermitsWithoutLapse(t *testing.T) {
	setup(t)

	if err := Enable(Options{AllowLAN: true}); err != nil {
		t.Fatal(err)
	}

	bypass := []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32")}
	if err := Update(Options{AllowLAN: true, Bypass: bypass}); err != nil {
		t.Fatal(err)
	}
	if err := probe(3 * time.Second); err != nil {
		t.Fatalf("исключение не сработало: %v", err)
	}

	if err := Update(Options{AllowLAN: true}); err != nil {
		t.Fatal(err)
	}
	if err := probe(3 * time.Second); err == nil {
		t.Fatal("после второго Update соединение прошло через блокировку")
	}
}
