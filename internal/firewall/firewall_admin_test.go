//go:build admin

package firewall

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

	if _, err := Enable(Options{AllowLAN: true, KillSwitch: true}); err != nil {
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

	if _, err := Enable(Options{AllowLAN: true, KillSwitch: true}); err != nil {
		t.Fatal(err)
	}

	_, err := Update(Options{
		AllowLAN:   true,
		KillSwitch: true,
		DNS:        []netip.Addr{netip.MustParseAddr("203.0.113.53")},
		Bypass:     []netip.Prefix{netip.MustParsePrefix(bypassSubnet)},
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

	if _, err := Update(Options{AllowLAN: true, KillSwitch: true}); err != nil {
		t.Fatal(err)
	}
	if err := probe(bypassTarget, 3*time.Second); err == nil {
		t.Fatal("после второго Update соединение прошло через блокировку")
	}
}

// Программа из списка без kill switch: мимо туннеля не выходит, loopback ей открыт, у
// остальных процессов сеть есть. После снятия сессии программа снова работает.
func TestAppsBlockedWithoutKillSwitch(t *testing.T) {
	curl := filepath.Join(os.Getenv("SystemRoot"), "System32", "curl.exe")
	if _, err := os.Stat(curl); err != nil {
		t.Skipf("нет %s", curl)
	}
	run := func(url string) error {
		return exec.Command(curl, "-s", "-o", "NUL", "--connect-timeout", "3", url).Run()
	}
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer local.Close()
	const remote = "http://1.1.1.1/"
	missing := `C:\no-such-dir\missing.exe`

	setup(t, blockedTarget)
	if err := run(remote); err != nil {
		t.Fatalf("curl не выходит в сеть ещё до блокировки: %v", err)
	}

	skipped, err := Enable(Options{Apps: []string{curl, missing}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(skipped, []string{missing}) {
		t.Fatalf("пропущены %v, ожидался %s", skipped, missing)
	}
	if err := run(remote); err == nil {
		t.Fatal("программа из списка вышла в сеть мимо туннеля")
	}
	if err := run(local.URL); err != nil {
		t.Fatalf("loopback программе закрыт: %v", err)
	}
	if err := probe(blockedTarget, 3*time.Second); err != nil {
		t.Fatalf("процесс не из списка потерял сеть: %v", err)
	}

	Disable()
	if err := run(remote); err != nil {
		t.Fatalf("после снятия сессии программа без сети: %v", err)
	}
}
