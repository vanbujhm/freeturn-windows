//go:build admin

package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/vanbujhm/freeturn-windows/internal/wgconf"
)

// TestMain кладёт wintun.dll рядом с exe теста: wintun ищет библиотеку только там,
// а бинарник теста лежит во временной папке. Нет DLL в third_party - тесты падают, а не пропускаются.
func TestMain(m *testing.M) {
	if err := copyWintun(); err != nil {
		fmt.Fprintln(os.Stderr, "wintun.dll:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func copyWintun() error {
	_, file, _, _ := runtime.Caller(0)
	src := filepath.Join(filepath.Dir(file), "..", "..", "third_party", "wintun", "wintun.dll")
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(filepath.Dir(exe), "wintun.dll"), data, 0o644)
}

// fakeKey - выдуманный ключ: 32 байта одного значения.
func fakeKey(b byte) wgconf.Key {
	var k wgconf.Key
	for i := range k {
		k[i] = b
	}
	return k
}

func testConfig() *wgconf.Config {
	return &wgconf.Config{
		PrivateKey: fakeKey(1),
		Addresses:  []netip.Prefix{netip.MustParsePrefix("198.51.100.2/32")},
		MTU:        1280,
		Peers: []wgconf.Peer{{
			PublicKey:  fakeKey(2),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		}},
	}
}

func TestRemoveStaleNoAdapter(t *testing.T) {
	if _, err := net.InterfaceByName(AdapterName); err == nil {
		t.Skip("адаптер FreeTurn уже есть: проверять нечего, не трогаем чужое подключение")
	}
	if err := RemoveStale(); err != nil {
		t.Fatalf("RemoveStale без адаптера: %v", err)
	}
}

func TestOpenAndClose(t *testing.T) {
	d, err := Open(testConfig(), netip.MustParseAddrPort("127.0.0.1:9"), t.Logf)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(d.Close)

	if d.LUID() == 0 {
		t.Error("LUID() == 0")
	}
	if _, err := net.InterfaceByName(AdapterName); err != nil {
		t.Errorf("адаптер %s не виден после Open: %v", AdapterName, err)
	}
	st, err := d.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if !st.LastHandshake.IsZero() {
		t.Errorf("рукопожатие до пира без сервера: %v", st.LastHandshake)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	if err := d.WaitHandshake(ctx); err != context.DeadlineExceeded {
		t.Errorf("WaitHandshake = %v, want DeadlineExceeded", err)
	}

	d.Close()
	d.Close() // повторный вызов безопасен

	// Адаптер исчезает не мгновенно.
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := net.InterfaceByName(AdapterName)
		if err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("адаптер остался после Close")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
