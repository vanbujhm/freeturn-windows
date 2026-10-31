//go:build admin

package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
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
	dst := filepath.Join(filepath.Dir(exe), "wintun.dll")
	// Дочерний процесс теста запускается из той же папки, а DLL у родителя уже загружена
	// и перезаписи не поддаётся: одинаковый файл не трогаем.
	if cur, err := os.ReadFile(dst); err == nil && bytes.Equal(cur, data) {
		return nil
	}
	return os.WriteFile(dst, data, 0o644)
}

// skipIfAdapterExists не даёт тесту убить живое подключение: адаптер FreeTurn уже есть.
func skipIfAdapterExists(t *testing.T) {
	t.Helper()
	if _, err := net.InterfaceByName(AdapterName); err == nil {
		t.Skipf("адаптер %s уже есть: не трогаем чужое подключение", AdapterName)
	}
}

// waitAdapterGone ждёт исчезновения адаптера до 5 с.
func waitAdapterGone(t *testing.T, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := net.InterfaceByName(AdapterName); err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(100 * time.Millisecond)
	}
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
	skipIfAdapterExists(t)
	if err := RemoveStale(); err != nil {
		t.Fatalf("RemoveStale без адаптера: %v", err)
	}
}

func TestOpenAndClose(t *testing.T) {
	skipIfAdapterExists(t)
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
	waitAdapterGone(t, "адаптер остался после Close")
}

const helperEnv = "FREETURN_HOLD_ADAPTER"

// TestHelperHoldAdapter работает только как дочерний процесс TestRemoveStaleAfterCrash:
// поднимает адаптер, сообщает об этом и ждёт, пока его убьют.
func TestHelperHoldAdapter(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		return
	}
	if _, err := Open(testConfig(), netip.MustParseAddrPort("127.0.0.1:9"), nil); err != nil {
		fmt.Println("OPEN-FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("HOLDING-ADAPTER")
	select {}
}

func TestRemoveStaleAfterCrash(t *testing.T) {
	skipIfAdapterExists(t)

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHoldAdapter$")
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("запуск дочернего процесса: %v", err)
	}
	killed := false
	t.Cleanup(func() {
		if !killed {
			cmd.Process.Kill()
			cmd.Wait()
		}
		// Что бы ни случилось, после теста адаптера быть не должно.
		RemoveStale()
	})

	lines := make(chan string, 8)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	timeout := time.After(30 * time.Second)
	for ready := false; !ready; {
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatal("дочерний процесс завершился, не поднявшись")
			}
			switch {
			case l == "HOLDING-ADAPTER":
				ready = true
			case len(l) >= 11 && l[:11] == "OPEN-FAILED":
				t.Fatalf("дочерний процесс: %s", l)
			}
		case <-timeout:
			t.Fatal("дочерний процесс не поднял адаптер за 30 с")
		}
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	cmd.Wait()
	killed = true

	_, err = net.InterfaceByName(AdapterName)
	t.Logf("адаптер после убитого процесса найден: %v (ошибка поиска: %v)", err == nil, err)

	if err := RemoveStale(); err != nil {
		t.Fatalf("RemoveStale: %v", err)
	}
	waitAdapterGone(t, "RemoveStale не убрал адаптер")
}
