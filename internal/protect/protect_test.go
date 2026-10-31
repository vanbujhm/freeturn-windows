package protect

import (
	"testing"

	"github.com/samosvalishe/free-turn-proxy/mobile"
	"golang.org/x/sys/windows"
)

// Проверка на этапе компиляции: Protector реализует интерфейс ядра.
var _ mobile.Protector = (*Protector)(nil)

// mustSocket создаёт сокет заданного семейства и закрывает его по окончании теста.
func mustSocket(t *testing.T, family int) windows.Handle {
	t.Helper()
	// Winsock нужно инициализировать явно: пакет net делает это лениво.
	var data windows.WSAData
	if err := windows.WSAStartup(0x0202, &data); err != nil {
		t.Fatalf("WSAStartup: %v", err)
	}
	t.Cleanup(func() { _ = windows.WSACleanup() })
	s, err := windows.Socket(family, windows.SOCK_DGRAM, windows.IPPROTO_UDP)
	if err != nil {
		t.Fatalf("socket(%d): %v", family, err)
	}
	t.Cleanup(func() { _ = windows.Closesocket(s) })
	return s
}

func TestEncodeIndex4IsNetworkOrder(t *testing.T) {
	if got := encodeIndex4(7); got != 0x07000000 {
		t.Fatalf("%#x", got)
	}
}

func TestProtectWithoutInterfaceFails(t *testing.T) {
	p := New()
	if p.Protect(int(mustSocket(t, windows.AF_INET))) {
		t.Fatal("должен отказать без интерфейса")
	}
}

func TestProtectIPv4Socket(t *testing.T) {
	p := New()
	p.SetInterface(1, 1)
	if !p.Protect(int(mustSocket(t, windows.AF_INET))) {
		t.Fatal("IPv4")
	}
}

func TestProtectIPv6Socket(t *testing.T) {
	p := New()
	p.SetInterface(1, 1)
	if !p.Protect(int(mustSocket(t, windows.AF_INET6))) {
		t.Fatal("IPv6")
	}
}
