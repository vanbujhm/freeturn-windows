package main

import (
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

func TestAutostartCommandQuotesPath(t *testing.T) {
	got := autostartCommand(`C:\Program Files\FreeTurn\FreeTurn.exe`)
	want := `"C:\Program Files\FreeTurn\FreeTurn.exe" --tray`
	if got != want {
		t.Fatalf("получили %s", got)
	}
}

func TestHasTrayFlag(t *testing.T) {
	if !hasTrayFlag([]string{"--tray"}) || hasTrayFlag([]string{"freeturn://x"}) || hasTrayFlag(nil) {
		t.Fatal("разбор --tray")
	}
}

// Тест пишет в свой временный раздел HKCU, а не в настоящий автозапуск, и удаляет его.
func TestSetAutostartAtRoundTrip(t *testing.T) {
	keyPath := fmt.Sprintf(`Software\FreeTurnTest-%d`, time.Now().UnixNano())
	t.Cleanup(func() { registry.DeleteKey(registry.CURRENT_USER, keyPath) })
	const name, cmd = "FreeTurn", `"C:\Program Files\FreeTurn\FreeTurn.exe" --tray`

	if err := setAutostartAt(keyPath, name, cmd, true); err != nil {
		t.Fatal(err)
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if got, _, err := k.GetStringValue(name); err != nil || got != cmd {
		t.Fatalf("значение %q, %v", got, err)
	}
	if err := setAutostartAt(keyPath, name, cmd, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := k.GetStringValue(name); err == nil {
		t.Fatal("значение осталось после выключения")
	}
	if err := setAutostartAt(keyPath, name, cmd, false); err != nil {
		t.Fatalf("повторное выключение: %v", err)
	}
}
