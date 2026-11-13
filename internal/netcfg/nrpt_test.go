package netcfg

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestNRPTKeyName(t *testing.T) {
	name, err := newNRPTKeyName()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, nrptPrefix) || !strings.HasSuffix(name, "}") {
		t.Fatalf("имя ключа %q", name)
	}
	guid := "{" + strings.TrimPrefix(name, nrptPrefix)
	if _, err := windows.GUIDFromString(guid); err != nil {
		t.Fatalf("в имени %q не GUID: %v", name, err)
	}
	if !ownNRPTKey(name) {
		t.Fatalf("своё имя %q не узнаётся", name)
	}
}

func TestRemoveNRPTKeyRejectsForeign(t *testing.T) {
	for _, name := range []string{`{Other-1}`, `..\x`, `{FreeTurn-x}\..\{Other}`, ``, `{FreeTurn-}`} {
		if ownNRPTKey(name) {
			t.Errorf("чужое имя %q принято за своё", name)
		}
		if err := RemoveNRPTKey(name); err == nil {
			t.Errorf("RemoveNRPTKey(%q) без ошибки", name)
		}
	}
}
