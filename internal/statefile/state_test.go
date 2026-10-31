package statefile

import (
	"os"
	"path/filepath"
	"testing"
)

const boot = int64(1_800_000_000)

func TestDecideRearm(t *testing.T) {
	s := State{Wanted: true, KillSwitch: true, BootUnix: boot}
	if got := Decide(s, boot); got != ActionRearm {
		t.Errorf("got %v", got)
	}
}

func TestDecideAwaitProfile(t *testing.T) {
	s := State{Wanted: true, BootUnix: boot}
	if got := Decide(s, boot); got != ActionAwaitProfile {
		t.Errorf("got %v", got)
	}
}

func TestDecideOtherBoot(t *testing.T) {
	s := State{Wanted: true, KillSwitch: true, BootUnix: boot}
	for _, now := range []int64{boot + 61, boot - 61, boot + 3600} {
		if got := Decide(s, now); got != ActionClear {
			t.Errorf("now=%d: got %v", now, got)
		}
	}
}

func TestDecideBootJitter(t *testing.T) {
	s := State{Wanted: true, KillSwitch: true, BootUnix: boot}
	for _, now := range []int64{boot + 30, boot - 30, boot + 60, boot - 60} {
		if got := Decide(s, now); got != ActionRearm {
			t.Errorf("now=%d: got %v", now, got)
		}
	}
}

func TestDecideNotWanted(t *testing.T) {
	// Без признака загрузка не важна: сбрасывать нечего.
	for _, now := range []int64{boot, boot + 3600} {
		s := State{KillSwitch: true, BootUnix: boot}
		if got := Decide(s, now); got != ActionNone {
			t.Errorf("now=%d: got %v", now, got)
		}
	}
}

func TestLoadMissingFile(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "state.json"))
	if err != nil || s != (State{}) {
		t.Errorf("got %+v, %v", s, err)
	}
}

func TestLoadCorrupt(t *testing.T) {
	for _, body := range []string{"\x00\x01garbage", "{", `{"Wanted":"yes"}`, ""} {
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := Load(path)
		if err != nil || s != (State{}) {
			t.Errorf("body %q: got %+v, %v", body, s, err)
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	want := State{Wanted: true, KillSwitch: true, AllowLAN: true, BootUnix: boot}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || got != want {
		t.Fatalf("got %+v, %v", got, err)
	}
	// Повторная запись заменяет файл.
	want.Wanted = false
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	if got, _ := Load(path); got != want {
		t.Errorf("got %+v", got)
	}
}

func TestSaveLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := Save(path, State{Wanted: true}); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Errorf("в каталоге лишнее: %v", entries)
	}
}

func TestSaveFailureLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	// Целевой путь занят каталогом: rename не сможет его заменить.
	path := filepath.Join(dir, "state.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, State{Wanted: true}); err == nil {
		t.Fatal("ожидалась ошибка")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("временный файл остался: %v", entries)
	}
}

func TestSaveMissingDirFails(t *testing.T) {
	if err := Save(filepath.Join(t.TempDir(), "no", "state.json"), State{}); err == nil {
		t.Fatal("ожидалась ошибка")
	}
}

func TestBootUnixPlausible(t *testing.T) {
	b := BootUnix()
	if b <= 1_600_000_000 {
		t.Errorf("BootUnix=%d", b)
	}
	if d := BootUnix() - b; d < -2 || d > 2 {
		t.Errorf("BootUnix нестабилен: %d", d)
	}
}
