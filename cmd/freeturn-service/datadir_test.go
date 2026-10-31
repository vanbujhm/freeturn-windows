package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func junction(t *testing.T, link, target string) {
	t.Helper()
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		t.Fatalf("mklink: %v: %s", err, out)
	}
}

func TestDataDirSDDL(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString(dataDirSDDL)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Error("наследование прав не отключено")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl.AceCount != 2 {
		t.Fatalf("записей %d", dacl.AceCount)
	}
	const fileAll = 0x1F01FF
	want := []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid}
	for i, kind := range want {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsWellKnown(kind) || ace.Mask != fileAll {
			t.Errorf("запись %d: %s, маска %#x", i, sid, ace.Mask)
		}
		if ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) !=
			windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE {
			t.Errorf("запись %d не наследуется файлами и папками", i)
		}
	}
}

func TestDataPathsFor(t *testing.T) {
	p := dataPathsFor(`C:\Program Files`)
	want := dataPaths{
		app:   `C:\Program Files\FreeTurn`,
		root:  `C:\Program Files\FreeTurn\Data`,
		core:  `C:\Program Files\FreeTurn\Data\core`,
		logs:  `C:\Program Files\FreeTurn\Data\logs`,
		state: `C:\Program Files\FreeTurn\Data\state.json`,
		lock:  `C:\Program Files\FreeTurn\Data\service.lock`,
	}
	if p != want {
		t.Fatalf("пути %+v", p)
	}
}

// testSDDL - те же права, что у боевых, но владелец остаётся создателем: администраторов
// владельцем без повышения не назначить. Свою запись добавляем, чтобы тест мог убрать каталог.
func testSDDL(t *testing.T) string {
	t.Helper()
	token := windows.GetCurrentProcessToken()
	if token.IsElevated() {
		t.Skip("нужен запуск без повышения")
	}
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")"
}

func fileSD(t *testing.T, path string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd
}

// aces перечисляет записи прав каталога.
func aces(t *testing.T, path string) []string {
	t.Helper()
	return describeACEs(t, fileSD(t, path))
}

// wantProtected проверяет, что каталог не наследует права родителя.
func wantProtected(t *testing.T, path string) {
	t.Helper()
	sd := fileSD(t, path)
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("%s наследует права родителя: %s", path, sd)
	}
}

func describeACEs(t *testing.T, sd *windows.SECURITY_DESCRIPTOR) []string {
	t.Helper()
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		out = append(out, fmt.Sprintf("%s %#x %#x", sid, ace.Mask, ace.Header.AceFlags))
	}
	return out
}

func wantACEs(t *testing.T, sddl string) []string {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	return describeACEs(t, sd)
}

func TestPrepareDataDirFresh(t *testing.T) {
	sddl := testSDDL(t)
	base := t.TempDir()
	p, err := prepareDataDirIn(base, sddl)
	if err != nil {
		t.Fatal(err)
	}
	if p != dataPathsFor(base) {
		t.Fatalf("пути %+v", p)
	}
	wantProtected(t, p.root)
	if got, want := aces(t, p.root), wantACEs(t, sddl); !slices.Equal(got, want) {
		t.Fatalf("права %v, нужны %v", got, want)
	}
	for _, dir := range []string{p.core, p.logs} {
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			t.Errorf("%s: %v", dir, err)
		}
		// Вложенный каталог наследует права закрытого.
		if got, want := aces(t, dir), wantACEs(t, sddl); len(got) != len(want) {
			t.Errorf("%s: права %v", dir, got)
		}
	}
}

// Каталог на месте Data - ссылка: права не должны лечь на то, куда она указывает.
func TestPrepareDataDirRefusesReparsePoint(t *testing.T) {
	sddl := testSDDL(t)
	base := t.TempDir()
	target := filepath.Join(base, "чужой")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	before := aces(t, target)
	app := dataPathsFor(base).app
	if err := os.Mkdir(app, 0o755); err != nil {
		t.Fatal(err)
	}
	junction(t, filepath.Join(app, "Data"), target)

	if _, err := prepareDataDirIn(base, sddl); err == nil {
		t.Fatal("ссылка принята за каталог")
	}
	if after := aces(t, target); !slices.Equal(before, after) {
		t.Errorf("права цели изменены: было %v, стало %v", before, after)
	}
	if _, err := os.Stat(filepath.Join(target, "core")); err == nil {
		t.Error("в цель ссылки легли каталоги службы")
	}
}

func TestPrepareDataDirRefusesFile(t *testing.T) {
	sddl := testSDDL(t)
	base := t.TempDir()
	app := dataPathsFor(base).app
	if err := os.Mkdir(app, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Data"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareDataDirIn(base, sddl); err == nil {
		t.Fatal("файл принят за каталог")
	}
}

// Существующий каталог получает права заново, а его файлы остаются.
func TestPrepareDataDirResetsExisting(t *testing.T) {
	sddl := testSDDL(t)
	base := t.TempDir()
	p := dataPathsFor(base)
	if err := os.MkdirAll(p.root, 0o755); err != nil {
		t.Fatal(err)
	}
	state := p.state
	if err := os.WriteFile(state, []byte("данные"), 0o600); err != nil {
		t.Fatal(err)
	}
	open, err := windows.SecurityDescriptorFromString("D:(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := open.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(p.root, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if slices.Equal(aces(t, p.root), wantACEs(t, sddl)) {
		t.Fatal("исходные права уже совпадают с нужными")
	}

	if _, err := prepareDataDirIn(base, sddl); err != nil {
		t.Fatal(err)
	}
	wantProtected(t, p.root)
	if got, want := aces(t, p.root), wantACEs(t, sddl); !slices.Equal(got, want) {
		t.Fatalf("права %v, нужны %v", got, want)
	}
	if _, err := os.Stat(state); err != nil {
		t.Errorf("файл потерян: %v", err)
	}
}

func TestLockInstance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.lock")
	release, err := lockInstance(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockInstance(path); !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("второй экземпляр: %v", err)
	}
	release()
	// Файл остаётся после прошлого запуска и новому запуску не мешает.
	release, err = lockInstance(path)
	if err != nil {
		t.Fatalf("после освобождения: %v", err)
	}
	release()
}
