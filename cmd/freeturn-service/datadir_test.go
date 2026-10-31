package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

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

func TestDataDirOwner(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString(dataDirSDDL)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if !trustedOwner(owner) {
		t.Fatalf("каталог службы сам не прошёл бы проверку владельца: %s", owner)
	}
}

func TestDataPathsFor(t *testing.T) {
	p := dataPathsFor(`C:\ProgramData`)
	want := dataPaths{
		root:  `C:\ProgramData\FreeTurn`,
		core:  `C:\ProgramData\FreeTurn\core`,
		logs:  `C:\ProgramData\FreeTurn\logs`,
		state: `C:\ProgramData\FreeTurn\state.json`,
		lock:  `C:\ProgramData\FreeTurn\service.lock`,
	}
	if p != want {
		t.Fatalf("пути %+v", p)
	}
}

func TestTrustedOwner(t *testing.T) {
	for kind, want := range map[windows.WELL_KNOWN_SID_TYPE]bool{
		windows.WinLocalSystemSid:           true,
		windows.WinBuiltinAdministratorsSid: true,
		windows.WinBuiltinUsersSid:          false,
		windows.WinAuthenticatedUserSid:     false,
		windows.WinWorldSid:                 false,
	} {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			t.Fatal(err)
		}
		if got := trustedOwner(sid); got != want {
			t.Errorf("%s: %v", sid, got)
		}
	}
}

// testPolicy - правила каталога, которые работают без повышения: владельца O:BA обычный
// пользователь задать не может, поэтому он остаётся владельцем сам. trustUser делает его
// доверенным, иначе его каталог считается подброшенным.
func testPolicy(t *testing.T, trustUser bool) dirPolicy {
	t.Helper()
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if token.IsElevated() {
		t.Skip("нужен запуск без повышения: здесь владелец каталогов администраторы")
	}
	return dirPolicy{
		sddl: "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")",
		trusted: func(owner *windows.SID) bool {
			return trustUser && owner.Equals(user.User.Sid)
		},
	}
}

func userACE(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return "(A;OICI;FA;;;" + user.User.Sid.String() + ")"
}

// setDACL ставит каталогу свои права, как сделал бы тот, кто его подбросил.
func setDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	const info = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func junction(t *testing.T, link, target string) {
	t.Helper()
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		t.Fatalf("mklink: %v: %s", err, out)
	}
}

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("данные"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func wantExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err != nil {
		t.Errorf("должен остаться: %v", err)
	}
}

func wantGone(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s должен исчезнуть: %v", path, err)
	}
}

// wantProtected проверяет, что path настоящий каталог с закрытыми правами и наследования нет.
func wantProtected(t *testing.T, path string) {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !st.IsDir() {
		t.Fatalf("%s не каталог: %v", path, st.Mode())
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("%s наследует права родителя: %s", path, sd)
	}
}

// wantClean проверяет, что отодвинутой копии каталога не осталось ни рядом с ним, ни в рабочем
// каталоге процесса: переименование коротким именем уводило её туда.
func wantClean(t *testing.T, root string) {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{root + asideInfix + "*", filepath.Join(cwd, filepath.Base(root)+asideInfix+"*")} {
		left, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if len(left) != 0 {
			t.Errorf("остатки: %v", left)
		}
	}
}

// Объект должен остаться рядом: переименование коротким именем считалось от рабочего каталога,
// а os.RemoveAll потом молча принимал уже пустой путь.
func TestRenameBesideStaysInParent(t *testing.T) {
	base := t.TempDir()
	from := filepath.Join(base, "старое")
	if err := os.Mkdir(from, 0o700); err != nil {
		t.Fatal(err)
	}
	to := filepath.Join(base, "новое")
	if err := renameBeside(from, to); err != nil {
		t.Fatal(err)
	}
	wantExists(t, to)
	wantGone(t, from)
}

// Закрытый от всех объект всё равно отодвигается: хватает прав родителя.
func TestRenameBesideClosedObject(t *testing.T) {
	base := t.TempDir()
	from := filepath.Join(base, "закрытое")
	if err := os.Mkdir(from, 0o700); err != nil {
		t.Fatal(err)
	}
	to := filepath.Join(base, "отодвинутое")
	full := "D:P" + userACE(t)
	t.Cleanup(func() {
		for _, path := range []string{from, to} {
			if _, err := os.Lstat(path); err == nil {
				setDACL(t, path, full)
			}
		}
	})
	setDACL(t, from, "D:P")
	if err := renameBeside(from, to); err != nil {
		t.Fatal(err)
	}
	wantExists(t, to)
	wantGone(t, from)
}

func TestRenameBesideMissing(t *testing.T) {
	base := t.TempDir()
	if err := renameBeside(filepath.Join(base, "нет"), filepath.Join(base, "другое")); err == nil {
		t.Fatal("несуществующий объект переименован")
	}
}

func TestSecureFresh(t *testing.T) {
	root := filepath.Join(t.TempDir(), "FreeTurn")
	note, err := testPolicy(t, false).secure(root)
	if err != nil || note != "" {
		t.Fatalf("заметка %q, ошибка %v", note, err)
	}
	wantProtected(t, root)
}

// Ссылка на месте каталога убирается как ссылка: то, на что она указывает, не трогаем.
func TestSecureRootJunction(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "чужой")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(target, "важный.txt")
	writeFile(t, marker)
	root := filepath.Join(base, "FreeTurn")
	junction(t, root, target)

	note, err := testPolicy(t, true).secure(root)
	if err != nil {
		t.Fatal(err)
	}
	if note == "" {
		t.Error("подмена не отмечена")
	}
	wantProtected(t, root)
	wantExists(t, marker)
	wantGone(t, filepath.Join(root, "важный.txt"))
	wantClean(t, root)
}

func TestSecureFileAtRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "FreeTurn")
	writeFile(t, root)
	if _, err := testPolicy(t, true).secure(root); err != nil {
		t.Fatal(err)
	}
	wantProtected(t, root)
	wantClean(t, root)
}

// Подброшенный каталог уходит целиком: вложенная папка со своими закрытыми правами осталась бы
// под управлением пользователя, а его state.json служба прочла бы как свой.
func TestSecurePlantedTree(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "снаружи")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(outside, "важный.txt")
	writeFile(t, marker)

	root := filepath.Join(base, "FreeTurn")
	logs := filepath.Join(root, "logs")
	if err := os.MkdirAll(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "state.json")
	writeFile(t, state)
	writeFile(t, filepath.Join(logs, "service.log"))
	setDACL(t, logs, "D:P"+userACE(t))
	junction(t, filepath.Join(root, "core"), outside)

	note, err := testPolicy(t, false).secure(root)
	if err != nil {
		t.Fatal(err)
	}
	if note == "" {
		t.Error("подмена не отмечена")
	}
	wantProtected(t, root)
	wantGone(t, logs)
	wantGone(t, state)
	wantGone(t, filepath.Join(root, "core"))
	wantExists(t, marker)
	wantClean(t, root)
}

// Закрыв свой каталог от всех, пользователь не должен останавливать службу: удалить его нельзя,
// но место освобождается, а остаток безвреден и назван в заметке.
func TestSecureDeniedTreeMovesAside(t *testing.T) {
	root := filepath.Join(t.TempDir(), "FreeTurn")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "state.json"))
	full := "D:P" + userACE(t)
	t.Cleanup(func() {
		left, _ := filepath.Glob(root + asideInfix + "*")
		for _, dir := range left {
			setDACL(t, dir, full)
		}
	})
	setDACL(t, root, "D:P")

	note, err := testPolicy(t, false).secure(root)
	if err != nil {
		t.Fatal(err)
	}
	wantProtected(t, root)
	wantGone(t, filepath.Join(root, "state.json"))
	left, err := filepath.Glob(root + asideInfix + "*")
	if err != nil || len(left) != 1 {
		t.Fatalf("остатки %v, ошибка %v", left, err)
	}
	if !strings.Contains(note, left[0]) {
		t.Errorf("остаток не назван: %q", note)
	}
}

// Свой каталог только получает права заново, файлы службы в нём остаются.
func TestSecureTrustedKeepsContents(t *testing.T) {
	root := filepath.Join(t.TempDir(), "FreeTurn")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "state.json")
	writeFile(t, state)
	note, err := testPolicy(t, true).secure(root)
	if err != nil || note != "" {
		t.Fatalf("заметка %q, ошибка %v", note, err)
	}
	wantProtected(t, root)
	wantExists(t, state)
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
