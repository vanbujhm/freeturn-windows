package profile

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// Ключи в тестах только сгенерированные: base64 от 32 одинаковых байт.
const (
	testObfKey   = "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI="
	testWGConfig = "[Interface]\nPrivateKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=\nAddress = 203.0.113.2/32\n"
)

func testProfile(name string) model.Profile {
	return model.Profile{
		Name:       name,
		Provider:   "vk",
		ObfKey:     testObfKey,
		WGConfig:   testWGConfig,
		DNSServers: []string{"198.51.100.1"},
		Threads:    4,
	}
}

func storePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "profiles.dat")
}

func mustOpen(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestProtectRoundTrip(t *testing.T) {
	plain := []byte("секретная строка " + testObfKey)
	enc, err := protect(plain)
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	if bytes.Contains(enc, []byte(testObfKey)) || bytes.Contains(enc, []byte("секретная")) {
		t.Fatal("зашифрованные байты содержат исходную строку")
	}
	dec, err := unprotect(enc)
	if err != nil {
		t.Fatalf("unprotect: %v", err)
	}
	if !bytes.Equal(dec, plain) {
		t.Fatalf("получили %q", dec)
	}
}

func TestUnprotectGarbage(t *testing.T) {
	if _, err := unprotect([]byte("это не DPAPI")); err == nil {
		t.Fatal("ожидалась ошибка")
	}
}

func TestStoreSaveAndReopen(t *testing.T) {
	path := storePath(t)
	s := mustOpen(t, path)
	p := testProfile("Домашний сервер")
	p.ID = "abc"
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}

	s2 := mustOpen(t, path)
	got, ok := s2.Get("abc")
	if !ok {
		t.Fatal("профиль не найден после повторного Open")
	}
	if !reflect.DeepEqual(got, p) {
		t.Fatalf("got %+v, want %+v", got, p)
	}
	if l := s2.List(); len(l) != 1 || l[0].Name != "Домашний сервер" {
		t.Fatalf("List: %+v", l)
	}
}

func TestStoreMissingFileIsEmpty(t *testing.T) {
	s := mustOpen(t, storePath(t))
	if l := s.List(); len(l) != 0 {
		t.Fatalf("List: %+v", l)
	}
	if _, ok := s.Get("x"); ok {
		t.Fatal("Get нашёл несуществующий профиль")
	}
}

func TestStoreOpenCreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "profiles.dat")
	s := mustOpen(t, path)
	if err := s.Save(testProfile("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestStoreSaveGeneratesID(t *testing.T) {
	s := mustOpen(t, storePath(t))
	if err := s.Save(testProfile("one")); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(testProfile("two")); err != nil {
		t.Fatal(err)
	}
	l := s.List()
	if len(l) != 2 {
		t.Fatalf("List: %+v", l)
	}
	for _, p := range l {
		if len(p.ID) != 32 || strings.Trim(p.ID, "0123456789abcdef") != "" {
			t.Errorf("ID %q не похож на 16 байт в hex", p.ID)
		}
	}
	if l[0].ID == l[1].ID {
		t.Error("ID совпали")
	}
}

func TestStoreSaveReplacesSameID(t *testing.T) {
	s := mustOpen(t, storePath(t))
	p := testProfile("old")
	p.ID = "id1"
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	p.Name = "new"
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	l := s.List()
	if len(l) != 1 || l[0].Name != "new" {
		t.Fatalf("List: %+v", l)
	}
}

func TestStoreDelete(t *testing.T) {
	path := storePath(t)
	s := mustOpen(t, path)
	a, b := testProfile("a"), testProfile("b")
	a.ID, b.ID = "a", "b"
	for _, p := range []model.Profile{a, b} {
		if err := s.Save(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Delete("a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("нет такого"); err != nil {
		t.Fatalf("удаление несуществующего: %v", err)
	}
	s2 := mustOpen(t, path)
	if l := s2.List(); len(l) != 1 || l[0].ID != "b" {
		t.Fatalf("List: %+v", l)
	}
}

func TestStoreListIsACopy(t *testing.T) {
	s := mustOpen(t, storePath(t))
	p := testProfile("x")
	p.ID = "x"
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	s.List()[0].DNSServers[0] = "испорчено"
	got, _ := s.Get("x")
	got.DNSServers[0] = "испорчено"
	if again, _ := s.Get("x"); again.DNSServers[0] != "198.51.100.1" {
		t.Fatalf("хранилище изменилось снаружи: %v", again.DNSServers)
	}
}

func TestStoreFileHasNoSecrets(t *testing.T) {
	path := storePath(t)
	s := mustOpen(t, path)
	if err := s.Save(testProfile("Профиль")); err != nil {
		t.Fatal(err)
	}
	raw := readFile(t, path)
	for _, secret := range []string{testObfKey, "PrivateKey", "[Interface]", "Профиль"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("файл содержит %q", secret)
		}
	}
}

func corruptFile(t *testing.T, path string) []byte {
	t.Helper()
	junk := make([]byte, 300)
	if _, err := rand.Read(junk); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, junk, 0o600); err != nil {
		t.Fatal(err)
	}
	return junk
}

func TestStoreCorruptFile(t *testing.T) {
	path := storePath(t)
	junk := corruptFile(t, path)

	s, err := Open(path)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open: %v", err)
	}
	if s == nil {
		t.Fatal("Store должен быть непустым указателем")
	}
	if l := s.List(); len(l) != 0 {
		t.Fatalf("List: %+v", l)
	}
	if err := s.Save(testProfile("x")); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Save: %v", err)
	}
	if err := s.Delete("x"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Delete: %v", err)
	}
	if !bytes.Equal(readFile(t, path), junk) {
		t.Fatal("файл на диске изменился")
	}
}

func TestStoreValidDPAPIButNotJSON(t *testing.T) {
	path := storePath(t)
	enc, err := protect([]byte("не JSON"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, enc, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open: %v", err)
	}
}

func TestStoreEmptyFile(t *testing.T) {
	path := storePath(t)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Save(testProfile("x")); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Save: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() != 0 {
		t.Fatalf("файл изменился: %v %v", fi, err)
	}
}

func TestStoreReset(t *testing.T) {
	path := storePath(t)
	junk := corruptFile(t, path)
	s, err := Open(path)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, path+".bad"), junk) {
		t.Fatal("profiles.dat.bad не содержит старый файл")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("profiles.dat остался: %v", err)
	}
	if err := s.Save(testProfile("после сброса")); err != nil {
		t.Fatal(err)
	}
	if l := mustOpen(t, path).List(); len(l) != 1 {
		t.Fatalf("List: %+v", l)
	}
}

func TestStoreResetReplacesOlderBad(t *testing.T) {
	path := storePath(t)
	if err := os.WriteFile(path+".bad", []byte("старый"), 0o600); err != nil {
		t.Fatal(err)
	}
	junk := corruptFile(t, path)
	s, _ := Open(path)
	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, path+".bad"), junk) {
		t.Fatal("старый .bad не заменён")
	}
}

func TestStoreResetOnHealthyStoreKeepsData(t *testing.T) {
	path := storePath(t)
	s := mustOpen(t, path)
	if err := s.Save(testProfile("x")); err != nil {
		t.Fatal(err)
	}
	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".bad"); !os.IsNotExist(err) {
		t.Fatalf(".bad появился у здорового хранилища: %v", err)
	}
	if len(s.List()) != 1 {
		t.Fatal("профиль пропал")
	}
}

// Сбой записи не должен портить прошлый файл. Сбой даёт открытый файл: Go открывает без
// FILE_SHARE_DELETE, и переименование поверх него не проходит.
func TestStoreAtomicWrite(t *testing.T) {
	path := storePath(t)
	s := mustOpen(t, path)
	p := testProfile("до")
	p.ID = "keep"
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, path)

	holder, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	p2 := testProfile("после")
	p2.ID = "new"
	err = s.Save(p2)
	holder.Close()
	if err == nil {
		t.Fatal("Save поверх занятого файла должен вернуть ошибку")
	}
	if !bytes.Equal(readFile(t, path), before) {
		t.Fatal("прошлый файл изменился")
	}
	if l := s.List(); len(l) != 1 || l[0].ID != "keep" {
		t.Fatalf("память разошлась с диском: %+v", l)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("остался временный файл: %v", entries)
	}
	// Когда файл свободен, запись проходит.
	if err := s.Save(p2); err != nil {
		t.Fatal(err)
	}
	if len(mustOpen(t, path).List()) != 2 {
		t.Fatal("после освобождения файла запись не прошла")
	}
}

func TestStoreConcurrentSave(t *testing.T) {
	path := storePath(t)
	s := mustOpen(t, path)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := testProfile(fmt.Sprint("p", i))
			if err := s.Save(p); err != nil {
				t.Error(err)
			}
			s.List()
		}()
	}
	wg.Wait()
	if n := len(mustOpen(t, path).List()); n != 8 {
		t.Fatalf("на диске %d профилей", n)
	}
}

func TestDefaults(t *testing.T) {
	s, err := LoadSettings(filepath.Join(t.TempDir(), "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Options.KillSwitch || !s.Options.AllowLAN || !s.Autostart {
		t.Fatalf("значения по умолчанию: %+v", s)
	}
	if s.ConnectOnLaunch || s.LastProfileID != "" || len(s.Options.Rules) != 0 {
		t.Fatalf("лишнее в значениях по умолчанию: %+v", s)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "settings.json")
	want := Settings{
		Options: model.Options{
			KillSwitch: false,
			AllowLAN:   false,
			Rules:      []model.Rule{{Kind: model.RuleSubnet, Value: "198.51.100.0/24"}},
		},
		Autostart:       false,
		ConnectOnLaunch: true,
		LastProfileID:   "abc",
	}
	if err := SaveSettings(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestSettingsOmittedFieldKeepsDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"LastProfileID":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Options.KillSwitch || !s.Options.AllowLAN || !s.Autostart || s.LastProfileID != "x" {
		t.Fatalf("got %+v", s)
	}
}

func TestSettingsCorruptGivesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	for _, content := range []string{"\x00\xff мусор", `{"Autostart": "да"}`, ""} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := LoadSettings(path)
		if err != nil {
			t.Fatalf("%q: %v", content, err)
		}
		if !s.Options.KillSwitch || !s.Options.AllowLAN || !s.Autostart {
			t.Fatalf("%q: %+v", content, s)
		}
	}
}

func TestSettingsFileHasNoSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := SaveSettings(path, defaultSettings()); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(readFile(t, path), []byte("PrivateKey")) {
		t.Fatal("в настройках секреты")
	}
}
