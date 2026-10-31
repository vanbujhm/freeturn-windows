// Package profile хранит профили подключения под DPAPI и настройки окна.
// Работает в процессе окна, не службы.
package profile

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// ErrCorrupt: файл профилей нельзя прочитать (повреждён, пустой или зашифрован другим
// пользователем). Файл не перезаписывается, пока вызывающий не выполнит Reset.
var ErrCorrupt = errors.New("файл профилей повреждён")

const (
	// renameAttempts и renameDelay: на Windows переименование может не пройти, пока
	// антивирус или другой процесс держит файл-приёмник открытым.
	renameAttempts = 5
	renameDelay    = 50 * time.Millisecond
)

// Store - хранилище профилей. Безопасно для вызовов из нескольких горутин.
type Store struct {
	mu       sync.Mutex
	path     string
	profiles []model.Profile
	corrupt  bool
}

// Open читает файл профилей. Нет файла: пустое хранилище. Нечитаемый файл: ErrCorrupt и
// пустое хранилище, в котором Save и Delete отказывают до Reset.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: path}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	profiles, err := decode(raw)
	if err != nil {
		s.corrupt = true
		return s, ErrCorrupt
	}
	s.profiles = profiles
	return s, nil
}

func decode(raw []byte) ([]model.Profile, error) {
	plain, err := unprotect(raw)
	if err != nil {
		return nil, err
	}
	var profiles []model.Profile
	if err := json.Unmarshal(plain, &profiles); err != nil {
		return nil, err
	}
	return profiles, nil
}

// List возвращает копию списка профилей.
func (s *Store) List() []model.Profile {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneAll(s.profiles)
}

// Get возвращает копию профиля по ID.
func (s *Store) Get(id string) (model.Profile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.profiles {
		if p.ID == id {
			return clone(p), true
		}
	}
	return model.Profile{}, false
}

// Save добавляет профиль или заменяет профиль с тем же ID. Пустой ID заменяется новым.
// Возвращает профиль в том виде, в каком он сохранён, с ID. Если запись на диск не
// удалась, список в памяти не меняется.
func (s *Store) Save(p model.Profile) (model.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.corrupt {
		return model.Profile{}, ErrCorrupt
	}
	if p.ID == "" {
		id, err := newID()
		if err != nil {
			return model.Profile{}, err
		}
		p.ID = id
	}
	next := cloneAll(s.profiles)
	if i := slices.IndexFunc(next, func(q model.Profile) bool { return q.ID == p.ID }); i >= 0 {
		next[i] = clone(p)
	} else {
		next = append(next, clone(p))
	}
	if err := s.commit(next); err != nil {
		return model.Profile{}, err
	}
	return clone(p), nil
}

// Delete удаляет профиль. Профиля с таким ID нет: не ошибка.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.corrupt {
		return ErrCorrupt
	}
	next := slices.DeleteFunc(cloneAll(s.profiles), func(q model.Profile) bool { return q.ID == id })
	if len(next) == len(s.profiles) {
		return nil
	}
	return s.commit(next)
}

// Reset убирает повреждённый файл в profiles.dat.bad, заменяя прежний .bad, и возвращает
// хранилищу возможность записи. У исправного хранилища ничего не делает.
func (s *Store) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.corrupt {
		return nil
	}
	err := renameRetry(s.path, s.path+".bad")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	s.corrupt = false
	s.profiles = nil
	return nil
}

// commit пишет список на диск и только после успеха принимает его в памяти.
func (s *Store) commit(next []model.Profile) error {
	plain, err := json.Marshal(next)
	if err != nil {
		return err
	}
	enc, err := protect(plain)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.path, enc); err != nil {
		return err
	}
	s.profiles = next
	return nil
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func clone(p model.Profile) model.Profile {
	p.DNSServers = slices.Clone(p.DNSServers)
	return p
}

func cloneAll(ps []model.Profile) []model.Profile {
	out := make([]model.Profile, len(ps))
	for i, p := range ps {
		out[i] = clone(p)
	}
	return out
}

// writeFileAtomic пишет во временный файл рядом и переименовывает его поверх path:
// при сбое прежний файл остаётся целым.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = renameRetry(tmpName, path)
	}
	if err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("запись %s: %w", filepath.Base(path), err)
	}
	return nil
}

// renameRetry повторяет переименование, пока файл-приёмник занят другим процессом.
func renameRetry(from, to string) error {
	var err error
	for i := 0; i < renameAttempts; i++ {
		if i > 0 {
			time.Sleep(renameDelay)
		}
		if err = os.Rename(from, to); err == nil || errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return err
}
