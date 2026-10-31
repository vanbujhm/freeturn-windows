// Package statefile хранит файл состояния службы: признак «туннель нужен», настройки
// блокировки и время загрузки системы. Секретов в файле нет.
package statefile

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

// State - содержимое файла состояния.
type State struct {
	// Wanted: туннель нужен. Плановое отключение и завершение Windows его сбрасывают.
	Wanted bool
	// KillSwitch и AllowLAN повторяют настройки последнего подключения.
	KillSwitch, AllowLAN bool
	// BootUnix - время загрузки системы, секунды Unix, на момент записи.
	BootUnix int64
}

// Action - что делать службе после запуска.
type Action int

const (
	// ActionNone: туннель не нужен, делать нечего.
	ActionNone Action = iota
	// ActionRearm: вернуть блокировку сразу, не дожидаясь окна.
	ActionRearm
	// ActionAwaitProfile: ждать профиль от окна, блокировки нет.
	ActionAwaitProfile
	// ActionClear: загрузка другая, признак сбросить.
	ActionClear
)

// bootTolerance - на сколько секунд время загрузки может разойтись между двумя
// вычислениями, чтобы считаться той же загрузкой.
const bootTolerance = 60

// Decide выбирает действие по сохранённому состоянию и времени загрузки сейчас.
func Decide(s State, bootNow int64) Action {
	if !s.Wanted {
		return ActionNone
	}
	diff := bootNow - s.BootUnix
	if diff < 0 {
		diff = -diff
	}
	if diff > bootTolerance {
		// Питание отключали: признак от прошлой загрузки оставил бы человека без интернета.
		return ActionClear
	}
	if s.KillSwitch {
		return ActionRearm
	}
	return ActionAwaitProfile
}

// Load читает состояние. Нет файла или содержимое испорчено: нулевое состояние без
// ошибки, службе безопаснее считать, что туннель не нужен. Ошибку чтения отдаём.
func Load(path string) (State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, nil
	}
	return s, nil
}

// Save пишет состояние атомарно: временный файл в том же каталоге, затем rename.
// Каталог должен существовать, его права выставляет служба. При сбое временный файл
// удаляется.
func Save(path string, s State) (err error) {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// BootUnix возвращает время загрузки системы в секундах Unix.
func BootUnix() int64 {
	return time.Now().Add(-windows.DurationSinceBoot()).Unix()
}
