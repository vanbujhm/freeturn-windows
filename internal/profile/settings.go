package profile

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// Settings - настройки окна. Секретов нет, файл открытый JSON.
type Settings struct {
	Options                    model.Options
	Autostart, ConnectOnLaunch bool
	LastProfileID              string
}

func defaultSettings() Settings {
	return Settings{
		Options:   model.Options{KillSwitch: true, AllowLAN: true},
		Autostart: true,
	}
}

// LoadSettings читает настройки. Нет файла или файл нечитаем: значения по умолчанию без
// ошибки, следующий SaveSettings перезапишет мусор. Поля, которых нет в JSON, остаются
// по умолчанию. Ошибка только если файл существует, но его не удалось прочитать.
func LoadSettings(path string) (Settings, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return defaultSettings(), nil
	}
	if err != nil {
		return defaultSettings(), err
	}
	s := defaultSettings()
	if err := json.Unmarshal(raw, &s); err != nil {
		return defaultSettings(), nil
	}
	return s, nil
}

// SaveSettings записывает настройки атомарно.
func SaveSettings(path string, s Settings) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, raw)
}
