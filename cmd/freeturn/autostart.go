package main

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"golang.org/x/sys/windows/registry"
)

const (
	// runKeyPath - раздел автозапуска текущего пользователя.
	runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
	// runValueName - имя значения программы в этом разделе.
	runValueName = "FreeTurn"
	// trayFlag - аргумент запуска: окно скрыто, пока туннель не требует внимания.
	trayFlag = "--tray"
)

// autostartCommand возвращает строку запуска. Путь в кавычках: в Program Files есть пробел,
// без кавычек Windows запустила бы другой файл.
func autostartCommand(exe string) string {
	return `"` + exe + `" ` + trayFlag
}

// setAutostart включает или выключает запуск текущего exe при входе в Windows.
func setAutostart(enabled bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return setAutostartAt(runKeyPath, runValueName, autostartCommand(exe), enabled)
}

// setAutostartAt пишет или удаляет значение name в разделе HKCU\keyPath. Путь вынесен
// параметром, чтобы тест не трогал настоящий автозапуск.
func setAutostartAt(keyPath, name, command string, enabled bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("автозапуск: %w", err)
	}
	defer k.Close()
	if enabled {
		return k.SetStringValue(name, command)
	}
	if err := k.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("автозапуск: %w", err)
	}
	return nil
}

// hasTrayFlag сообщает, запущена ли программа с --tray.
func hasTrayFlag(args []string) bool {
	return slices.Contains(args, trayFlag)
}
