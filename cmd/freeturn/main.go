// FreeTurn - окно, трей и профили. Туннель держит служба FreeTurnService, окно только
// управляет ею по именованному каналу.
//
// Аргументы:
//
//	--tray             окно при запуске скрыто, кроме состояния «Интернет заблокирован»
//	freeturn://...     ссылка на импорт профиля; запущенному окну её передаёт второй запуск
//
// Переменная окружения FREETURN_DEV_CONSOLE=1 для разработки: окно не проверяет владельца
// канала и не пишет себя в автозапуск. Так можно проверить окно со службой, запущенной
// командой console, без установки. В обычном запуске канал обязан принадлежать LocalSystem.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"golang.org/x/sys/windows"

	"github.com/vanbujhm/freeturn-windows/frontend"
	"github.com/vanbujhm/freeturn-windows/internal/ipc"
	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/profile"
)

const (
	appName       = "FreeTurn"
	instanceID    = "com.freeturn.windows"
	devConsoleEnv = "FREETURN_DEV_CONSOLE"
	linkScheme    = "freeturn://"

	dialTimeout = 2 * time.Second
	// quitDisconnectLimit - сколько «Выход» ждёт отключения туннеля, потом выходит всё равно.
	quitDisconnectLimit = 10 * time.Second

	windowWidth, windowHeight = 420, 640
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fatal(err.Error())
	}
}

// fatal показывает окно сообщения и завершает программу: окна приложения ещё нет.
func fatal(msg string) {
	text, _ := windows.UTF16PtrFromString(msg)
	title, _ := windows.UTF16PtrFromString(appName)
	windows.MessageBox(0, text, title, windows.MB_OK|windows.MB_ICONERROR)
	os.Exit(1)
}

// dataDir возвращает %LOCALAPPDATA%\FreeTurn.
func dataDir() (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return "", errors.New("не задана папка LOCALAPPDATA")
	}
	return filepath.Join(base, appName), nil
}

// desktopDir возвращает рабочий стол пользователя, с учётом переноса в OneDrive.
func desktopDir() (string, error) {
	if dir, err := windows.KnownFolderPath(windows.FOLDERID_Desktop, 0); err == nil && dir != "" {
		return dir, nil
	}
	home := os.Getenv("USERPROFILE")
	if home == "" {
		return "", errors.New("не задана папка USERPROFILE")
	}
	return filepath.Join(home, "Desktop"), nil
}

// linkArg ищет среди аргументов ссылку freeturn://. Windows передаёт её обработчику схемы
// одним аргументом, возможно с кавычками.
func linkArg(args []string) string {
	for _, a := range args {
		a = strings.Trim(strings.TrimSpace(a), `"`)
		if len(a) >= len(linkScheme) && strings.EqualFold(a[:len(linkScheme)], linkScheme) {
			return a
		}
	}
	return ""
}

// marshalError отдаёт интерфейсу ошибки API как JSON с кодом.
func marshalError(err error) []byte {
	var ae *Error
	if !errors.As(err, &ae) {
		return nil
	}
	b, jerr := json.Marshal(ae)
	if jerr != nil {
		return nil
	}
	return b
}

func run(args []string) error {
	dev := os.Getenv(devConsoleEnv) == "1"
	trayMode := hasTrayFlag(args)

	dir, err := dataDir()
	if err != nil {
		return err
	}
	// Повреждённый файл профилей не мешает запуску: Store остаётся читаемым и пустым,
	// окно предложит ResetProfiles. Любая другая ошибка Open фатальна.
	store, err := profile.Open(filepath.Join(dir, "profiles.dat"))
	corrupt := errors.Is(err, profile.ErrCorrupt)
	if err != nil && !corrupt {
		return fmt.Errorf("Не удалось открыть профили: %w", err)
	}
	settingsPath := filepath.Join(dir, "settings.json")
	settings, err := profile.LoadSettings(settingsPath)
	if err != nil {
		return fmt.Errorf("Не удалось прочитать настройки: %w", err)
	}

	var owner *windows.SID
	if !dev {
		if owner, err = ipc.ServiceOwner(); err != nil {
			return fmt.Errorf("Не удалось определить владельца канала службы: %w", err)
		}
	}
	// Запись в автозапуск следует настройке, по умолчанию она включена. Сборка для
	// разработки себя в автозапуск не пишет.
	if !dev {
		if err := setAutostart(settings.Autostart); err != nil {
			return fmt.Errorf("Не удалось обновить автозапуск: %w", err)
		}
	}

	var (
		app      *application.App
		win      *application.WebviewWindow
		tr       *tray
		api      *API
		quitting atomic.Bool
		quitOnce sync.Once
	)
	emit := func(name string, data ...any) {
		if app != nil {
			app.Event.Emit(name, data...)
		}
	}
	showWindow := func() {
		win.Show()
		win.UnMinimise()
		win.Focus()
	}

	sup := newSupervisor(
		func(onEvent func(ipc.Event)) (serviceConn, error) {
			c, err := ipc.Dial(ipc.PipePath, dialTimeout, owner, onEvent)
			if err != nil {
				return nil, err
			}
			return c, nil
		},
		func(ev ipc.Event) {
			switch ev.Kind {
			case ipc.KindStatus:
				if ev.Status != nil {
					emit(eventStatus, *ev.Status)
					tr.SetPhase(ev.Status.Phase)
				}
			case ipc.KindLog:
				emit(eventLog, ev.Log)
			}
		},
		func() {
			emit(eventServiceDown)
			tr.SetDown()
		},
		func(st model.Status, first bool) {
			tr.SetPhase(st.Phase)
			api.onServiceUp(st, first)
			if first && trayMode && st.Phase == model.PhaseBlocked {
				showWindow()
			}
		},
	)

	api = newAPI(apiDeps{
		Service:      sup,
		Store:        store,
		Corrupt:      corrupt,
		Settings:     settings,
		SettingsPath: settingsPath,
		Emit:         emit,
		SetAutostart: func(on bool) error {
			if dev {
				return nil
			}
			return setAutostart(on)
		},
		DesktopDir: desktopDir,
		OpenURL:    func(u string) error { return app.Browser.OpenURL(u) },
	})

	// handleLinkArg разбирает ссылку из аргументов и сообщает окну. Отказ показывается
	// сообщением: окно может быть не готово принять событие.
	handleLinkArg := func(args []string) {
		raw := linkArg(args)
		if raw == "" {
			return
		}
		if err := api.handleLink(raw); err != nil {
			app.Dialog.Error().SetTitle(appName).SetMessage(err.Error()).Show()
		}
	}

	app = application.New(application.Options{
		Name:         appName,
		Services:     []application.Service{application.NewService(api)},
		MarshalError: marshalError,
		Assets: application.AssetOptions{
			Handler: application.BundledAssetFileServer(frontend.Assets),
		},
		Windows: application.WindowsOptions{DisableQuitOnLastWindowClosed: true},
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: instanceID,
			OnSecondInstanceLaunch: func(d application.SecondInstanceData) {
				showWindow()
				handleLinkArg(d.Args)
			},
		},
		OnShutdown: sup.Stop,
	})

	win = app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:   "main",
		Title:  appName,
		URL:    "/",
		Width:  windowWidth,
		Height: windowHeight,
		Hidden: trayMode,
	})
	// Крестик сворачивает в трей, туннель продолжает работать. При выходе окно закрывается.
	win.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		if quitting.Load() {
			return
		}
		win.Hide()
		e.Cancel()
	})

	quit := func() {
		quitOnce.Do(func() {
			go func() {
				// Плановый выход отключает туннель, но не зависает на службе, которая молчит.
				done := make(chan struct{})
				go func() {
					_ = sup.Disconnect()
					close(done)
				}()
				select {
				case <-done:
				case <-time.After(quitDisconnectLimit):
				}
				quitting.Store(true)
				app.Quit()
			}()
		})
	}

	tr = newTray(app, trayActions{
		Open: showWindow,
		Quit: quit,
		Toggle: func() {
			go func() {
				if tr.offersDisconnect() {
					if err := api.Disconnect(); err != nil {
						emit(eventLog, "не удалось отключить: "+err.Error())
					}
					return
				}
				id := api.Settings().LastProfileID
				if id == "" {
					showWindow() // профиль ещё не выбирали
					return
				}
				if err := api.Connect(id); err != nil {
					emit(eventLog, "не удалось подключить: "+err.Error())
					showWindow()
				}
			}()
		},
	})

	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		sup.Start()
		handleLinkArg(args)
	})
	return app.Run()
}
