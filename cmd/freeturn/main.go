// FreeTurn - окно, трей и профили. Туннель держит служба FreeTurnService, окно только
// управляет ею по именованному каналу.
//
// Аргументы:
//
//	--tray             окно при запуске скрыто, кроме состояния «Интернет заблокирован»
//	freeturn://...     ссылка на импорт профиля; запущенному окну её передаёт второй запуск
//
// Для разработки есть сборка с тегом devconsole (см. dev_on.go): окно не проверяет владельца
// канала. В обычной сборке этого кода нет, канал обязан принадлежать LocalSystem.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	"github.com/vanbujhm/freeturn-windows/internal/update"
)

// Задаются при сборке: -ldflags "-X main.version=1.2.3 -X main.updateRepo=владелец/имя".
// Пустой updateRepo отключает проверку новой версии совсем.
var (
	version    = "dev"
	updateRepo = ""
)

const (
	appName    = "FreeTurn"
	instanceID = "com.freeturn.windows"
	linkScheme = "freeturn://"

	dialTimeout = 2 * time.Second
	// quitDisconnectLimit - сколько выход из программы ждёт отключения туннеля, потом выходит
	// всё равно.
	quitDisconnectLimit = 10 * time.Second

	windowWidth, windowHeight = 420, 640

	// updateFirstDelay - пауза до первой проверки версии, updateEvery - период следующих.
	updateFirstDelay = 30 * time.Second
	updateEvery      = 24 * time.Hour
	updateFailedLog  = "не удалось проверить новую версию"

	// wmEndSession приходит скрытому окну потока Wails при выходе из системы и выключении.
	wmEndSession = 0x0016
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

// showOnSecondLaunch решает, показывать ли окно по второму запуску: автозапуск с --tray
// без ссылки не должен выдвигать окно, остальное это действие человека.
func showOnSecondLaunch(args []string) bool {
	return !hasTrayFlag(args) || linkArg(args) != ""
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

// loadSettings читает настройки. Неразобранный файл не мешает запуску: берутся значения по
// умолчанию, reset говорит об этом интерфейсу. profile.LoadSettings сам молча подменяет
// битый JSON значениями по умолчанию, поэтому файл проверяется ещё раз.
func loadSettings(path string) (s profile.Settings, reset bool) {
	s, err := profile.LoadSettings(path)
	if err != nil {
		return s, true
	}
	raw, rerr := os.ReadFile(path)
	if rerr != nil {
		return s, !errors.Is(rerr, os.ErrNotExist)
	}
	var probe profile.Settings
	return s, json.Unmarshal(raw, &probe) != nil
}

// disconnectWithin просит службу отключить туннель и ждёт не дольше limit.
func disconnectWithin(svc Service, limit time.Duration) {
	done := make(chan struct{})
	go func() {
		_ = svc.Disconnect()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(limit):
	}
}

func run(args []string) error {
	dev := devConsoleEnabled()
	trayMode := hasTrayFlag(args)

	var (
		app      *application.App
		win      *application.WebviewWindow
		tr       *tray
		sup      *supervisor
		quitting atomic.Bool
		quitOnce sync.Once
		ready    atomic.Bool // окно и трей созданы, второй экземпляр можно обслужить
		captcha  *captchaManager
	)
	// Проверка версии живёт до выхода из программы.
	updateCtx, stopUpdates := context.WithCancel(context.Background())
	defer stopUpdates()
	api := new(API)
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

	// Приложение создаётся первым: здесь второй экземпляр передаёт аргументы первому и
	// выходит, ничего не прочитав и не показав диалогов. Данные читаются ниже.
	app = application.New(application.Options{
		Name:         appName,
		Services:     []application.Service{application.NewService(api)},
		MarshalError: marshalError,
		Assets: application.AssetOptions{
			Handler: application.BundledAssetFileServer(frontend.Assets),
			// Вызовы Wails принимаются только от главного окна: окно капчи показывает чужие
			// скрипты (см. isolation.go).
			Middleware: runtimeGuard,
		},
		Windows: application.WindowsOptions{
			DisableQuitOnLastWindowClosed: true,
			// Выход из системы: окно не мешает ему и перед концом просит службу отключить
			// туннель. Остальное делает Wails (WM_ENDSESSION закрывает приложение).
			WndProcInterceptor: func(_ uintptr, msg uint32, wParam, _ uintptr) (uintptr, bool) {
				if msg == wmEndSession && wParam != 0 {
					quitting.Store(true)
					if sup != nil {
						disconnectWithin(sup, quitDisconnectLimit)
					}
				}
				return 0, false
			},
		},
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: instanceID,
			OnSecondInstanceLaunch: func(d application.SecondInstanceData) {
				if !ready.Load() {
					return
				}
				if showOnSecondLaunch(d.Args) {
					showWindow()
				}
				if raw := linkArg(d.Args); raw != "" {
					if err := api.handleLink(raw); err != nil {
						app.Dialog.Error().SetTitle(appName).SetMessage(errText(err)).Show()
					}
				}
			},
		},
		OnShutdown: func() {
			stopUpdates()
			if sup != nil {
				sup.Stop()
			}
		},
	})

	captcha = newCaptchaManager(app, func(line string) { emit(eventLog, line) })

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
	settings, settingsReset := loadSettings(settingsPath)

	var owner *windows.SID
	if !dev {
		if owner, err = ipc.ServiceOwner(); err != nil {
			return fmt.Errorf("Не удалось определить владельца канала службы: %w", err)
		}
	}
	// Запись в автозапуск следует настройке, по умолчанию она включена. Сбой не мешает
	// запуску: окно работает и без автозапуска, о сбое узнает журнал. Сборка для разработки
	// себя в автозапуск не пишет.
	var startupLogs []string
	if !dev {
		if err := setAutostart(settings.Autostart); err != nil {
			startupLogs = append(startupLogs, "не удалось обновить запуск с Windows")
		}
	}

	sup = newSupervisor(
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
					captcha.Update(*ev.Status)
				}
			case ipc.KindLog:
				emit(eventLog, ev.Log)
			}
		},
		func() {
			emit(eventServiceDown)
			tr.SetDown()
			captcha.Update(model.Status{}) // службы нет: о капче ничего не известно
		},
		func(st model.Status, first bool) {
			tr.SetPhase(st.Phase)
			captcha.Update(st)
			api.onServiceUp(st, first)
			if first && trayMode && st.Phase == model.PhaseBlocked {
				showWindow()
			}
		},
	)

	api.init(apiDeps{
		Service:       sup,
		Store:         store,
		Corrupt:       corrupt,
		Settings:      settings,
		SettingsReset: settingsReset,
		SettingsPath:  settingsPath,
		Emit:          emit,
		SetAutostart: func(on bool) error {
			if dev {
				return nil
			}
			return setAutostart(on)
		},
		DesktopDir: desktopDir,
		OpenURL:    func(u string) error { return app.Browser.OpenURL(u) },
	})

	win = app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:   "main",
		Title:  appName,
		URL:    "/",
		Width:  windowWidth,
		Height: windowHeight,
		Hidden: trayMode,
	})
	mainWindowID.Store(uint32(win.ID()))
	// Крестик сворачивает в трей, туннель продолжает работать. При выходе (меню трея или
	// конец сеанса Windows) окно закрывается как обычно.
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
				disconnectWithin(sup, quitDisconnectLimit)
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
						emit(eventLog, "не удалось отключить: "+errText(err))
					}
					return
				}
				id := api.Settings().LastProfileID
				if id == "" {
					showWindow() // профиль ещё не выбирали
					return
				}
				if err := api.Connect(id); err != nil {
					emit(eventLog, "не удалось подключить: "+errText(err))
					showWindow()
				}
			}()
		},
	})

	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		for _, line := range startupLogs {
			emit(eventLog, line)
		}
		sup.Start()
		go update.Watch(updateCtx, &http.Client{}, updateRepo, version, updateFirstDelay, updateEvery,
			func(r update.Release) { api.setUpdate(UpdateInfo{Version: r.Version, URL: r.URL}) },
			func() { emit(eventLog, updateFailedLog) })
		if raw := linkArg(args); raw != "" {
			if err := api.handleLink(raw); err != nil {
				app.Dialog.Error().SetTitle(appName).SetMessage(errText(err)).Show()
			}
		}
	})
	ready.Store(true)
	return app.Run()
}
