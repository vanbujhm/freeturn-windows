package main

import (
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

const (
	captchaName                       = "captcha"
	captchaTitle                      = "Проверка VK"
	captchaWidth, captchaHeight       = 480, 720
	captchaMinWidth, captchaMinHeight = 360, 560
	captchaRefusedLog                 = "адрес капчи отклонён: открываются только локальные адреса"
)

// captchaURLAllowed сообщает, можно ли открыть адрес в окне капчи. Подходит только
// http://127.0.0.1:<порт>/... и http://localhost:<порт>/... без имени пользователя: адрес
// приходит из канала от службы, внешние адреса окно открывать не должно. Строка с пробелами,
// управляющими символами и обратной косой чертой отвергается целиком: WebView2 читает такие
// адреса не так, как Go.
func captchaURLAllowed(raw string) bool {
	for _, r := range raw {
		if r <= ' ' || r == 0x7f || r == '\\' {
			return false
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Opaque != "" {
		return false
	}
	host := u.Hostname()
	if host != "127.0.0.1" && !strings.EqualFold(host, "localhost") {
		return false
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || u.Port() != strconv.Itoa(port) {
		return false
	}
	return u.Host == host+":"+u.Port()
}

// captchaAction - что делать с окном капчи после нового состояния.
type captchaAction int

const (
	captchaKeep   captchaAction = iota // ничего не менять
	captchaOpen                        // открыть окно (или перевести на новый адрес)
	captchaClose                       // закрыть окно
	captchaRefuse                      // адрес не годится: закрыть окно, записать в журнал
)

// decideCaptcha решает по адресу, обработанному в прошлый раз (prev), и новому состоянию.
// Окно нужно, пока фаза captcha и адрес не пуст. Тот же адрес не открывается заново, даже
// если человек закрыл окно: закрытие капчи подключение не отменяет.
func decideCaptcha(prev string, st model.Status) captchaAction {
	want := ""
	if st.Phase == model.PhaseCaptcha {
		want = st.CaptchaURL
	}
	switch {
	case want == prev:
		return captchaKeep
	case want == "":
		return captchaClose
	case !captchaURLAllowed(want):
		return captchaRefuse
	default:
		return captchaOpen
	}
}

// captchaManager ведёт окно капчи по потоку состояний службы. Сами операции с окном
// подставляются, чтобы решение проверялось без окна.
type captchaManager struct {
	open  func(url string)
	close func()
	logf  func(string)

	mu   sync.Mutex
	last string // адрес, по которому приняли решение в прошлый раз
}

// Update вызывается при каждом состоянии службы и при обрыве канала (пустое состояние).
func (m *captchaManager) Update(st model.Status) {
	m.mu.Lock()
	defer m.mu.Unlock()
	act := decideCaptcha(m.last, st)
	if act == captchaKeep {
		return
	}
	m.last = ""
	if st.Phase == model.PhaseCaptcha {
		m.last = st.CaptchaURL
	}
	switch act {
	case captchaOpen:
		m.open(st.CaptchaURL)
	case captchaClose:
		m.close()
	case captchaRefuse:
		m.close()
		m.logf(captchaRefusedLog)
	}
}

// captchaWindowOptions - параметры окна капчи. Имя captcha отличает его от главного окна
// (runtimeRequestAllowed). Разрешения WebView2 отклоняются все: страница чужая, а буфер
// обмена хранит ссылки и конфигурации с ключами. Без явной политики Wails разрешает всё.
// Прочие виды разрешений (в том числе неизвестные) спросят человека, как в браузере.
func captchaWindowOptions(u string) application.WebviewWindowOptions {
	return application.WebviewWindowOptions{
		Name:      captchaName,
		Title:     captchaTitle,
		URL:       u,
		Width:     captchaWidth,
		Height:    captchaHeight,
		MinWidth:  captchaMinWidth,
		MinHeight: captchaMinHeight,
		Permissions: map[application.PermissionType]application.Permission{
			application.PermissionMicrophone:    application.PermissionDeny,
			application.PermissionCamera:        application.PermissionDeny,
			application.PermissionGeolocation:   application.PermissionDeny,
			application.PermissionNotifications: application.PermissionDeny,
			application.PermissionClipboardRead: application.PermissionDeny,
		},
		Windows: application.WindowsWindow{
			Permissions: map[application.CoreWebView2PermissionKind]application.CoreWebView2PermissionState{
				application.CoreWebView2PermissionKindUnknownPermission: application.CoreWebView2PermissionStateDeny,
				application.CoreWebView2PermissionKindOtherSensors:      application.CoreWebView2PermissionStateDeny,
			},
		},
	}
}

// newCaptchaManager связывает менеджер с окнами Wails. Операции с окнами идут через
// главный поток, как требует Wails, и ставятся в очередь, не блокируя вызывающего: Update
// зовут из потока выдачи событий. Указатель на окно трогает только главный поток.
func newCaptchaManager(app *application.App, logf func(string)) *captchaManager {
	var win *application.WebviewWindow
	return &captchaManager{
		logf: logf,
		open: func(u string) {
			application.InvokeAsync(func() {
				if win != nil {
					win.SetURL(u)
					win.Show()
					win.UnMinimise()
					win.Focus()
					return
				}
				w := app.Window.NewWithOptions(captchaWindowOptions(u))
				// Закрытие человеком не отменяет подключение: окно просто исчезает. Хук
				// Wails выполняется в отдельной горутине, а win принадлежит главному потоку,
				// поэтому указатель сбрасывается через очередь главного потока: операции
				// после закрытия (новая капча) увидят уже сброшенное значение.
				w.RegisterHook(events.Common.WindowClosing, func(*application.WindowEvent) {
					application.InvokeAsync(func() {
						if win == w {
							win = nil
						}
					})
				})
				win = w
				w.Focus()
			})
		},
		close: func() {
			application.InvokeAsync(func() {
				if w := win; w != nil {
					win = nil
					w.Close()
				}
			})
		},
	}
}
