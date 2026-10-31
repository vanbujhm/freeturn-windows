package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"sync"

	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// Тексты трея. Остальной текст интерфейса лежит в frontend/src/strings.ts, но меню трея
// рисует система, а не страница.
const (
	trayConnect    = "Подключить"
	trayDisconnect = "Отключить"
	trayOpen       = "Открыть"
	trayQuit       = "Выход"
)

// trayActions - что делают пункты меню и клик по значку.
type trayActions struct {
	Toggle func() // подключить или отключить, смотря по состоянию
	Open   func()
	Quit   func()
}

// tray - значок и меню в области уведомлений.
type tray struct {
	st     *application.SystemTray
	menu   *application.Menu
	toggle *application.MenuItem
	icons  map[trayLook][]byte

	mu   sync.Mutex
	look trayLook
}

// trayLook - вид значка. Службы нет: серый значок и подсказка об этом.
type trayLook int

const (
	lookDown trayLook = iota
	lookIdle
	lookBusy
	lookOn
	lookBad
)

var lookColors = map[trayLook]color.RGBA{
	lookDown: {R: 0x9a, G: 0x9a, B: 0x9a, A: 0xff},
	lookIdle: {R: 0x6b, G: 0x72, B: 0x80, A: 0xff},
	lookBusy: {R: 0xf5, G: 0xa6, B: 0x23, A: 0xff},
	lookOn:   {R: 0x2e, G: 0xa0, B: 0x43, A: 0xff},
	lookBad:  {R: 0xd9, G: 0x3a, B: 0x3a, A: 0xff},
}

var lookTips = map[trayLook]string{
	lookDown: "FreeTurn: служба недоступна",
	lookIdle: "FreeTurn: отключено",
	lookBusy: "FreeTurn: подключение",
	lookOn:   "FreeTurn: подключено",
	lookBad:  "FreeTurn: нет интернета или ошибка",
}

// lookOfPhase выбирает вид значка по этапу подключения.
func lookOfPhase(p model.Phase) trayLook {
	switch p {
	case model.PhaseConnected:
		return lookOn
	case model.PhaseConnecting, model.PhaseCaptcha, model.PhaseReconnecting:
		return lookBusy
	case model.PhaseError, model.PhaseBlocked:
		return lookBad
	default:
		return lookIdle
	}
}

// canDisconnect сообщает, что пункт меню должен предлагать «Отключить»: туннель есть, идёт
// подключение или стоит блокировка (отключение снимает её).
func canDisconnect(l trayLook) bool { return l == lookOn || l == lookBusy || l == lookBad }

func newTray(app *application.App, act trayActions) *tray {
	t := &tray{st: app.SystemTray.New(), look: lookDown, icons: map[trayLook][]byte{}}
	for l, c := range lookColors {
		t.icons[l] = circleIcon(c)
	}
	t.menu = app.NewMenu()
	t.toggle = t.menu.Add(trayConnect)
	t.toggle.OnClick(func(*application.Context) { act.Toggle() })
	t.menu.Add(trayOpen).OnClick(func(*application.Context) { act.Open() })
	t.menu.AddSeparator()
	t.menu.Add(trayQuit).OnClick(func(*application.Context) { act.Quit() })

	t.st.SetIcon(t.icons[lookDown])
	t.st.SetTooltip(lookTips[lookDown])
	t.st.SetMenu(t.menu)
	t.st.OnClick(act.Open)
	t.toggle.SetEnabled(false)
	return t
}

// offersDisconnect сообщает, предлагает ли пункт меню «Отключить».
func (t *tray) offersDisconnect() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return canDisconnect(t.look)
}

// SetPhase обновляет значок и меню по состоянию службы.
func (t *tray) SetPhase(p model.Phase) { t.setLook(lookOfPhase(p)) }

// SetDown показывает, что службы нет.
func (t *tray) SetDown() { t.setLook(lookDown) }

func (t *tray) setLook(l trayLook) {
	t.mu.Lock()
	changed := t.look != l
	t.look = l
	t.mu.Unlock()
	if !changed {
		return
	}
	t.st.SetIcon(t.icons[l])
	t.st.SetTooltip(lookTips[l])
	application.InvokeAsync(func() {
		label := trayConnect
		if canDisconnect(l) {
			label = trayDisconnect
		}
		t.toggle.SetLabel(label).SetEnabled(l != lookDown)
		t.menu.Update()
	})
}

// circleIcon рисует значок: цветной круг 32x32. Готовые значки появятся вместе с оформлением.
func circleIcon(c color.RGBA) []byte {
	const size, r = 32, 13.0
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx, dy := float64(x)+0.5-size/2, float64(y)+0.5-size/2
			if dx*dx+dy*dy <= r*r {
				img.SetRGBA(x, y, c)
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err) // кодирование в память не должно падать
	}
	return buf.Bytes()
}
