package netcfg

import (
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// quietPeriod — сколько должно быть тихо, прежде чем сообщить о смене маршрута по умолчанию.
const quietPeriod = 2 * time.Second

// debouncer вызывает f через d после последнего trigger.
type debouncer struct {
	mu      sync.Mutex
	d       time.Duration
	f       func()
	timer   *time.Timer
	stopped bool
}

func newDebouncer(d time.Duration, f func()) *debouncer {
	return &debouncer{d: d, f: f}
}

func (b *debouncer) trigger() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		return
	}
	if b.timer != nil {
		b.timer.Stop()
	}
	b.timer = time.AfterFunc(b.d, b.f)
}

// stop отменяет отложенный вызов и запрещает новые.
func (b *debouncer) stop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stopped = true
	if b.timer != nil {
		b.timer.Stop()
	}
}

// WatchDefaultRoute вызывает cb, когда маршрут по умолчанию (/0) изменился и 2 секунды
// больше ничего не менялось. Маршруты /1, которые ставит сам туннель, не считаются:
// иначе подключение будило бы собственный наблюдатель.
func WatchDefaultRoute(cb func()) (stop func(), err error) {
	deb := newDebouncer(quietPeriod, cb)
	reg, err := winipcfg.RegisterRouteChangeCallback(func(_ winipcfg.MibNotificationType, row *winipcfg.MibIPforwardRow2) {
		if row.DestinationPrefix.Prefix().Bits() == 0 {
			deb.trigger()
		}
	})
	if err != nil {
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			deb.stop()
			_ = reg.Unregister()
		})
	}, nil
}
