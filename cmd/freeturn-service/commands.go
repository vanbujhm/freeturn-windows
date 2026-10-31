package main

import (
	"errors"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/samosvalishe/free-turn-proxy/mobile"

	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/netcfg"
	"github.com/vanbujhm/freeturn-windows/internal/statefile"
)

// wantedOn - состояние после принятого подключения.
func wantedOn(o model.Options, boot int64) statefile.State {
	return statefile.State{Wanted: true, KillSwitch: o.KillSwitch, AllowLAN: o.AllowLAN, BootUnix: boot}
}

// wantedOff - состояние после отключения.
func wantedOff(s statefile.State) statefile.State {
	s.Wanted = false
	return s
}

// tunnelControl - часть движка, которой пользуются команды канала.
type tunnelControl interface {
	Connect(model.ConnectRequest) error
	Disconnect()
	Status() model.Status
}

// commands отвечает на команды канала и ведёт файл состояния. Клиентов может быть несколько,
// поэтому mu держится на всю команду: иначе запись признака могла бы лечь в другом порядке,
// чем сами команды. stateMu защищает только состояние и его запись, поэтому зависшая команда
// не мешает записи. Ошибка записи не мешает команде: теряется только восстановление.
type commands struct {
	eng     tunnelControl
	logs    func() []string
	save    func(statefile.State) error
	boot    func() int64
	logf    func(level, msg string)
	applied func() []netcfg.BypassRoute

	mu      sync.Mutex
	stopped atomic.Bool

	// syncMu держит "прочитать маршруты, изменить state.Bypass, записать" одним действием.
	// Берётся раньше stateMu и держится на время applied.
	syncMu sync.Mutex
	// stateMu защищает state и запись, applied под ним не вызывается.
	stateMu sync.Mutex
	state   statefile.State
}

func (c *commands) Connect(r model.ConnectRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped.Load() {
		return errors.New("служба останавливается")
	}
	if err := c.eng.Connect(r); err != nil {
		return err
	}
	boot := c.boot()
	c.update(func(statefile.State) statefile.State { return wantedOn(r.Options, boot) })
	return nil
}

func (c *commands) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.disconnect()
}

// shutdown выполняет Disconnect при остановке службы и запрещает новые подключения: канал
// закрывается позже, и команда из него не должна поднять туннель заново. Запрет ставится без
// mu: его может держать зависшая команда другого клиента.
func (c *commands) shutdown() {
	c.stopped.Store(true)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.disconnect()
}

func (c *commands) disconnect() {
	c.eng.Disconnect()
	c.update(wantedOff)
}

// clearWanted сбрасывает признак, когда остановка не уложилась в срок. Не ждёт ни команд, ни
// маршрутов: они могут висеть. Набор маршрутов остаётся последним записанным.
func (c *commands) clearWanted() {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.state = wantedOff(c.state)
	c.write()
}

// syncBypass записывает набор маршрутов обхода, если он изменился.
func (c *commands) syncBypass() {
	c.syncMu.Lock()
	defer c.syncMu.Unlock()
	routes := c.applied()
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if !slices.Equal(c.state.Bypass, routes) {
		c.state.Bypass = routes
		c.write()
	}
}

// update меняет состояние и записывает его вместе с текущим набором маршрутов. Чтение набора и
// запись идут под одним syncMu, иначе syncBypass успел бы записать более новый набор, а update
// затёр бы его старым. stateMu при чтении набора не держится: applied ждёт системных вызовов, а
// clearWanted не должен ждать их.
func (c *commands) update(change func(statefile.State) statefile.State) {
	c.syncMu.Lock()
	defer c.syncMu.Unlock()
	routes := c.applied()
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.state = change(c.state)
	c.state.Bypass = routes
	c.write()
}

// write вызывается под stateMu.
func (c *commands) write() {
	if err := c.save(c.state); err != nil {
		c.logf(mobile.LevelError, "файл состояния не записан: "+err.Error())
	}
}

func (c *commands) Status() model.Status { return c.eng.Status() }

func (c *commands) Logs() []string { return c.logs() }
