package main

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/samosvalishe/free-turn-proxy/mobile"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/vanbujhm/freeturn-windows/internal/engine"
	"github.com/vanbujhm/freeturn-windows/internal/firewall"
	"github.com/vanbujhm/freeturn-windows/internal/ipc"
	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/netcfg"
	"github.com/vanbujhm/freeturn-windows/internal/tunnel"
	"github.com/vanbujhm/freeturn-windows/internal/wgconf"
)

const (
	serviceName = "FreeTurnService"
	// debugFlag включает строки ядра уровня debug. Только для console: в них есть куки и токены
	// капчи, поэтому установленная служба этот аргумент не читает.
	debugFlag = "-debug"
	// servicePipeSDDL задаёт владельца канала: окно проверяет, что это ровно LocalSystem.
	servicePipeSDDL = "O:SY" + ipc.PipeSDDL
	// pbtResumeAutomatic - событие питания PBT_APMRESUMEAUTOMATIC, система вышла из сна.
	pbtResumeAutomatic = 0x12
	// pendingWaitHintMs - сколько SCM ждёт запуск или остановку, прежде чем счесть службу зависшей.
	pendingWaitHintMs = 30_000
	// exitFailure - код выхода при сбое запуска.
	exitFailure = 1
	// eventStartFailed - код записи в журнале событий Windows.
	eventStartFailed = 1
)

// serviceHandler отвечает SCM. Работу делает run, здесь только перевод команд. run и report
// вынесены в поля, чтобы проверять ответы SCM без настоящего запуска.
type serviceHandler struct {
	run    func(ctx context.Context, o runOptions) error
	report func(msg string) // сбой запуска, журнала службы к этому моменту может не быть
}

// Execute сам ничего долгого не делает: команды SCM должны получать ответ сразу, поэтому
// пробуждение уходит сигналом в run. Отмена ctx выполняет Disconnect и сбрасывает признак.
// Аргументы запуска не читаются: см. debugFlag.
func (h *serviceHandler) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending, WaitHint: pendingWaitHintMs}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wake := make(chan struct{}, 1)
	started := make(chan struct{})
	done := make(chan error, 1)
	o := runOptions{
		pipeSDDL: servicePipeSDDL,
		wake:     wake,
		ready:    func() { close(started) },
	}
	go func() { done <- h.run(ctx, o) }()

	ready := (<-chan struct{})(started) // обнуляется после первого срабатывания
	stopping := false
	for {
		select {
		case <-ready:
			ready = nil
			if !stopping {
				changes <- svc.Status{
					State:   svc.Running,
					Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPowerEvent,
				}
			}
		case err := <-done:
			if err != nil {
				// Код выхода, а не тихий ноль: только так SCM перезапустит службу.
				h.report("служба не запустилась: " + err.Error())
				return true, exitFailure
			}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				stopping = true
				changes <- svc.Status{State: svc.StopPending, WaitHint: pendingWaitHintMs}
				cancel()
			case svc.PowerEvent:
				if c.EventType == pbtResumeAutomatic {
					notify(wake)
				}
			}
		}
	}
}

// reportFailure пишет в журнал событий Windows. Источник регистрирует install. Если записать
// не вышло, остаётся только код выхода службы.
func reportFailure(msg string) {
	events, err := eventlog.Open(serviceName)
	if err != nil {
		return
	}
	defer events.Close()
	events.Error(eventStartFailed, msg)
}

// coreTarget - часть движка, которой нужны события ядра.
type coreTarget interface {
	OnCoreState(state string, streams, total int, errMsg string)
	OnCaptcha(url string, manual bool)
	MaskLog(s string) string
}

// coreSink принимает события ядра. Он нужен раньше движка: corehost.New ставит приёмник, а
// движку нужен уже готовый Host. Поэтому target задаётся после создания движка, до первого
// Connect, а раньше него ядро не работает и событий нет.
type coreSink struct {
	target coreTarget
	debug  bool
	log    func(level, msg string)
}

func (s *coreSink) OnState(state string, streams, total int, errMsg string) {
	s.target.OnCoreState(state, streams, total, errMsg)
}

func (s *coreSink) OnCaptcha(url string, manual bool) {
	s.target.OnCaptcha(url, manual)
}

// OnLog: другого пути из ядра в журнал нет, поэтому маскировка здесь обязательна.
func (s *coreSink) OnLog(level, msg string, _ int64) {
	if level == mobile.LevelDebug && !s.debug {
		return
	}
	s.log(level, s.target.MaskLog(msg))
}

// deviceLog принимает ошибки устройства WireGuard. Они тоже идут мимо движка.
func (s *coreSink) deviceLog(format string, args ...any) {
	s.log(mobile.LevelError, s.target.MaskLog(fmt.Sprintf(format, args...)))
}

// sysNet закрывает engine.Network функциями netcfg. changed вызывается после каждой смены
// набора маршрутов обхода, и при ошибке тоже: часть маршрутов могла встать.
type sysNet struct {
	changed func()
}

func (sysNet) FindPhysical(exclude uint64) (model.Physical, error) {
	return netcfg.FindPhysical(exclude)
}

func (sysNet) ConfigureInterface(luid uint64, addrs []netip.Prefix, mtu int) error {
	return netcfg.ConfigureInterface(luid, addrs, mtu)
}

func (sysNet) ApplyTunnelRoutes(luid uint64, allowed []netip.Prefix, dns []netip.Addr) error {
	return netcfg.ApplyTunnelRoutes(luid, allowed, dns)
}

func (sysNet) ClearTunnel(luid uint64) error { return netcfg.ClearTunnel(luid) }

func (n sysNet) SetBypass(ph model.Physical, p []netip.Prefix) error {
	err := netcfg.SetBypass(ph, p)
	n.changed()
	return err
}

func (n sysNet) ClearBypass() error {
	err := netcfg.ClearBypass()
	n.changed()
	return err
}

func (sysNet) OtherTunnel(exclude uint64) (string, bool) { return netcfg.OtherTunnel(exclude) }

func (sysNet) FakeIPTunnel(exclude uint64) (string, bool) { return netcfg.FakeIPTunnel(exclude) }

// sysFirewall закрывает engine.Firewall функциями firewall.
type sysFirewall struct{}

func (sysFirewall) Enable(o firewall.Options) error { return firewall.Enable(o) }
func (sysFirewall) Update(o firewall.Options) error { return firewall.Update(o) }
func (sysFirewall) Disable()                        { firewall.Disable() }

// sysTunnels закрывает engine.Tunnels функцией tunnel.Open.
type sysTunnels struct {
	logf func(format string, args ...any)
}

func (t sysTunnels) Open(cfg *wgconf.Config, ep netip.AddrPort) (engine.TunnelDevice, error) {
	dev, err := tunnel.Open(cfg, ep, t.logf)
	if err != nil {
		return nil, err
	}
	return dev, nil
}
