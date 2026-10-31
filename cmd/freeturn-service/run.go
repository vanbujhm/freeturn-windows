package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/samosvalishe/free-turn-proxy/mobile"

	"github.com/vanbujhm/freeturn-windows/internal/corehost"
	"github.com/vanbujhm/freeturn-windows/internal/engine"
	"github.com/vanbujhm/freeturn-windows/internal/ipc"
	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/netcfg"
	"github.com/vanbujhm/freeturn-windows/internal/protect"
	"github.com/vanbujhm/freeturn-windows/internal/split"
	"github.com/vanbujhm/freeturn-windows/internal/statefile"
	"github.com/vanbujhm/freeturn-windows/internal/tunnel"
)

const (
	tickInterval     = 30 * time.Second
	ratesInterval    = time.Second
	coreTimeout      = 60 * time.Second
	handshakeTimeout = 20 * time.Second
	firewallGrace    = 6 * time.Second
	// serverCloseLimit - сколько остановка ждёт закрытия канала и записи признака.
	serverCloseLimit = 2 * time.Second
	// stopDeadline - срок всей остановки, вместе с запасом на запись признака он меньше подсказки
	// SCM pendingWaitHintMs.
	stopDeadline = 25 * time.Second
)

// runOptions различает службу и консоль.
type runOptions struct {
	pipeSDDL string
	debug    bool            // ядро пишет строки debug, только с echo: см. debugFlag
	echo     io.Writer       // nil: журнал только в файле
	wake     <-chan struct{} // система вышла из сна, nil в консоли
	ready    func()          // канал открыт, nil в консоли
}

// run поднимает службу и работает до отмены ctx. Порядок запуска важен: права ставятся до
// первого чтения каталога, второй экземпляр отсекается до RemoveStale, а блокировка возвращается
// раньше, чем канал начнёт принимать команды. Остановка целиком укладывается в stopDeadline.
func run(ctx context.Context, o runOptions) error {
	paths, note, err := prepareDataDir()
	if err != nil {
		return err
	}
	release, err := lockInstance(paths.lock)
	if err != nil {
		return err
	}
	defer release()

	var relay eventRelay
	logs := newServiceLog(paths.logs, o.echo, func(line string) {
		relay.send(ipc.Event{Kind: ipc.KindLog, Log: line})
	})
	defer logs.close()
	logs.write(mobile.LevelInfo, "служба запускается")
	if note != "" {
		logs.write(mobile.LevelWarn, note)
	}
	if o.debug {
		logs.write(mobile.LevelWarn, "подробные строки ядра идут только в консоль: в них куки и токены капчи, не передавайте их")
	}

	clearStaleAdapter(tunnel.RemoveStale, logs.write)

	state, err := statefile.Load(paths.state)
	if err != nil {
		logs.write(mobile.LevelError, "файл состояния не прочитан: "+err.Error())
	}
	save := func(s statefile.State) error { return statefile.Save(paths.state, s) }

	bypass := make(chan struct{}, 1)
	eng := newEngine(paths.core, o.debug, logs, &relay, func() { notify(bypass) })
	state, err = recoverAfterStart(eng, state, statefile.BootUnix(), netcfg.RemoveRoutes, save)
	if err != nil {
		logs.write(mobile.LevelError, "состояние после перезапуска не восстановлено: "+err.Error())
	}

	cmds := &commands{
		eng:     eng,
		logs:    logs.ring.last,
		save:    save,
		boot:    statefile.BootUnix,
		logf:    logs.write,
		applied: netcfg.AppliedBypass,
		state:   state,
	}
	srv, err := ipc.Serve(ipc.PipePath, o.pipeSDDL, cmds)
	if err != nil {
		logs.write(mobile.LevelError, "канал не открыт: "+err.Error())
		return fmt.Errorf("канал не открыт: %w", err)
	}
	relay.srv.Store(srv)

	loops, stopWatch := startLoops(ctx, eng, o.wake, logs)
	// Запись идёт на диск со сбросом, поэтому в своём потоке: SetBypass зовут под session.netMu.
	loops.Go(func() { serial(ctx, bypass, cmds.syncBypass) })
	if o.ready != nil {
		o.ready()
	}
	logs.write(mobile.LevelInfo, "служба работает")

	<-ctx.Done()
	stop := func() {
		stopWatch()
		// Сначала отключение: от закрытия канала оно зависеть не должно.
		cmds.shutdown()
		if !within(srv.Close, serverCloseLimit) {
			logs.write(mobile.LevelWarn, "канал не закрылся вовремя, служба завершается без него")
		}
		loops.Wait()
	}
	if !within(stop, stopDeadline) {
		// Завершение процесса снимает блокировку, а следующий запуск убирает адаптер и маршруты.
		logs.write(mobile.LevelError, "остановка не уложилась в срок, служба завершается как есть")
		if !within(cmds.clearWanted, serverCloseLimit) {
			logs.write(mobile.LevelError, "признак туннеля не сброшен")
		}
		return nil
	}
	logs.write(mobile.LevelInfo, "служба остановлена")
	return nil
}

// clearStaleAdapter убирает адаптер прошлого запуска. Сбой запуск не останавливает, в том числе
// без wintun.dll: блокировка после падения важнее, а Connect без библиотеки кончится кодом adapter.
func clearStaleAdapter(remove func() error, logf func(level, msg string)) {
	if err := remove(); errors.Is(err, tunnel.ErrNoWintun) {
		logf(mobile.LevelError, err.Error())
	} else if err != nil {
		logf(mobile.LevelWarn, "старый адаптер не удалён: "+err.Error())
	}
}

// within ждёт fn не дольше limit и сообщает, успел ли он. Иначе поток остаётся ждать, а всё, что
// fn не успел, закроет завершение процесса.
func within(fn func(), limit time.Duration) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
		return true
	case <-time.After(limit):
		return false
	}
}

// newEngine собирает движок из настоящих пакетов. Один Protector стоит и у ядра, и у движка,
// и у разрешителя доменов: индекс физического интерфейса у них должен быть общий.
// bypassChanged вызывается после каждой смены набора маршрутов обхода и не должен ждать.
func newEngine(coreDir string, debug bool, logs *serviceLog, relay *eventRelay, bypassChanged func()) *engine.Engine {
	prot := protect.New()
	sink := &coreSink{debug: debug, log: logs.write}
	host := corehost.New(coreDir, sink, prot, debug)
	eng := engine.New(engine.Deps{
		Core:     host,
		Tunnels:  sysTunnels{logf: sink.deviceLog},
		Net:      sysNet{changed: bypassChanged},
		FW:       sysFirewall{},
		Protect:  prot,
		Resolver: split.NewResolver(prot.Protect),
		FreePort: corehost.FreePort,
		Classify: corehost.Classify,
		OnChange: func(st model.Status) {
			relay.send(ipc.Event{Kind: ipc.KindStatus, Status: &st})
		},
		Logf:             logs.write,
		CoreTimeout:      coreTimeout,
		HandshakeTimeout: handshakeTimeout,
		FirewallGrace:    firewallGrace,
	})
	sink.target = eng
	return eng
}

// startLoops запускает таймеры и наблюдение за сетью. Вызовы движка могут ждать секунды,
// поэтому у каждого свой поток, а циклы кончаются вместе с ctx. Если наблюдение не встало,
// туннель всё равно работает: сеть сверяет и Tick. Возвращает ожидание циклов и остановку
// наблюдения.
func startLoops(ctx context.Context, eng *engine.Engine, wake <-chan struct{}, logs *serviceLog) (*sync.WaitGroup, func()) {
	var loops sync.WaitGroup
	ticks := time.NewTicker(tickInterval)
	rates := time.NewTicker(ratesInterval)
	changed := make(chan struct{}, 1)

	loops.Go(func() {
		defer ticks.Stop()
		tickLoop(ctx, ticks.C, wake, eng.Tick, eng.Woke)
	})
	loops.Go(func() {
		defer rates.Stop()
		serial(ctx, rates.C, eng.RefreshRates)
	})
	loops.Go(func() { serial(ctx, changed, eng.NetworkChanged) })

	stop, err := netcfg.WatchDefaultRoute(func() { notify(changed) })
	if err != nil {
		logs.write(mobile.LevelWarn, "смена сети отслеживается только таймером: "+err.Error())
		return &loops, func() {}
	}
	return &loops, stop
}

// tickLoop выполняет такты и пробуждения по одному в одном потоке, поэтому они не пересекаются.
// Пробуждение идёт раньше ждущего такта: сверке после сна нужно уже разбуженное ядро.
func tickLoop(ctx context.Context, ticks <-chan time.Time, wake <-chan struct{}, onTick func(time.Time), onWake func()) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-wake:
			onWake()
			continue
		default:
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
			onWake()
		case <-ticks:
			onTick(time.Now())
		}
	}
}

// serial вызывает f на каждый сигнал, по одному за раз.
func serial[T any](ctx context.Context, signals <-chan T, f func()) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-signals:
			f()
		}
	}
}

// notify ставит сигнал в канал ёмкостью 1 и не ждёт. С serial это даёт один идущий вызов и
// один ожидающий: события склеиваются, а вызывающий поток не блокируется.
func notify(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// eventRelay рассылает события клиентам. Канала может ещё не быть: ArmBlock меняет статус раньше
// ipc.Serve, а клиент всё равно начинает с GetStatus.
type eventRelay struct {
	srv atomic.Pointer[ipc.Server]
}

func (r *eventRelay) send(ev ipc.Event) {
	if s := r.srv.Load(); s != nil {
		s.Broadcast(ev)
	}
}

// restorer - часть движка, нужная после перезапуска.
type restorer interface {
	ArmBlock(model.Options) error
	AwaitProfile()
}

// restore выполняет решение statefile.Decide. Правил в файле нет, поэтому до профиля от окна
// блокировка стоит без исключений.
func restore(r restorer, action statefile.Action, s statefile.State, save func(statefile.State) error) error {
	switch action {
	case statefile.ActionRearm:
		return r.ArmBlock(model.Options{KillSwitch: s.KillSwitch, AllowLAN: s.AllowLAN})
	case statefile.ActionAwaitProfile:
		r.AwaitProfile()
	case statefile.ActionClear:
		return save(statefile.State{})
	}
	return nil
}

// recoverAfterStart приводит систему и файл в порядок после прошлого запуска. Маршруты обхода
// живут на физическом адаптере и переживают падение, поэтому снимаются при любом решении и
// раньше блокировки. Сбой снятия не отменяет блокировку: она важнее. Возвращает состояние, от
// которого служба работает дальше.
func recoverAfterStart(r restorer, s statefile.State, boot int64,
	remove func([]netcfg.BypassRoute) error, save func(statefile.State) error) (statefile.State, error) {
	var errs []error
	if len(s.Bypass) > 0 {
		errs = append(errs, remove(s.Bypass))
		s.Bypass = nil
		errs = append(errs, save(s))
	}
	action := statefile.Decide(s, boot)
	errs = append(errs, restore(r, action, s, save))
	if action == statefile.ActionClear {
		s = statefile.State{}
	}
	return s, errors.Join(errs...)
}
