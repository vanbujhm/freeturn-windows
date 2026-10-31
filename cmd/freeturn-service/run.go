package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/samosvalishe/free-turn-proxy/mobile"
	"golang.org/x/sys/windows"

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
	// instanceMutex не даёт запустить второй экземпляр. Объекты Global\ создают только
	// администраторы и службы, поэтому пользователь не может занять имя заранее.
	instanceMutex = `Global\FreeTurnService`
	// dataDirSDDL: владелец администраторы, SYSTEM и администраторы полный доступ, права
	// родителя не наследуются, файлы и папки внутри получают эти же права.
	dataDirSDDL = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

	tickInterval     = 30 * time.Second
	ratesInterval    = time.Second
	coreTimeout      = 60 * time.Second
	handshakeTimeout = 20 * time.Second
	firewallGrace    = 6 * time.Second
	// serverCloseLimit - сколько остановка ждёт закрытия канала, см. closeWithin.
	serverCloseLimit = 2 * time.Second
)

// runOptions различает службу и консоль.
type runOptions struct {
	pipeSDDL string
	debug    bool            // строки ядра уровня debug идут в журнал
	echo     io.Writer       // nil: журнал только в файле
	wake     <-chan struct{} // система вышла из сна, nil в консоли
	ready    func()          // канал открыт, nil в консоли
}

// run поднимает службу и работает до отмены ctx. Порядок запуска важен: права ставятся до
// первого чтения каталога, RemoveStale до любой работы с туннелем, а блокировка возвращается
// раньше, чем канал начнёт принимать команды.
func run(ctx context.Context, o runOptions) error {
	release, err := singleInstance(instanceMutex)
	if err != nil {
		return err
	}
	defer release()

	paths, err := prepareDataDir()
	if err != nil {
		return err
	}

	var relay eventRelay
	logs := newServiceLog(paths.logs, o.echo, func(line string) {
		relay.send(ipc.Event{Kind: ipc.KindLog, Log: line})
	})
	defer logs.close()
	logs.write(mobile.LevelInfo, "служба запускается")
	if o.debug {
		// Masker знает только секреты профиля, а ядро на этом уровне пишет куки и тело запросов капчи.
		logs.write(mobile.LevelWarn, "подробный журнал ядра включён: в нём могут быть куки и токены капчи, не передавайте его")
	}

	if err := tunnel.RemoveStale(); err != nil {
		logs.write(mobile.LevelWarn, "старый адаптер не удалён: "+err.Error())
	}

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
	stopWatch()
	// Сначала отключение: от закрытия канала оно зависеть не должно.
	cmds.shutdown()
	if !closeWithin(srv.Close, serverCloseLimit) {
		logs.write(mobile.LevelWarn, "канал не закрылся вовремя, служба завершается без него")
	}
	loops.Wait()
	logs.write(mobile.LevelInfo, "служба остановлена")
	return nil
}

// closeWithin ждёт fn не дольше limit и сообщает, успел ли он. Канал может зависнуть при
// закрытии: namedpipe теряет сигнал, если клиент отключился в тот же момент (ERROR_NO_DATA).
// Завершение процесса всё равно закрывает канал, поэтому поток просто остаётся ждать.
func closeWithin(fn func(), limit time.Duration) bool {
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
// чем сами команды. Ошибка записи не мешает команде: теряется только восстановление.
type commands struct {
	eng     tunnelControl
	logs    func() []string
	save    func(statefile.State) error
	boot    func() int64
	logf    func(level, msg string)
	applied func() []netcfg.BypassRoute

	mu      sync.Mutex
	state   statefile.State
	stopped bool
}

func (c *commands) Connect(r model.ConnectRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return errors.New("служба останавливается")
	}
	if err := c.eng.Connect(r); err != nil {
		return err
	}
	c.store(wantedOn(r.Options, c.boot()))
	return nil
}

func (c *commands) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.disconnect()
}

// shutdown выполняет Disconnect при остановке службы и запрещает новые подключения: канал
// закрывается позже, и команда из него не должна поднять туннель заново.
func (c *commands) shutdown() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopped = true
	c.disconnect()
}

func (c *commands) disconnect() {
	c.eng.Disconnect()
	c.store(wantedOff(c.state))
}

// syncBypass записывает набор маршрутов обхода, если он изменился. Держит mu, поэтому во время
// Disconnect ждёт его конца. Это не страшно: маршрут, которого уже нет, запуск после падения
// просто пропустит.
func (c *commands) syncBypass() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !slices.Equal(c.state.Bypass, c.applied()) {
		c.store(c.state)
	}
}

// store записывает состояние вместе с текущим набором маршрутов.
func (c *commands) store(s statefile.State) {
	s.Bypass = c.applied()
	c.state = s
	if err := c.save(s); err != nil {
		c.logf(mobile.LevelError, "файл состояния не записан: "+err.Error())
	}
}

func (c *commands) Status() model.Status { return c.eng.Status() }

func (c *commands) Logs() []string { return c.logs() }

// dataPaths - файлы службы в %ProgramData%.
type dataPaths struct {
	root, core, logs, state string
}

func dataPathsFor(programData string) dataPaths {
	root := filepath.Join(programData, "FreeTurn")
	return dataPaths{
		root:  root,
		core:  filepath.Join(root, "core"),
		logs:  filepath.Join(root, "logs"),
		state: filepath.Join(root, "state.json"),
	}
}

func programDataPaths() (dataPaths, error) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return dataPaths{}, fmt.Errorf("каталог ProgramData: %w", err)
	}
	return dataPathsFor(base), nil
}

// prepareDataDir создаёт каталоги и закрывает их от пользователей. Вызывается при каждом
// запуске раньше любого чтения из каталога. Создать папку в ProgramData может любой
// пользователь, поэтому сбой здесь останавливает запуск: файлам в таком каталоге верить нельзя.
func prepareDataDir() (dataPaths, error) {
	p, err := programDataPaths()
	if err != nil {
		return dataPaths{}, err
	}
	if err := os.MkdirAll(p.root, 0o700); err != nil {
		return dataPaths{}, fmt.Errorf("каталог службы: %w", err)
	}
	if err := checkDir(p.root); err != nil {
		return dataPaths{}, err
	}
	if err := protectDir(p.root); err != nil {
		return dataPaths{}, fmt.Errorf("права каталога службы: %w", err)
	}
	for _, dir := range []string{p.core, p.logs} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return dataPaths{}, fmt.Errorf("каталог службы: %w", err)
		}
		if err := checkDir(dir); err != nil {
			return dataPaths{}, err
		}
	}
	return p, nil
}

// checkDir отвергает всё, кроме настоящего каталога. Служба работает как SYSTEM, а ссылка на
// месте каталога увела бы её права и файлы в чужое место.
func checkDir(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s не каталог", path)
	}
	return nil
}

// protectDir ставит права dataDirSDDL. Владелец меняется тоже: иначе пользователь, создавший
// каталог заранее, мог бы вернуть себе доступ. Windows разносит наследуемые права по вложенным
// файлам сама.
func protectDir(path string) error {
	sd, err := windows.SecurityDescriptorFromString(dataDirSDDL)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	const info = windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION |
		windows.PROTECTED_DACL_SECURITY_INFORMATION
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil)
}

// singleInstance занимает имя на время жизни процесса. RemoveStale удалил бы адаптер работающей
// службы, если запустить console рядом с ней, поэтому проверка идёт раньше него. Система
// освобождает имя и при падении, поэтому перезапуск после падения не мешает сам себе.
func singleInstance(name string) (release func(), err error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateMutex(nil, false, namePtr)
	if err != nil {
		if h != 0 {
			windows.CloseHandle(h)
		}
		return nil, fmt.Errorf("другой экземпляр уже работает или не хватает прав: %w", err)
	}
	return func() { windows.CloseHandle(h) }, nil
}
