package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

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
	// dataDirSDDL: владелец администраторы, SYSTEM и администраторы полный доступ, права
	// родителя не наследуются, файлы и папки внутри получают эти же права.
	dataDirSDDL = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	// secureAttempts - сколько раз secure пробует занять место подброшенного каталога.
	secureAttempts = 3
	// asideInfix стоит в имени подброшенного каталога, который отодвинут в сторону.
	asideInfix = ".planted-"

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
	routes := c.applied()
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if !slices.Equal(c.state.Bypass, routes) {
		c.state.Bypass = routes
		c.write()
	}
}

// update меняет состояние и записывает его вместе с текущим набором маршрутов. Набор читается
// раньше stateMu: его замок держится на время системных вызовов и не должен держать clearWanted.
func (c *commands) update(change func(statefile.State) statefile.State) {
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

// dataPaths - файлы службы в %ProgramData%.
type dataPaths struct {
	root, core, logs, state, lock string
}

func dataPathsFor(programData string) dataPaths {
	root := filepath.Join(programData, "FreeTurn")
	return dataPaths{
		root:  root,
		core:  filepath.Join(root, "core"),
		logs:  filepath.Join(root, "logs"),
		state: filepath.Join(root, "state.json"),
		lock:  filepath.Join(root, "service.lock"),
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
// запуске и при установке раньше любого чтения из каталога. Создать папку в ProgramData может
// любой пользователь, поэтому сбой здесь останавливает запуск: файлам в таком каталоге верить
// нельзя. Непустая заметка сообщает, что каталог пришлось заменить.
func prepareDataDir() (dataPaths, string, error) {
	p, err := programDataPaths()
	if err != nil {
		return dataPaths{}, "", err
	}
	note, err := serviceDir.secure(p.root)
	if err != nil {
		return dataPaths{}, note, fmt.Errorf("каталог службы: %w", err)
	}
	// Вложенные каталоги создаются уже внутри закрытого и получают его права.
	for _, dir := range []string{p.core, p.logs} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return dataPaths{}, note, fmt.Errorf("каталог службы: %w", err)
		}
	}
	return p, note, nil
}

// dirPolicy описывает закрытый каталог: какие права ему ставить и кому из владельцев верить.
type dirPolicy struct {
	sddl    string
	trusted func(*windows.SID) bool
}

var serviceDir = dirPolicy{sddl: dataDirSDDL, trusted: trustedOwner}

// trustedOwner: каталог создан службой или установщиком. Владельцем становится только тот, кто
// создал объект или получил такое право, поэтому обычный пользователь сюда не попадёт.
func trustedOwner(owner *windows.SID) bool {
	return owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

// secure приводит root к закрытому состоянию. Новый каталог сразу создаётся с нужными правами и
// не бывает открытым ни мгновения. Существующий проверяется по дескриптору, а подброшенный
// заменяется целиком: вложенная папка со своими правами пережила бы любую смену прав снаружи.
// Повтор нужен, если каталог успели подбросить снова.
func (d dirPolicy) secure(root string) (note string, err error) {
	sd, err := windows.SecurityDescriptorFromString(d.sddl)
	if err != nil {
		return "", err
	}
	for range secureAttempts {
		err := createProtected(root, sd)
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return note, err
		}
		planted, err := d.adopt(root, sd)
		if err != nil {
			return note, err
		}
		if !planted {
			return note, nil
		}
		if note, err = evict(root); err != nil {
			return note, err
		}
	}
	return note, errors.New("его снова и снова создаёт кто-то другой")
}

func createProtected(root string, sd *windows.SECURITY_DESCRIPTOR) error {
	path, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	return windows.CreateDirectory(path, &sa)
}

// adopt проверяет существующий root и ставит ему права. Всё идёт через один дескриптор: он
// открыт без FILE_SHARE_DELETE, поэтому объект нельзя подменить между проверкой и записью прав,
// а ссылка открывается как ссылка и не ведёт за собой. true: каталог подброшен. Отказ в доступе
// это тоже подброшенный каталог: у законного владельца право прочитать и сменить права есть
// всегда, а значит, владелец другой.
func (d dirPolicy) adopt(root string, sd *windows.SECURITY_DESCRIPTOR) (planted bool, err error) {
	path, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return false, err
	}
	const (
		access = windows.READ_CONTROL | windows.WRITE_DAC | windows.FILE_READ_ATTRIBUTES
		share  = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE
		flags  = windows.FILE_FLAG_OPEN_REPARSE_POINT | windows.FILE_FLAG_BACKUP_SEMANTICS
	)
	h, err := windows.CreateFile(path, access, share, nil, windows.OPEN_EXISTING, flags, 0)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(h)

	var attrs windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &attrs); err != nil {
		return false, err
	}
	if attrs.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		attrs.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return true, nil
	}
	current, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := current.Owner()
	if err != nil {
		return false, err
	}
	if !d.trusted(owner) {
		return true, nil
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, err
	}
	const info = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	return false, windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil)
}

// evict убирает подброшенный root: сначала отодвигает, потом удаляет. Так каталог уходит и тогда,
// когда пользователь закрыл его от всех. Удаление идёт через os.RemoveAll, он ссылки не раскрывает.
// Если удалить не вышло, остаток лежит под другим именем и службе не мешает.
func evict(root string) (note string, err error) {
	aside := root + asideInfix + rand.Text()
	if err := renameBeside(root, aside); err != nil {
		return "", fmt.Errorf("чужой каталог не убран: %w", err)
	}
	// RemoveAll молча принимает несуществующий путь, а ответ об удалении должен быть правдой.
	if _, err := os.Lstat(aside); err != nil {
		return "", fmt.Errorf("чужой каталог не убран: %w", err)
	}
	if err := os.RemoveAll(aside); err != nil {
		return fmt.Sprintf("чужой каталог службы отодвинут, но не удалён: %s: %v", aside, err), nil
	}
	return "чужой каталог службы удалён", nil
}

// fileRenameInfo - FILE_RENAME_INFORMATION, имя задано массивом.
type fileRenameInfo struct {
	flags         uint32
	rootDirectory windows.Handle
	nameLength    uint32
	name          [1024]uint16
}

// renameBeside переименовывает объект, ссылка переименовывается сама. Оба пути полные: короткое
// имя в SetFileInformationByHandle считалось бы от рабочего каталога процесса и увело бы объект
// туда. DELETE даёт FILE_DELETE_CHILD у родителя, даже если сам объект закрыт. Другие права дал
// бы только объект, а MoveFileEx и CreateFile их просят всегда, поэтому открытие идёт через
// NtCreateFile с одним DELETE.
func renameBeside(path, target string) error {
	nt, err := windows.NewNTUnicodeString(`\??\` + path)
	if err != nil {
		return err
	}
	attrs := windows.OBJECT_ATTRIBUTES{ObjectName: nt, Attributes: windows.OBJ_CASE_INSENSITIVE}
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	const (
		share   = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
		options = windows.FILE_OPEN_FOR_BACKUP_INTENT | windows.FILE_OPEN_REPARSE_POINT
	)
	var (
		h    windows.Handle
		iosb windows.IO_STATUS_BLOCK
	)
	err = windows.NtCreateFile(&h, windows.DELETE, &attrs, &iosb, nil, 0, share, windows.FILE_OPEN, options, 0, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)

	name, err := windows.UTF16FromString(`\??\` + target)
	if err != nil {
		return err
	}
	name = name[:len(name)-1] // длина задаётся явно, ноль не нужен
	var info fileRenameInfo
	if len(name) > len(info.name) {
		return fmt.Errorf("слишком длинный путь: %s", target)
	}
	info.nameLength = uint32(len(name) * 2)
	copy(info.name[:], name)
	return windows.NtSetInformationFile(h, &iosb, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), windows.FileRenameInformation)
}

// lockInstance не даёт запустить второй экземпляр. RemoveStale удалил бы адаптер работающей
// службы, если запустить console рядом с ней, поэтому блокировка берётся раньше него. Файл
// открыт без совместного доступа на время жизни процесса, при падении дескриптор закрывает ядро
// системы. Он лежит в закрытом каталоге, поэтому пользователь занять его не может.
func lockInstance(path string) (release func(), err error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, fmt.Errorf("другой экземпляр службы уже работает: %w", err)
	}
	return func() { windows.CloseHandle(h) }, nil
}
