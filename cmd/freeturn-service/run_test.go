package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vanbujhm/freeturn-windows/internal/engine"
	"github.com/vanbujhm/freeturn-windows/internal/ipc"
	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/netcfg"
	"github.com/vanbujhm/freeturn-windows/internal/statefile"
)

// fakeRestorer стоит на месте движка при восстановлении после перезапуска.
type fakeRestorer struct {
	armed    []model.Options
	armErr   error
	awaiting int
}

func (f *fakeRestorer) ArmBlock(o model.Options) error {
	f.armed = append(f.armed, o)
	return f.armErr
}

func (f *fakeRestorer) AwaitProfile() { f.awaiting++ }

func TestRestore(t *testing.T) {
	saved := statefile.State{Wanted: true, KillSwitch: true, AllowLAN: true, BootUnix: 1000}
	failure := errors.New("диск")

	tests := []struct {
		name     string
		action   statefile.Action
		armErr   error
		saveErr  error
		armed    bool
		awaiting int
		cleared  bool
		wantErr  error
	}{
		{name: "ничего", action: statefile.ActionNone},
		{name: "блокировка", action: statefile.ActionRearm, armed: true},
		{name: "блокировка не встала", action: statefile.ActionRearm, armed: true, armErr: failure, wantErr: failure},
		{name: "ждём профиль", action: statefile.ActionAwaitProfile, awaiting: 1},
		{name: "другая загрузка", action: statefile.ActionClear, cleared: true},
		{name: "запись не удалась", action: statefile.ActionClear, cleared: true, saveErr: failure, wantErr: failure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &fakeRestorer{armErr: tt.armErr}
			var written []statefile.State
			err := restore(r, tt.action, saved, func(s statefile.State) error {
				written = append(written, s)
				return tt.saveErr
			})
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ошибка %v", err)
			}
			if tt.armed {
				// После падения правил нет: окно пришлёт их вместе с профилем.
				want := model.Options{KillSwitch: true, AllowLAN: true}
				if len(r.armed) != 1 || r.armed[0].KillSwitch != want.KillSwitch ||
					r.armed[0].AllowLAN != want.AllowLAN || r.armed[0].Rules != nil {
					t.Errorf("ArmBlock %+v", r.armed)
				}
			} else if len(r.armed) != 0 {
				t.Errorf("лишний ArmBlock %+v", r.armed)
			}
			if r.awaiting != tt.awaiting {
				t.Errorf("AwaitProfile %d раз", r.awaiting)
			}
			if tt.cleared != (len(written) == 1 && reflect.DeepEqual(written[0], statefile.State{})) {
				t.Errorf("записано %+v", written)
			}
		})
	}
}

func TestWantedTransitions(t *testing.T) {
	on := wantedOn(model.Options{KillSwitch: true, AllowLAN: true}, 1000)
	want := statefile.State{Wanted: true, KillSwitch: true, AllowLAN: true, BootUnix: 1000}
	if !reflect.DeepEqual(on, want) {
		t.Errorf("wantedOn = %+v", on)
	}
	want.Wanted = false
	if off := wantedOff(on); !reflect.DeepEqual(off, want) {
		t.Errorf("wantedOff = %+v", off)
	}
}

// fakeTunnel стоит на месте движка за командами канала.
type fakeTunnel struct {
	mu          sync.Mutex
	connectErr  error
	connects    int
	disconnects int
}

func (f *fakeTunnel) Connect(model.ConnectRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connects++
	return f.connectErr
}

func (f *fakeTunnel) Disconnect() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disconnects++
}

func (f *fakeTunnel) Status() model.Status { return model.Status{Phase: model.PhaseIdle} }

// stateLog запоминает всё, что служба записала в файл состояния.
type stateLog struct {
	saved  []statefile.State
	err    error
	routes []netcfg.BypassRoute // набор, который сейчас стоит в системе
}

func (s *stateLog) save(st statefile.State) error {
	s.saved = append(s.saved, st)
	return s.err
}

func newCommands(tun *fakeTunnel, st *stateLog, logs *logCatcher) *commands {
	return &commands{
		eng:     tun,
		logs:    func() []string { return []string{"строка"} },
		save:    st.save,
		boot:    func() int64 { return 1000 },
		logf:    logs.write,
		applied: func() []netcfg.BypassRoute { return st.routes },
	}
}

var ksRequest = model.ConnectRequest{Options: model.Options{KillSwitch: true, AllowLAN: true}}

func TestCommandsConnectSavesWanted(t *testing.T) {
	tun, st := &fakeTunnel{}, &stateLog{}
	c := newCommands(tun, st, &logCatcher{})
	if err := c.Connect(ksRequest); err != nil {
		t.Fatal(err)
	}
	want := []statefile.State{{Wanted: true, KillSwitch: true, AllowLAN: true, BootUnix: 1000}}
	if !reflect.DeepEqual(st.saved, want) {
		t.Fatalf("записано %+v", st.saved)
	}
}

// Отказ занятого движка не меняет признак: туннель, который идёт, по-прежнему нужен.
func TestCommandsRejectedConnectKeepsState(t *testing.T) {
	tun, st := &fakeTunnel{connectErr: engine.ErrBusy}, &stateLog{}
	c := newCommands(tun, st, &logCatcher{})
	if err := c.Connect(ksRequest); !errors.Is(err, engine.ErrBusy) {
		t.Fatalf("ошибка %v", err)
	}
	if len(st.saved) != 0 {
		t.Fatalf("записано %+v", st.saved)
	}
}

func TestCommandsDisconnectClearsWanted(t *testing.T) {
	tun, st := &fakeTunnel{}, &stateLog{}
	c := newCommands(tun, st, &logCatcher{})
	if err := c.Connect(ksRequest); err != nil {
		t.Fatal(err)
	}
	c.Disconnect()
	if tun.disconnects != 1 {
		t.Fatalf("Disconnect %d раз", tun.disconnects)
	}
	last := st.saved[len(st.saved)-1]
	if !reflect.DeepEqual(last, statefile.State{KillSwitch: true, AllowLAN: true, BootUnix: 1000}) {
		t.Fatalf("после отключения %+v", last)
	}
}

// Отключение после перезапуска сбрасывает признак прошлого запуска.
func TestCommandsDisconnectAfterRestart(t *testing.T) {
	tun, st := &fakeTunnel{}, &stateLog{}
	c := newCommands(tun, st, &logCatcher{})
	c.state = statefile.State{Wanted: true, KillSwitch: true, BootUnix: 900}
	c.Disconnect()
	if want := (statefile.State{KillSwitch: true, BootUnix: 900}); !reflect.DeepEqual(st.saved[0], want) {
		t.Fatalf("записано %+v", st.saved[0])
	}
}

// Ошибка записи не должна ломать подключение: без файла теряется только восстановление.
func TestCommandsSaveErrorIsLogged(t *testing.T) {
	tun, st, logs := &fakeTunnel{}, &stateLog{err: errors.New("диск полон")}, &logCatcher{}
	c := newCommands(tun, st, logs)
	if err := c.Connect(ksRequest); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	c.Disconnect()
	if got := logs.got(); len(got) != 2 {
		t.Fatalf("журнал %q", got)
	}
}

// После Stop команда из канала, которая опоздала, не должна поднять туннель.
func TestCommandsShutdown(t *testing.T) {
	tun, st := &fakeTunnel{}, &stateLog{}
	c := newCommands(tun, st, &logCatcher{})
	if err := c.Connect(ksRequest); err != nil {
		t.Fatal(err)
	}
	c.shutdown()
	if tun.disconnects != 1 || st.saved[len(st.saved)-1].Wanted {
		t.Fatalf("отключений %d, записано %+v", tun.disconnects, st.saved)
	}
	if err := c.Connect(ksRequest); err == nil {
		t.Fatal("Connect после остановки принят")
	}
	if tun.connects != 1 {
		t.Fatalf("Connect дошёл до движка %d раз", tun.connects)
	}
}

var testBypass = []netcfg.BypassRoute{{
	LUID:    7,
	Prefix:  netip.MustParsePrefix("203.0.113.0/24"),
	NextHop: netip.MustParseAddr("198.51.100.1"),
}}

// recovery записывает порядок шагов восстановления.
type recovery struct {
	list      []string
	saved     []statefile.State
	removeErr error
}

func (r *recovery) ArmBlock(model.Options) error {
	r.list = append(r.list, "block")
	return nil
}

func (r *recovery) AwaitProfile() { r.list = append(r.list, "await") }

func (r *recovery) remove(rs []netcfg.BypassRoute) error {
	r.list = append(r.list, "remove")
	if !slices.Equal(rs, testBypass) {
		panic("сняты не те маршруты")
	}
	return r.removeErr
}

func (r *recovery) save(s statefile.State) error {
	r.list = append(r.list, "save")
	r.saved = append(r.saved, s)
	return nil
}

// Маршруты снимаются при любом решении и раньше блокировки.
func TestRecoverRemovesRoutesFirst(t *testing.T) {
	const boot = 1000
	tests := []struct {
		name  string
		state statefile.State
		boot  int64
		order []string
	}{
		{"туннель не нужен", statefile.State{BootUnix: boot}, boot, []string{"remove", "save"}},
		{"блокировка", statefile.State{Wanted: true, KillSwitch: true, BootUnix: boot}, boot,
			[]string{"remove", "save", "block"}},
		{"ждём профиль", statefile.State{Wanted: true, BootUnix: boot}, boot,
			[]string{"remove", "save", "await"}},
		{"другая загрузка", statefile.State{Wanted: true, BootUnix: boot}, boot + 3600,
			[]string{"remove", "save", "save"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.state
			s.Bypass = testBypass
			r := &recovery{}
			got, err := recoverAfterStart(r, s, tt.boot, r.remove, r.save)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(r.list, tt.order) {
				t.Fatalf("порядок %v", r.list)
			}
			if r.saved[0].Bypass != nil || r.saved[0].Wanted != s.Wanted {
				t.Errorf("первая запись %+v", r.saved[0])
			}
			if got.Bypass != nil {
				t.Errorf("поле не очищено: %+v", got)
			}
		})
	}
}

func TestRecoverWithoutRoutesRemovesNothing(t *testing.T) {
	r := &recovery{}
	s := statefile.State{Wanted: true, BootUnix: 1000}
	if _, err := recoverAfterStart(r, s, 1000, r.remove, r.save); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.list, []string{"await"}) {
		t.Fatalf("порядок %v", r.list)
	}
}

// Сбой снятия маршрутов не должен оставить человека без блокировки.
func TestRecoverContinuesAfterRemoveError(t *testing.T) {
	failure := errors.New("отказ")
	r := &recovery{removeErr: failure}
	s := statefile.State{Wanted: true, KillSwitch: true, BootUnix: 1000, Bypass: testBypass}
	got, err := recoverAfterStart(r, s, 1000, r.remove, r.save)
	if !errors.Is(err, failure) {
		t.Fatalf("ошибка %v", err)
	}
	if !slices.Equal(r.list, []string{"remove", "save", "block"}) || got.Bypass != nil {
		t.Fatalf("порядок %v, состояние %+v", r.list, got)
	}
}

// Устаревший признак не должен вернуться в файл со следующей записью маршрутов.
func TestRecoverOtherBootForgetsWanted(t *testing.T) {
	r := &recovery{}
	s := statefile.State{Wanted: true, KillSwitch: true, BootUnix: 1000}
	got, err := recoverAfterStart(r, s, 5000, r.remove, r.save)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, statefile.State{}) {
		t.Fatalf("состояние %+v", got)
	}
}

func TestCommandsSaveApplied(t *testing.T) {
	tun, st := &fakeTunnel{}, &stateLog{routes: testBypass}
	c := newCommands(tun, st, &logCatcher{})
	if err := c.Connect(ksRequest); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(st.saved[0].Bypass, testBypass) {
		t.Fatalf("после подключения %+v", st.saved[0])
	}

	// Маршрут, который не снялся, остаётся в файле: его снимет следующий запуск.
	c.Disconnect()
	last := st.saved[len(st.saved)-1]
	if last.Wanted || !slices.Equal(last.Bypass, testBypass) {
		t.Fatalf("после отключения %+v", last)
	}
}

func TestSyncBypassKeepsWanted(t *testing.T) {
	tun, st := &fakeTunnel{}, &stateLog{}
	c := newCommands(tun, st, &logCatcher{})
	if err := c.Connect(ksRequest); err != nil {
		t.Fatal(err)
	}
	st.saved = nil

	st.routes = testBypass
	c.syncBypass()
	if len(st.saved) != 1 || !st.saved[0].Wanted || !st.saved[0].KillSwitch ||
		!slices.Equal(st.saved[0].Bypass, testBypass) {
		t.Fatalf("записано %+v", st.saved)
	}

	// Без перемен файл не трогаем: сигнал приходит и тогда, когда набор остался прежним.
	c.syncBypass()
	if len(st.saved) != 1 {
		t.Fatalf("лишняя запись %+v", st.saved)
	}
}

func TestCommandsLogsAndStatus(t *testing.T) {
	c := newCommands(&fakeTunnel{}, &stateLog{}, &logCatcher{})
	if got := c.Logs(); !slices.Equal(got, []string{"строка"}) {
		t.Fatalf("Logs = %v", got)
	}
	if got := c.Status(); got.Phase != model.PhaseIdle {
		t.Fatalf("Status = %+v", got)
	}
}

// loopEvents собирает порядок вызовов цикла тактов.
type loopEvents struct {
	mu   sync.Mutex
	list []string
}

func (l *loopEvents) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = append(l.list, s)
}

func (l *loopEvents) get() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.list)
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("не дождались: " + what)
		}
		time.Sleep(time.Millisecond)
	}
}

// Такт, накопившийся за время сна, не должен обогнать пробуждение.
func TestTickLoopWokeGoesFirst(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time, 1)
	wake := make(chan struct{}, 1)
	ticks <- time.Now()
	wake <- struct{}{}

	ev := &loopEvents{}
	go tickLoop(ctx, ticks, wake, func(time.Time) { ev.add("tick") }, func() { ev.add("woke") })

	waitUntil(t, "оба вызова", func() bool { return len(ev.get()) == 2 })
	if got := ev.get(); !slices.Equal(got, []string{"woke", "tick"}) {
		t.Fatalf("порядок %v", got)
	}
}

// Пока такт идёт, ни следующий такт, ни пробуждение не начинаются, а пробуждение идёт первым.
func TestTickLoopNeverOverlaps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time, 1)
	wake := make(chan struct{}, 1)
	gate := make(chan struct{})

	var active, peak atomic.Int32
	enter := func() {
		if n := active.Add(1); n > peak.Load() {
			peak.Store(n)
		}
	}
	ev := &loopEvents{}
	onTick := func(time.Time) {
		enter()
		defer active.Add(-1)
		ev.add("tick")
		<-gate
	}
	onWake := func() {
		enter()
		defer active.Add(-1)
		ev.add("woke")
	}
	go tickLoop(ctx, ticks, wake, onTick, onWake)

	ticks <- time.Now()
	waitUntil(t, "первый такт", func() bool { return len(ev.get()) == 1 })
	ticks <- time.Now()
	wake <- struct{}{}
	time.Sleep(10 * time.Millisecond)
	if got := ev.get(); len(got) != 1 {
		t.Fatalf("вызовы при идущем такте: %v", got)
	}

	close(gate)
	waitUntil(t, "все вызовы", func() bool { return len(ev.get()) == 3 })
	if got := ev.get(); !slices.Equal(got, []string{"tick", "woke", "tick"}) {
		t.Fatalf("порядок %v", got)
	}
	if peak.Load() != 1 {
		t.Fatalf("одновременно %d вызовов", peak.Load())
	}
}

func TestTickLoopStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tickLoop(ctx, nil, nil, func(time.Time) {}, func() {})
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("цикл не остановился")
	}
}

// NetworkChanged может блокироваться: сколько бы событий ни пришло, один вызов идёт и один ждёт.
func TestSerialCoalesces(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pending := make(chan struct{}, 1)
	gate := make(chan struct{})
	var calls atomic.Int32
	go serial(ctx, pending, func() {
		calls.Add(1)
		<-gate
	})

	notify(pending)
	waitUntil(t, "первый вызов", func() bool { return calls.Load() == 1 })
	for range 100 {
		notify(pending)
	}
	close(gate)
	waitUntil(t, "второй вызов", func() bool { return calls.Load() == 2 })
	time.Sleep(10 * time.Millisecond)
	if n := calls.Load(); n != 2 {
		t.Fatalf("вызовов %d", n)
	}
}

func TestDataDirSDDL(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString(dataDirSDDL)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Error("наследование прав не отключено")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl.AceCount != 2 {
		t.Fatalf("записей %d", dacl.AceCount)
	}
	const fileAll = 0x1F01FF
	want := []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid}
	for i, kind := range want {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsWellKnown(kind) || ace.Mask != fileAll {
			t.Errorf("запись %d: %s, маска %#x", i, sid, ace.Mask)
		}
		if ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) !=
			windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE {
			t.Errorf("запись %d не наследуется файлами и папками", i)
		}
	}
}

// Владелец канала службы должен быть ровно LocalSystem: окно проверяет это в Dial.
func TestServicePipeOwner(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString(servicePipeSDDL)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if !owner.IsWellKnown(windows.WinLocalSystemSid) {
		t.Fatalf("владелец %s", owner)
	}
}

func TestDataPathsFor(t *testing.T) {
	p := dataPathsFor(`C:\ProgramData`)
	want := dataPaths{
		root:  `C:\ProgramData\FreeTurn`,
		core:  `C:\ProgramData\FreeTurn\core`,
		logs:  `C:\ProgramData\FreeTurn\logs`,
		state: `C:\ProgramData\FreeTurn\state.json`,
	}
	if p != want {
		t.Fatalf("пути %+v", p)
	}
}

// Каталог в ProgramData может создать любой пользователь: ссылка вместо него увела бы права
// и файлы службы в чужое место.
func TestCheckDirRejectsNonDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := checkDir(dir); err != nil {
		t.Fatalf("каталог: %v", err)
	}
	file := filepath.Join(dir, "файл")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkDir(file); err == nil {
		t.Error("файл принят за каталог")
	}
	if err := checkDir(filepath.Join(dir, "нет")); err == nil {
		t.Error("пустой путь принят")
	}
}

func TestSingleInstance(t *testing.T) {
	name := fmt.Sprintf(`Local\FreeTurnServiceTest-%d`, os.Getpid())
	release, err := singleInstance(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := singleInstance(name); err == nil {
		t.Fatal("второй экземпляр запустился")
	}
	release()
	release, err = singleInstance(name)
	if err != nil {
		t.Fatalf("после освобождения: %v", err)
	}
	release()
}

// Канал может не закрыться: namedpipe теряет сигнал закрытия, если клиент ушёл в тот же момент.
// Служба из-за этого не должна зависнуть на остановке.
func TestCloseWithinGivesUpOnHang(t *testing.T) {
	hang := make(chan struct{})
	defer close(hang)
	if closeWithin(func() { <-hang }, 10*time.Millisecond) {
		t.Fatal("зависшее закрытие считается успешным")
	}
}

func TestCloseWithinWaitsForClose(t *testing.T) {
	closed := false
	if !closeWithin(func() { closed = true }, time.Minute) || !closed {
		t.Fatalf("закрыто %v", closed)
	}
}

// Рассылка до открытия канала не должна падать: ArmBlock меняет статус раньше ipc.Serve.
func TestEventRelayBeforeServe(t *testing.T) {
	var r eventRelay
	r.send(ipc.Event{Kind: ipc.KindLog, Log: "строка"})
}
