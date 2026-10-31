package main

import (
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/vanbujhm/freeturn-windows/internal/engine"
	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/netcfg"
	"github.com/vanbujhm/freeturn-windows/internal/statefile"
)

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
	hang        chan struct{} // не nil: Disconnect ждёт его закрытия
	entered     chan struct{} // получает сигнал при входе в Disconnect
}

func (f *fakeTunnel) Connect(model.ConnectRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connects++
	return f.connectErr
}

func (f *fakeTunnel) Disconnect() {
	f.mu.Lock()
	f.disconnects++
	hang, entered := f.hang, f.entered
	f.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
	}
	if hang != nil {
		<-hang
	}
}

func (f *fakeTunnel) Status() model.Status { return model.Status{Phase: model.PhaseIdle} }

// stateLog запоминает всё, что служба записала в файл состояния.
type stateLog struct {
	mu     sync.Mutex
	saved  []statefile.State
	err    error
	routes []netcfg.BypassRoute // набор, который сейчас стоит в системе
}

func (s *stateLog) save(st statefile.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saved = append(s.saved, st)
	return s.err
}

func (s *stateLog) lastSaved(t *testing.T) statefile.State {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.saved) == 0 {
		t.Fatal("ничего не записано")
	}
	return s.saved[len(s.saved)-1]
}

func (s *stateLog) current() []netcfg.BypassRoute {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.routes
}

func (s *stateLog) setRoutes(r []netcfg.BypassRoute) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes = r
}

func newCommands(tun *fakeTunnel, st *stateLog, logs *logCatcher) *commands {
	return &commands{
		eng:     tun,
		logs:    func() []string { return []string{"строка"} },
		save:    st.save,
		boot:    func() int64 { return 1000 },
		logf:    logs.write,
		applied: st.current,
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

// Зависшее отключение не должно оставить признак: следующий запуск вернул бы блокировку.
func TestClearWantedDuringHungDisconnect(t *testing.T) {
	tun := &fakeTunnel{hang: make(chan struct{}), entered: make(chan struct{}, 1)}
	defer close(tun.hang)
	st := &stateLog{routes: testBypass}
	c := newCommands(tun, st, &logCatcher{})
	if err := c.Connect(ksRequest); err != nil {
		t.Fatal(err)
	}
	go c.shutdown()
	<-tun.entered

	if !within(c.clearWanted, 5*time.Second) {
		t.Fatal("clearWanted ждёт зависшее отключение")
	}
	last := st.lastSaved(t)
	if last.Wanted || !last.KillSwitch || !slices.Equal(last.Bypass, testBypass) {
		t.Fatalf("записано %+v", last)
	}
}

// Запись маршрутов не ждёт отключения: их снимают как раз сейчас.
func TestSyncBypassDuringHungDisconnect(t *testing.T) {
	tun := &fakeTunnel{hang: make(chan struct{}), entered: make(chan struct{}, 1)}
	defer close(tun.hang)
	st := &stateLog{}
	c := newCommands(tun, st, &logCatcher{})
	go c.Disconnect()
	<-tun.entered

	st.setRoutes(testBypass)
	if !within(c.syncBypass, 5*time.Second) {
		t.Fatal("syncBypass ждёт зависшее отключение")
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
