package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/vanbujhm/freeturn-windows/internal/ipc"
	"github.com/vanbujhm/freeturn-windows/internal/model"
)

const testSecret = "секрет-из-профиля"

// fakeTarget стоит на месте движка: запоминает события ядра и прячет testSecret.
type fakeTarget struct {
	states   []string
	captchas []string
}

func (f *fakeTarget) OnCoreState(state string, streams, total int, errMsg string) {
	f.states = append(f.states, state+"/"+errMsg)
	if streams != 2 || total != 3 {
		panic("потоки не дошли")
	}
}

func (f *fakeTarget) OnCaptcha(url string, manual bool) {
	if manual {
		f.captchas = append(f.captchas, url)
	}
}

func (f *fakeTarget) MaskLog(s string) string {
	return strings.ReplaceAll(s, testSecret, "***")
}

type logCatcher struct {
	mu    sync.Mutex
	lines []string
}

func (c *logCatcher) write(level, msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, level+": "+msg)
}

func (c *logCatcher) got() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.lines)
}

func TestCoreSinkRoutesEvents(t *testing.T) {
	target := &fakeTarget{}
	s := &coreSink{target: target, log: (&logCatcher{}).write}

	s.OnState("connected", 2, 3, "текст")
	s.OnCaptcha("http://127.0.0.1:1/", true)

	if !slices.Equal(target.states, []string{"connected/текст"}) {
		t.Errorf("состояния %v", target.states)
	}
	if !slices.Equal(target.captchas, []string{"http://127.0.0.1:1/"}) {
		t.Errorf("капчи %v", target.captchas)
	}
}

func TestCoreSinkMasksLog(t *testing.T) {
	logs := &logCatcher{}
	s := &coreSink{target: &fakeTarget{}, log: logs.write}

	s.OnLog("info", "ключ "+testSecret, 0)
	s.deviceLog("сбой %s", testSecret)

	want := []string{"info: ключ ***", "error: сбой ***"}
	if got := logs.got(); !slices.Equal(got, want) {
		t.Fatalf("журнал %q", got)
	}
}

func TestCoreSinkDebugLines(t *testing.T) {
	logs := &logCatcher{}
	s := &coreSink{target: &fakeTarget{}, log: logs.write}
	s.OnLog("debug", "подробно", 0)
	if got := logs.got(); len(got) != 0 {
		t.Fatalf("без debug строка дошла: %q", got)
	}

	s.debug = true
	s.OnLog("debug", "подробно "+testSecret, 0)
	if got := logs.got(); !slices.Equal(got, []string{"debug: подробно ***"}) {
		t.Fatalf("с debug журнал %q", got)
	}
}

// Набор маршрутов меняется только в этих двух вызовах, и файл состояния узнаёт о них отсюда.
// Пустой набор систему не трогает.
func TestSysNetReportsBypassChange(t *testing.T) {
	changes := 0
	n := sysNet{changed: func() { changes++ }}
	if err := n.SetBypass(model.Physical{}, nil); err != nil {
		t.Fatal(err)
	}
	if changes != 1 {
		t.Fatalf("после SetBypass сигналов %d", changes)
	}
	if err := n.ClearBypass(); err != nil {
		t.Fatal(err)
	}
	if changes != 2 {
		t.Fatalf("после ClearBypass сигналов %d", changes)
	}
}

// fakeRun заменяет run в тестах Execute.
type fakeRun struct {
	opts    chan runOptions
	stopped chan struct{}
	fail    error // не nil: запуск срывается до готовности
}

func newFakeRun() *fakeRun {
	return &fakeRun{opts: make(chan runOptions, 1), stopped: make(chan struct{})}
}

func (f *fakeRun) run(ctx context.Context, o runOptions) error {
	f.opts <- o
	if f.fail != nil {
		return f.fail
	}
	o.ready()
	<-ctx.Done()
	close(f.stopped)
	return nil
}

// execute запускает Execute и возвращает каналы для общения с ним.
type execution struct {
	r       chan svc.ChangeRequest
	changes chan svc.Status
	result  chan [2]uint32 // ssec как 0 или 1 и код выхода
	report  chan string    // что ушло в журнал событий Windows
}

func execute(run func(context.Context, runOptions) error, args ...string) *execution {
	e := &execution{
		r:       make(chan svc.ChangeRequest),
		changes: make(chan svc.Status, 16),
		result:  make(chan [2]uint32, 1),
		report:  make(chan string, 1),
	}
	report := func(msg string) { e.report <- msg }
	go func() {
		ssec, code := (&serviceHandler{run: run, report: report}).Execute(args, e.r, e.changes)
		out := [2]uint32{0, code}
		if ssec {
			out[0] = 1
		}
		e.result <- out
	}()
	return e
}

func (e *execution) wantState(t *testing.T, want svc.State) svc.Status {
	t.Helper()
	select {
	case st := <-e.changes:
		if st.State != want {
			t.Fatalf("состояние %d, ожидалось %d", st.State, want)
		}
		return st
	case <-time.After(5 * time.Second):
		t.Fatalf("нет перехода в состояние %d", want)
	}
	return svc.Status{}
}

func (e *execution) wantResult(t *testing.T) [2]uint32 {
	t.Helper()
	select {
	case out := <-e.result:
		return out
	case <-time.After(5 * time.Second):
		t.Fatal("Execute не завершился")
	}
	return [2]uint32{}
}

func TestExecuteStops(t *testing.T) {
	for _, cmd := range []svc.Cmd{svc.Stop, svc.Shutdown} {
		f := newFakeRun()
		e := execute(f.run, serviceName)

		if st := e.wantState(t, svc.StartPending); st.WaitHint != 30_000 {
			t.Errorf("запуск: WaitHint = %d", st.WaitHint)
		}
		st := e.wantState(t, svc.Running)
		const accepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPowerEvent
		if st.Accepts != accepted {
			t.Errorf("Accepts = %#x", st.Accepts)
		}

		e.r <- svc.ChangeRequest{Cmd: cmd}
		e.wantState(t, svc.StopPending)
		if out := e.wantResult(t); out != [2]uint32{} {
			t.Errorf("код выхода %v", out)
		}
		select {
		case <-f.stopped:
		default:
			t.Error("run не дождались")
		}
		select {
		case msg := <-e.report:
			t.Errorf("обычная остановка попала в журнал событий: %s", msg)
		default:
		}
	}
}

// Подробный журнал пишет куки и токены, поэтому установленной службе он недоступен, в том числе
// через sc start: аргументы запуска задаёт любой, кто может запускать службу.
func TestExecuteIgnoresDebugArgument(t *testing.T) {
	f := newFakeRun()
	e := execute(f.run, serviceName, debugFlag)
	o := <-f.opts
	if o.pipeSDDL != "O:SY"+ipc.PipeSDDL {
		t.Errorf("pipeSDDL = %q", o.pipeSDDL)
	}
	if o.debug {
		t.Error("-debug из аргументов запуска включил подробный журнал")
	}
	e.wantState(t, svc.StartPending)
	e.wantState(t, svc.Running)
	e.r <- svc.ChangeRequest{Cmd: svc.Stop}
	e.wantResult(t)
}

func TestExecuteResume(t *testing.T) {
	f := newFakeRun()
	e := execute(f.run, serviceName)
	o := <-f.opts
	e.wantState(t, svc.StartPending)
	e.wantState(t, svc.Running)

	// Переход в сон и другие события будить ядро не должны.
	e.r <- svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: 0x4}
	e.r <- svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: svc.Status{State: svc.Running}}
	e.wantState(t, svc.Running)
	select {
	case <-o.wake:
		t.Fatal("чужое событие питания разбудило ядро")
	default:
	}

	// Два пробуждения подряд дают один сигнал и не держат цикл службы.
	e.r <- svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: 0x12}
	e.r <- svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: 0x12}
	e.r <- svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: svc.Status{State: svc.Running}}
	e.wantState(t, svc.Running)
	select {
	case <-o.wake:
	default:
		t.Fatal("нет сигнала пробуждения")
	}

	e.r <- svc.ChangeRequest{Cmd: svc.Stop}
	e.wantState(t, svc.StopPending)
	e.wantResult(t)
}

// Ошибка запуска должна дойти до SCM кодом выхода, иначе он не перезапустит службу.
func TestExecuteRunFails(t *testing.T) {
	f := newFakeRun()
	f.fail = errors.New("канал занят")
	e := execute(f.run, serviceName)
	e.wantState(t, svc.StartPending)
	if out := e.wantResult(t); out[1] == 0 {
		t.Fatalf("код выхода %v", out)
	}
	// До открытия журнала службы это единственное место, где причина останется.
	select {
	case msg := <-e.report:
		if !strings.Contains(msg, "канал занят") {
			t.Fatalf("в журнале событий %q", msg)
		}
	default:
		t.Fatal("ошибка запуска не попала в журнал событий")
	}
}

// Сумма сроков должна быть меньше подсказки SCM, иначе он решит, что служба зависла.
func TestStopFitsWaitHint(t *testing.T) {
	hint := time.Duration(pendingWaitHintMs) * time.Millisecond
	if stopDeadline+serverCloseLimit >= hint {
		t.Fatalf("срок %v + %v, подсказка %v", stopDeadline, serverCloseLimit, hint)
	}
}
