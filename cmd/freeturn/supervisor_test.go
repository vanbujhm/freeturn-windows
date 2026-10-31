package main

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vanbujhm/freeturn-windows/internal/ipc"
	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// fakeConn - подключение, которое тест может оборвать.
type fakeConn struct {
	fakeService
	done      chan struct{}
	closeOnce sync.Once
	onEvent   func(ipc.Event)
}

func newFakeConn(st model.Status) *fakeConn {
	c := &fakeConn{done: make(chan struct{})}
	c.status = st
	return c
}

func (c *fakeConn) Done() <-chan struct{} { return c.done }
func (c *fakeConn) Close()                { c.closeOnce.Do(func() { close(c.done) }) }

// script выдаёт подключения по очереди; закончились: служба недоступна.
type script struct {
	mu    sync.Mutex
	conns []*fakeConn
	dials int
}

func (s *script) dial(onEvent func(ipc.Event)) (serviceConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dials++
	if len(s.conns) == 0 {
		return nil, errors.New("канала нет")
	}
	c := s.conns[0]
	s.conns = s.conns[1:]
	c.onEvent = onEvent
	return c, nil
}

func (s *script) add(c *fakeConn) {
	s.mu.Lock()
	s.conns = append(s.conns, c)
	s.mu.Unlock()
}

// recorder собирает сигналы supervisor.
type recorder struct {
	mu     sync.Mutex
	log    []string
	events []ipc.Event
	ups    []model.Status
	firsts []bool
	wake   chan struct{}
}

func newRecorder() *recorder { return &recorder{wake: make(chan struct{}, 64)} }

func (r *recorder) note(s string) {
	r.mu.Lock()
	r.log = append(r.log, s)
	r.mu.Unlock()
	r.wake <- struct{}{}
}

func (r *recorder) onDown() { r.note("down") }
func (r *recorder) onUp(st model.Status, first bool) {
	r.mu.Lock()
	r.ups = append(r.ups, st)
	r.firsts = append(r.firsts, first)
	r.mu.Unlock()
	r.note("up")
}
func (r *recorder) onEvent(ev ipc.Event) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
	r.note("event")
}

// waitLog ждёт, пока в журнале станет n записей.
func (r *recorder) waitLog(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		r.mu.Lock()
		got := append([]string(nil), r.log...)
		r.mu.Unlock()
		if len(got) >= n {
			return got
		}
		select {
		case <-r.wake:
		case <-deadline:
			t.Fatalf("ждали %d записей, есть %v", n, got)
		}
	}
}

func fastRetry(t *testing.T) {
	t.Helper()
	old := reconnectDelay
	reconnectDelay = 5 * time.Millisecond
	t.Cleanup(func() { reconnectDelay = old })
}

func TestSupervisorServiceDownOncePerOutage(t *testing.T) {
	fastRetry(t)
	sc := &script{}
	r := newRecorder()
	s := newSupervisor(sc.dial, r.onEvent, r.onDown, r.onUp)
	s.Start()
	defer s.Stop()

	r.waitLog(t, 1)
	time.Sleep(60 * time.Millisecond) // много неудачных попыток подряд
	sc.mu.Lock()
	dials := sc.dials
	sc.mu.Unlock()
	if dials < 3 {
		t.Fatalf("попыток подключения: %d", dials)
	}
	if got := r.waitLog(t, 1); len(got) != 1 || got[0] != "down" {
		t.Fatalf("service-down не один за простой: %v", got)
	}
	if err := s.Disconnect(); !errors.Is(err, errNoService) {
		t.Fatalf("без службы Disconnect вернул %v", err)
	}

	first := newFakeConn(model.Status{Phase: model.PhaseIdle})
	sc.add(first)
	got := r.waitLog(t, 2)
	if got[1] != "up" {
		t.Fatalf("после возвращения: %v", got)
	}
	r.mu.Lock()
	if !r.firsts[0] || r.ups[0].Phase != model.PhaseIdle {
		t.Fatalf("onUp: first=%v st=%+v", r.firsts, r.ups)
	}
	r.mu.Unlock()
	if err := s.Disconnect(); err != nil || first.disconnects != 1 {
		t.Fatalf("вызов не дошёл до службы: %v", err)
	}

	// Обрыв: один down, затем возвращение с first=false.
	second := newFakeConn(model.Status{Phase: model.PhaseIdle, AwaitingProfile: true})
	sc.add(second)
	first.Close()
	got = r.waitLog(t, 4)
	if got[2] != "down" || got[3] != "up" {
		t.Fatalf("обрыв и возвращение: %v", got)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.firsts[1] || !r.ups[1].AwaitingProfile {
		t.Fatalf("повторный onUp: first=%v st=%+v", r.firsts, r.ups[1])
	}
}

func TestSupervisorDeliversEventsOffReadGoroutine(t *testing.T) {
	fastRetry(t)
	sc := &script{}
	c := newFakeConn(model.Status{Phase: model.PhaseIdle})
	sc.add(c)
	r := newRecorder()
	release := make(chan struct{})
	slow := func(ev ipc.Event) {
		<-release // обработчик долгий: чтение канала не должно встать
		r.onEvent(ev)
	}
	s := newSupervisor(sc.dial, slow, r.onDown, r.onUp)
	s.Start()
	defer s.Stop()
	r.waitLog(t, 1)

	sent := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			c.onEvent(ipc.Event{Kind: ipc.KindLog, Log: "строка"})
		}
		close(sent)
	}()
	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		t.Fatal("onEvent клиента блокируется на медленном обработчике")
	}
	close(release)
	r.waitLog(t, 11)
}

func TestSupervisorRereadsStatusAfterOverflow(t *testing.T) {
	fastRetry(t)
	sc := &script{}
	c := newFakeConn(model.Status{Phase: model.PhaseConnected})
	sc.add(c)
	r := newRecorder()
	release := make(chan struct{})
	var once sync.Once
	handler := func(ev ipc.Event) {
		once.Do(func() { <-release })
		r.onEvent(ev)
	}
	s := newSupervisor(sc.dial, handler, r.onDown, r.onUp)
	s.Start()
	defer s.Stop()
	r.waitLog(t, 1)

	for i := 0; i < eventQueue+50; i++ {
		c.onEvent(ipc.Event{Kind: ipc.KindLog, Log: "x"})
	}
	close(release)
	deadline := time.After(5 * time.Second)
	for {
		r.mu.Lock()
		var status bool
		for _, ev := range r.events {
			if ev.Kind == ipc.KindStatus && ev.Status != nil && ev.Status.Phase == model.PhaseConnected {
				status = true
			}
		}
		r.mu.Unlock()
		if status {
			return
		}
		select {
		case <-r.wake:
		case <-deadline:
			t.Fatal("после переполнения очереди состояние не перечитано")
		}
	}
}

func TestSupervisorStopClosesConn(t *testing.T) {
	fastRetry(t)
	sc := &script{}
	c := newFakeConn(model.Status{})
	sc.add(c)
	r := newRecorder()
	s := newSupervisor(sc.dial, r.onEvent, r.onDown, r.onUp)
	s.Start()
	r.waitLog(t, 1)
	s.Stop()
	select {
	case <-c.Done():
	default:
		t.Fatal("Stop не закрыл подключение")
	}
	s.Stop() // повторный вызов безопасен
}
