package ipc

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/ipc/namedpipe"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// stub - заглушка Handler: запоминает вызовы.
type stub struct {
	mu             sync.Mutex
	connects       []model.ConnectRequest
	disconnects    int
	connectErr     error
	status         model.Status
	logs           []string
	disconnectGate chan struct{} // если задан, Disconnect ждёт закрытия
	disconnectIn   chan struct{} // получает сигнал при входе в Disconnect
}

func (s *stub) Connect(r model.ConnectRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connects = append(s.connects, r)
	return s.connectErr
}

func (s *stub) Disconnect() {
	s.mu.Lock()
	gate, in := s.disconnectGate, s.disconnectIn
	s.disconnects++
	s.mu.Unlock()
	if in != nil {
		in <- struct{}{}
	}
	if gate != nil {
		<-gate
	}
}

func (s *stub) Status() model.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

func (s *stub) Logs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logs
}

func pipeName(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return `\\.\pipe\FreeTurnTest-` + hex.EncodeToString(b[:])
}

func startServer(t *testing.T, h Handler) (*Server, string) {
	t.Helper()
	path := pipeName(t)
	srv, err := Serve(path, PipeSDDL, h)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv, path
}

func dial(t *testing.T, path string, onEvent func(Event)) *Client {
	t.Helper()
	c, err := Dial(path, 2*time.Second, onEvent)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

func rawDial(t *testing.T, path string) net.Conn {
	t.Helper()
	conn, err := namedpipe.DialTimeout(path, 2*time.Second)
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func recvEvent(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(3 * time.Second):
		t.Fatal("событие не пришло")
		return Event{}
	}
}

func TestRoundTrip(t *testing.T) {
	h := &stub{
		status: model.Status{Phase: model.PhaseConnected, Streams: 3, Total: 4, ProfileID: "p1"},
		logs:   []string{"a", "b"},
	}
	_, path := startServer(t, h)
	c := dial(t, path, nil)

	st, err := c.Status()
	if err != nil || st.Phase != model.PhaseConnected || st.Streams != 3 || st.ProfileID != "p1" {
		t.Fatalf("Status: %+v, %v", st, err)
	}
	logs, err := c.Logs()
	if err != nil || len(logs) != 2 || logs[0] != "a" || logs[1] != "b" {
		t.Fatalf("Logs: %v, %v", logs, err)
	}
	req := model.ConnectRequest{
		Profile: model.Profile{ID: "p1", Provider: "direct", Peer: "198.51.100.7:51820"},
		Options: model.Options{KillSwitch: true, Rules: []model.Rule{{Kind: model.RuleSubnet, Value: "203.0.113.0/24"}}},
	}
	if err := c.Connect(req); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := c.Disconnect(); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.connects) != 1 || h.disconnects != 1 {
		t.Fatalf("connects=%d disconnects=%d", len(h.connects), h.disconnects)
	}
	got := h.connects[0]
	if got.Profile.ID != "p1" || got.Profile.Peer != "198.51.100.7:51820" || !got.Options.KillSwitch ||
		len(got.Options.Rules) != 1 || got.Options.Rules[0].Value != "203.0.113.0/24" {
		t.Errorf("запрос исказился: %+v", got)
	}
}

func TestConnectErrorPropagates(t *testing.T) {
	h := &stub{connectErr: errors.New("нет подключения")}
	_, path := startServer(t, h)
	c := dial(t, path, nil)
	err := c.Connect(model.ConnectRequest{})
	if err == nil || err.Error() != "нет подключения" {
		t.Fatalf("got %v", err)
	}
	// Канал после ошибки жив.
	if _, err := c.Status(); err != nil {
		t.Errorf("Status после ошибки: %v", err)
	}
}

func TestBroadcastReachesAllClients(t *testing.T) {
	srv, path := startServer(t, &stub{})
	ch1, ch2 := make(chan Event, 4), make(chan Event, 4)
	c1 := dial(t, path, func(ev Event) { ch1 <- ev })
	c2 := dial(t, path, func(ev Event) { ch2 <- ev })
	// Dial возвращается раньше, чем сервер зарегистрировал клиента: сверяемся запросом.
	for _, c := range []*Client{c1, c2} {
		if _, err := c.Status(); err != nil {
			t.Fatal(err)
		}
	}
	srv.Broadcast(Event{Kind: "status", Status: &model.Status{Phase: model.PhaseCaptcha, CaptchaURL: "https://captcha.example.test/x"}})
	srv.Broadcast(Event{Kind: "log", Log: "строка журнала"})
	for i, ch := range []chan Event{ch1, ch2} {
		ev := recvEvent(t, ch)
		if ev.Kind != "status" || ev.Status == nil || ev.Status.Phase != model.PhaseCaptcha || ev.Status.CaptchaURL == "" {
			t.Errorf("клиент %d: %+v", i, ev)
		}
		ev = recvEvent(t, ch)
		if ev.Kind != "log" || ev.Log != "строка журнала" {
			t.Errorf("клиент %d: %+v", i, ev)
		}
	}
}

func TestClientDoneOnServerClose(t *testing.T) {
	srv, path := startServer(t, &stub{})
	c := dial(t, path, nil)
	if _, err := c.Status(); err != nil {
		t.Fatal(err)
	}
	srv.Close()
	select {
	case <-c.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("Done не закрылся")
	}
	if _, err := c.Status(); err == nil {
		t.Error("вызов после обрыва должен вернуть ошибку")
	}
}

func TestClientCloseClosesDone(t *testing.T) {
	_, path := startServer(t, &stub{})
	c := dial(t, path, nil)
	c.Close()
	c.Close() // повторный вызов безопасен
	select {
	case <-c.Done():
	case <-time.After(time.Second):
		t.Fatal("Done не закрылся")
	}
}

// expectDropped проверяет, что сервер закрыл соединение: чтение заканчивается ошибкой.
func expectDropped(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	for {
		_, err := conn.Read(buf)
		if err == nil {
			continue
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal("сервер не закрыл соединение")
		}
		return
	}
}

func TestOversizedMessageRejected(t *testing.T) {
	_, path := startServer(t, &stub{})
	conn := rawDial(t, path)
	go func() {
		// Запись может оборваться, когда сервер закроет канал: это ожидаемо.
		big := make([]byte, 2<<20)
		for i := range big {
			big[i] = 'a'
		}
		conn.Write(big)
		conn.Write([]byte("\n"))
	}()
	expectDropped(t, conn)

	c := dial(t, path, nil)
	if _, err := c.Status(); err != nil {
		t.Fatalf("сервер перестал принимать: %v", err)
	}
}

func TestMalformedJSONDropsClient(t *testing.T) {
	_, path := startServer(t, &stub{status: model.Status{Phase: model.PhaseIdle}})
	good := dial(t, path, nil)
	if _, err := good.Status(); err != nil {
		t.Fatal(err)
	}
	junk := []string{
		"это не json\n",
		`{"type":"resp"}` + "\n",
		`{"type":"req","id":1,"method":"Connect"}` + "\n", // Connect без тела
	}
	for _, line := range junk {
		bad := rawDial(t, path)
		if _, err := bad.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
		expectDropped(t, bad)
	}
	if st, err := good.Status(); err != nil || st.Phase != model.PhaseIdle {
		t.Fatalf("второй клиент: %+v, %v", st, err)
	}
}

func TestUnknownMethodGetsErrorNotDrop(t *testing.T) {
	_, path := startServer(t, &stub{})
	conn := rawDial(t, path)
	if _, err := conn.Write([]byte(`{"type":"req","id":7,"method":"Nope"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(line, `"id":7`) || !strings.Contains(line, `"err"`) {
		t.Fatalf("got %q, %v", line, err)
	}
}

func TestProfileNotInEvents(t *testing.T) {
	// Ответ и событие несут только Status: в них нет ни одного поля профиля.
	h := &stub{status: model.Status{Phase: model.PhaseConnected, ProfileID: "p1"}}
	srv, path := startServer(t, h)
	conn := rawDial(t, path)
	r := bufio.NewReader(conn)
	conn.Write([]byte(`{"type":"req","id":1,"method":"GetStatus"}` + "\n"))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := r.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	srv.Broadcast(Event{Kind: "status", Status: &model.Status{Phase: model.PhaseConnected, ProfileID: "p1"}})
	ev, err := r.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{resp, ev} {
		for _, field := range []string{"CallLink", "WGConfig", "ObfKey", "ClientID", "Peer", `"Profile"`, `"connect"`} {
			if strings.Contains(line, field) {
				t.Errorf("в %q есть %s", line, field)
			}
		}
	}
	if !strings.Contains(ev, `"type":"event"`) {
		t.Errorf("не событие: %q", ev)
	}
}

func TestBlockedDisconnectDoesNotStopEvents(t *testing.T) {
	h := &stub{disconnectGate: make(chan struct{}), disconnectIn: make(chan struct{}, 1)}
	srv, path := startServer(t, h)
	ch := make(chan Event, 4)
	c := dial(t, path, func(ev Event) { ch <- ev })
	if _, err := c.Status(); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- c.Disconnect() }()
	<-h.disconnectIn // Disconnect уже висит в обработчике

	srv.Broadcast(Event{Kind: "log", Log: "во время Disconnect"})
	if ev := recvEvent(t, ch); ev.Log != "во время Disconnect" {
		t.Fatalf("got %+v", ev)
	}
	select {
	case err := <-errc:
		t.Fatalf("Disconnect вернулся раньше времени: %v", err)
	default:
	}
	close(h.disconnectGate)
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestBroadcastNeverBlocksOnStuckClient(t *testing.T) {
	srv, path := startServer(t, &stub{})
	// Клиент подключился и ничего не читает.
	stuck := rawDial(t, path)
	stuck.Write([]byte(`{"type":"req","id":1,"method":"GetStatus"}` + "\n"))
	good := make(chan Event, 1)
	c := dial(t, path, func(ev Event) {
		select {
		case good <- ev:
		default:
		}
	})
	if _, err := c.Status(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		line := strings.Repeat("x", 4096)
		for i := 0; i < 5000; i++ {
			srv.Broadcast(Event{Kind: "log", Log: line})
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Broadcast завис на медленном клиенте")
	}
	recvEvent(t, good)
}

func TestServeBadSDDLReturnsError(t *testing.T) {
	srv, err := Serve(pipeName(t), "это не SDDL", &stub{})
	if err == nil {
		srv.Close()
		t.Fatal("ожидалась ошибка")
	}
}

func TestServeSecondInstanceOnSameNameFails(t *testing.T) {
	_, path := startServer(t, &stub{})
	if srv, err := Serve(path, PipeSDDL, &stub{}); err == nil {
		srv.Close()
		t.Fatal("второй сервер на то же имя должен упасть")
	}
}

func TestDialMissingPipeTimesOut(t *testing.T) {
	start := time.Now()
	if c, err := Dial(pipeName(t), 200*time.Millisecond, nil); err == nil {
		c.Close()
		t.Fatal("ожидалась ошибка")
	}
	if time.Since(start) > 3*time.Second {
		t.Error("Dial не уложился в таймаут")
	}
}

func TestCallTimeout(t *testing.T) {
	old := callTimeout
	callTimeout = 200 * time.Millisecond
	defer func() { callTimeout = old }()

	h := &stub{disconnectGate: make(chan struct{})}
	_, path := startServer(t, h)
	defer close(h.disconnectGate)
	c := dial(t, path, nil)
	if err := c.Disconnect(); err == nil {
		t.Fatal("ожидалась ошибка по таймауту")
	}
}

// --- очередь исходящих сообщений ---

func TestOutboxOverflowKeepsLatestStatusDropsLogs(t *testing.T) {
	o := newOutbox()
	for i := 0; i < queueLimit+50; i++ {
		o.pushEvent([]byte("log"), false)
	}
	if len(o.events) != queueLimit {
		t.Fatalf("очередь %d, нужно %d", len(o.events), queueLimit)
	}
	o.pushEvent([]byte("status-1"), true)
	o.pushEvent([]byte("status-2"), true)
	var last []byte
	var statuses int
	for _, e := range o.events {
		if e.status {
			statuses++
			last = e.line
		}
	}
	if statuses != 1 || string(last) != "status-2" {
		t.Errorf("статусов %d, последний %q", statuses, last)
	}
	if len(o.events) != queueLimit {
		t.Errorf("очередь выросла: %d", len(o.events))
	}
}

func TestOutboxResponsesFirstAndBounded(t *testing.T) {
	o := newOutbox()
	o.pushEvent([]byte("ev"), false)
	if !o.pushResponse([]byte("resp")) {
		t.Fatal("ответ отвергнут")
	}
	line, closed := o.pop()
	if closed || string(line) != "resp" {
		t.Errorf("первым должен идти ответ: %q", line)
	}
	for i := 0; i < respLimit; i++ {
		o.pushResponse([]byte("r"))
	}
	if o.pushResponse([]byte("r")) {
		t.Error("очередь ответов не ограничена")
	}
}
