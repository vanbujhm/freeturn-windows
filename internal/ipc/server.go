package ipc

import (
	"bufio"
	"encoding/json"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/ipc/namedpipe"
	"golang.org/x/sys/windows"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// Handler - то, чем служба отвечает на команды окна. Вызовы одного клиента идут по одному,
// в его потоке. Connect возвращается быстро, Disconnect может ждать секунды: события этого
// клиента идут своим потоком записи и не ждут.
type Handler interface {
	Connect(model.ConnectRequest) error
	Disconnect()
	Status() model.Status
	Logs() []string
}

// Server принимает клиентов на именованном канале.
type Server struct {
	h  Handler
	ln net.Listener

	mu      sync.Mutex
	clients map[*srvClient]struct{}
	closed  bool

	closeOnce  sync.Once
	acceptDone chan struct{}
}

// Serve открывает канал path с правами sddl и принимает клиентов в фоне. Если sddl не
// разобрался, возвращается ошибка: канал с правами по умолчанию не создаётся.
func Serve(path, sddl string, h Handler) (*Server, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	ln, err := (&namedpipe.ListenConfig{SecurityDescriptor: sd}).Listen(path)
	if err != nil {
		return nil, err
	}
	s := &Server{
		h:          h,
		ln:         ln,
		clients:    make(map[*srvClient]struct{}),
		acceptDone: make(chan struct{}),
	}
	go s.acceptLoop()
	return s, nil
}

func (s *Server) acceptLoop() {
	defer close(s.acceptDone)
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if s.isClosed() {
				return
			}
			// Сбой одного подключения не должен останавливать приём. Пауза не даёт крутиться
			// вхолостую, если ошибка постоянная.
			time.Sleep(100 * time.Millisecond)
			continue
		}
		c := &srvClient{srv: s, conn: conn, out: newOutbox()}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			return
		}
		s.clients[c] = struct{}{}
		s.mu.Unlock()
		go c.writeLoop()
		go c.readLoop()
	}
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Broadcast ставит событие в очередь каждого клиента. Не блокируется и в канал сам не пишет:
// его зовут из потока событий ядра.
func (s *Server) Broadcast(ev Event) {
	s.mu.Lock()
	clients := make([]*srvClient, 0, len(s.clients))
	for c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.Unlock()
	if len(clients) == 0 {
		return
	}
	line, err := json.Marshal(eventMsg{Type: typeEvent, Event: ev})
	if err != nil {
		return
	}
	line = append(line, '\n')
	isStatus := ev.Kind == KindStatus
	for _, c := range clients {
		c.out.pushEvent(line, isStatus)
	}
}

// Close закрывает канал и всех клиентов. Обработчик, который уже выполняется, не ждёт.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		clients := make([]*srvClient, 0, len(s.clients))
		for c := range s.clients {
			clients = append(clients, c)
		}
		s.mu.Unlock()
		s.ln.Close()
		for _, c := range clients {
			c.close()
		}
		<-s.acceptDone
	})
}

func (s *Server) remove(c *srvClient) {
	s.mu.Lock()
	delete(s.clients, c)
	s.mu.Unlock()
}

// srvClient - одно подключение. Читает его поток readLoop, пишет поток writeLoop.
type srvClient struct {
	srv       *Server
	conn      net.Conn
	out       *outbox
	closeOnce sync.Once
}

func (c *srvClient) close() {
	c.closeOnce.Do(func() {
		c.out.close()
		c.conn.Close()
		c.srv.remove(c)
	})
}

// readLoop разбирает запросы и вызывает Handler. Любая неполадка во входе закрывает только
// этого клиента.
func (c *srvClient) readLoop() {
	defer c.close()
	sc := bufio.NewScanner(c.conn)
	sc.Buffer(make([]byte, 0, 64<<10), maxServerLine)
	for sc.Scan() {
		var req request
		if json.Unmarshal(sc.Bytes(), &req) != nil || req.Type != typeReq {
			return
		}
		resp, ok := c.handle(req)
		if !ok {
			return
		}
		line, err := json.Marshal(resp)
		if err != nil {
			return
		}
		if !c.out.pushResponse(append(line, '\n')) {
			return
		}
	}
}

// handle выполняет одну команду. false: запрос составлен неверно, клиента надо отключить.
func (c *srvClient) handle(req request) (response, bool) {
	resp := response{Type: typeResp, ID: req.ID}
	switch req.Method {
	case methodConnect:
		if req.Connect == nil {
			return resp, false
		}
		if err := c.srv.h.Connect(*req.Connect); err != nil {
			resp.Err = err.Error()
		}
	case methodDisconnect:
		c.srv.h.Disconnect()
	case methodGetStatus:
		st := c.srv.h.Status()
		resp.Status = &st
	case methodGetLogs:
		resp.Logs = c.srv.h.Logs()
	default:
		resp.Err = "неизвестная команда"
	}
	return resp, true
}

// writeLoop пишет в канал ответы и события. Клиент, который не читает, отключается по
// таймауту записи.
func (c *srvClient) writeLoop() {
	defer c.close()
	for {
		line, closed := c.out.pop()
		if closed {
			return
		}
		if line == nil {
			<-c.out.wake
			continue
		}
		c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := c.conn.Write(line); err != nil {
			return
		}
	}
}

// outbox - очередь исходящих строк одного клиента. Ответы идут раньше событий и не
// теряются: их не больше respLimit. События ограничены queueLimit; при переполнении
// новый статус вытесняет прежний, а журнал отбрасывается.
type outbox struct {
	mu     sync.Mutex
	resps  [][]byte
	events []queuedEvent
	closed bool
	wake   chan struct{}
}

type queuedEvent struct {
	line   []byte
	status bool
}

func newOutbox() *outbox {
	return &outbox{wake: make(chan struct{}, 1)}
}

func (o *outbox) signal() {
	select {
	case o.wake <- struct{}{}:
	default:
	}
}

// pushResponse ставит ответ в очередь. false: очередь ответов полна или закрыта.
func (o *outbox) pushResponse(line []byte) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || len(o.resps) >= respLimit {
		return false
	}
	o.resps = append(o.resps, line)
	o.signal()
	return true
}

// pushEvent ставит событие в очередь и никогда не ждёт.
func (o *outbox) pushEvent(line []byte, status bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return
	}
	if len(o.events) >= queueLimit {
		if !status {
			return
		}
		// Очередь полна: новый статус занимает место прежнего статуса, а если статусов нет,
		// самого старого события.
		i := slices.IndexFunc(o.events, func(e queuedEvent) bool { return e.status })
		if i < 0 {
			i = 0
		}
		o.events = slices.Delete(o.events, i, i+1)
	}
	o.events = append(o.events, queuedEvent{line: line, status: status})
	o.signal()
}

// pop отдаёт следующую строку: ответ, иначе событие. nil без closed: очередь пуста.
func (o *outbox) pop() (line []byte, closed bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil, true
	}
	if len(o.resps) > 0 {
		line = o.resps[0]
		o.resps = o.resps[1:]
		return line, false
	}
	if len(o.events) > 0 {
		line = o.events[0].line
		o.events = o.events[1:]
		return line, false
	}
	return nil, false
}

func (o *outbox) close() {
	o.mu.Lock()
	o.closed = true
	o.resps, o.events = nil, nil
	o.mu.Unlock()
	o.signal()
}
