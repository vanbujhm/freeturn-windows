package main

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vanbujhm/freeturn-windows/internal/ipc"
	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// errNoService: канала службы сейчас нет, supervisor ждёт её возвращения.
var errNoService = errors.New("служба недоступна")

// reconnectDelay - пауза между попытками подключиться к каналу. Переменная ради тестов.
var reconnectDelay = 2 * time.Second

// eventQueue - размер очереди событий между потоком чтения канала и потоком выдачи.
const eventQueue = 256

// serviceConn - живое подключение к службе. Реализует *ipc.Client.
type serviceConn interface {
	Service
	Done() <-chan struct{}
	Close()
}

// dialer подключается к каналу службы и привязывает onEvent к подключению.
type dialer func(onEvent func(ipc.Event)) (serviceConn, error)

// supervisor держит подключение к службе: пока канала нет, пробует каждые 2 секунды,
// сообщает об обрыве один раз за простой и о возвращении. Сам реализует Service,
// поэтому API не знает о переподключениях.
type supervisor struct {
	dial dialer
	// onEvent вызывается в одной горутине выдачи, блокироваться ему можно.
	onEvent func(ipc.Event)
	onDown  func()
	// onUp вызывается после каждого подключения с текущим состоянием службы.
	onUp func(st model.Status, first bool)

	events  chan ipc.Event
	dropped atomic.Bool // событие не поместилось в очередь, состояние нужно перечитать
	stop    chan struct{}
	stopped sync.Once

	mu  sync.RWMutex
	cur serviceConn
}

func newSupervisor(dial dialer, onEvent func(ipc.Event), onDown func(), onUp func(model.Status, bool)) *supervisor {
	return &supervisor{
		dial: dial, onEvent: onEvent, onDown: onDown, onUp: onUp,
		events: make(chan ipc.Event, eventQueue),
		stop:   make(chan struct{}),
	}
}

// Start запускает подключение и выдачу событий.
func (s *supervisor) Start() {
	go s.pump()
	go s.run()
}

// Stop останавливает попытки и закрывает канал. Туннель службы не трогает. Горутины не
// ждёт: Stop зовут из OnShutdown в главном потоке, а обработчики событий обращаются к
// трею через главный поток, ожидание здесь привело бы к взаимной блокировке.
func (s *supervisor) Stop() {
	s.stopped.Do(func() { close(s.stop) })
	s.mu.RLock()
	c := s.cur
	s.mu.RUnlock()
	if c != nil {
		c.Close()
	}
}

// enqueue вызывается в потоке чтения канала: ждать и звать Status здесь нельзя, пока
// поток занят, ответы на вызовы не приходят. Если очередь полна, событие теряется, а
// pump перечитывает состояние.
func (s *supervisor) enqueue(ev ipc.Event) {
	select {
	case s.events <- ev:
	default:
		s.dropped.Store(true)
	}
}

func (s *supervisor) pump() {
	for {
		select {
		case ev := <-s.events:
			s.onEvent(ev)
		case <-s.stop:
			return
		}
		if len(s.events) == 0 && s.dropped.Swap(false) {
			if st, err := s.Status(); err == nil {
				s.onEvent(ipc.Event{Kind: ipc.KindStatus, Status: &st})
			}
		}
	}
}

func (s *supervisor) run() {
	first, down := true, false
	for {
		c, st, err := s.connect()
		if err != nil {
			if !down {
				down = true
				s.onDown()
			}
			if !s.sleep() {
				return
			}
			continue
		}
		down = false
		s.setConn(c)
		s.onUp(st, first)
		first = false

		select {
		case <-c.Done():
		case <-s.stop:
			c.Close()
			return
		}
		s.setConn(nil)
		down = true
		s.onDown()
		if !s.sleep() {
			return
		}
	}
}

// connect подключается и сразу читает состояние: канал, который не отвечает, не считается живым.
func (s *supervisor) connect() (serviceConn, model.Status, error) {
	c, err := s.dial(s.enqueue)
	if err != nil {
		return nil, model.Status{}, err
	}
	st, err := c.Status()
	if err != nil {
		c.Close()
		return nil, model.Status{}, err
	}
	return c, st, nil
}

func (s *supervisor) sleep() bool {
	t := time.NewTimer(reconnectDelay)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-s.stop:
		return false
	}
}

func (s *supervisor) setConn(c serviceConn) {
	s.mu.Lock()
	s.cur = c
	s.mu.Unlock()
}

func (s *supervisor) conn() (serviceConn, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cur == nil {
		return nil, errNoService
	}
	return s.cur, nil
}

func (s *supervisor) Connect(r model.ConnectRequest) error {
	c, err := s.conn()
	if err != nil {
		return err
	}
	return c.Connect(r)
}

func (s *supervisor) Disconnect() error {
	c, err := s.conn()
	if err != nil {
		return err
	}
	return c.Disconnect()
}

func (s *supervisor) Status() (model.Status, error) {
	c, err := s.conn()
	if err != nil {
		return model.Status{}, err
	}
	return c.Status()
}

func (s *supervisor) Logs() ([]string, error) {
	c, err := s.conn()
	if err != nil {
		return nil, err
	}
	return c.Logs()
}
