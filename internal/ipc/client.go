package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/ipc/namedpipe"
	"golang.org/x/sys/windows"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// callTimeout - сколько клиент ждёт ответ службы. Disconnect ждёт секунды, остальное
// отвечает сразу, так что минута означает зависшую службу.
var callTimeout = time.Minute

var (
	// ErrClosed: канал оборван или клиент закрыт.
	ErrClosed = errors.New("ipc: канал закрыт")
	// ErrTimeout: служба не ответила за callTimeout.
	ErrTimeout = errors.New("ipc: служба не отвечает")
)

// Client - подключение окна к службе. Вызовы можно делать из разных потоков.
type Client struct {
	conn    net.Conn
	onEvent func(Event)

	writeMu sync.Mutex // сериализует запись строк в канал

	mu      sync.Mutex
	nextID  uint64
	pending map[uint64]chan serverMsg

	done      chan struct{}
	closeOnce sync.Once
}

// ServiceOwner возвращает SID LocalSystem: владелец канала установленной службы.
func ServiceOwner() (*windows.SID, error) {
	return windows.CreateWellKnownSid(windows.WinLocalSystemSid)
}

// Dial подключается к каналу службы. Если owner не nil, канал, созданный кем-то другим,
// отвергается: так чужой экземпляр канала с тем же именем не получит профиль. Окно передаёт
// ServiceOwner(), nil без проверки нужен тестам и консольному запуску службы. onEvent (может быть nil) вызывается в потоке чтения
// канала, поэтому не должен блокироваться: пока он занят, ответы на вызовы не приходят.
func Dial(path string, timeout time.Duration, owner *windows.SID, onEvent func(Event)) (*Client, error) {
	conn, err := (&namedpipe.DialConfig{ExpectedOwner: owner}).DialTimeout(path, timeout)
	if err != nil {
		return nil, err
	}
	c := &Client{
		conn:    conn,
		onEvent: onEvent,
		pending: make(map[uint64]chan serverMsg),
		done:    make(chan struct{}),
	}
	go c.readLoop()
	return c, nil
}

// Done закрывается, когда канал оборван или клиент закрыт.
func (c *Client) Done() <-chan struct{} { return c.done }

// Close закрывает канал. Повторный вызов безопасен.
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		close(c.done)
		c.conn.Close()
	})
}

func (c *Client) readLoop() {
	defer c.Close()
	sc := bufio.NewScanner(c.conn)
	sc.Buffer(make([]byte, 0, 64<<10), maxClientLine)
	for sc.Scan() {
		var m serverMsg
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			return
		}
		switch m.Type {
		case typeResp:
			c.mu.Lock()
			ch := c.pending[m.ID]
			delete(c.pending, m.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- m // ёмкость 1, ответ на id приходит один раз
			}
		case typeEvent:
			if c.onEvent != nil {
				c.onEvent(m.Event)
			}
		}
	}
}

// call отправляет запрос и ждёт ответ.
func (c *Client) call(req request) (serverMsg, error) {
	ch := make(chan serverMsg, 1)
	c.mu.Lock()
	select {
	case <-c.done:
		c.mu.Unlock()
		return serverMsg{}, ErrClosed
	default:
	}
	c.nextID++
	req.Type, req.ID = typeReq, c.nextID
	c.pending[req.ID] = ch
	c.mu.Unlock()

	drop := func() {
		c.mu.Lock()
		delete(c.pending, req.ID)
		c.mu.Unlock()
	}
	line, err := json.Marshal(req)
	if err != nil {
		drop()
		return serverMsg{}, err
	}
	timer := time.NewTimer(callTimeout)
	defer timer.Stop()

	c.writeMu.Lock()
	c.conn.SetWriteDeadline(time.Now().Add(callTimeout))
	_, err = c.conn.Write(append(line, '\n'))
	c.writeMu.Unlock()
	if err != nil {
		drop()
		c.Close()
		return serverMsg{}, ErrClosed
	}

	select {
	case m := <-ch:
		if m.Err != "" {
			return m, errors.New(m.Err)
		}
		return m, nil
	case <-c.done:
		drop()
		return serverMsg{}, ErrClosed
	case <-timer.C:
		drop()
		return serverMsg{}, ErrTimeout
	}
}

// Connect просит службу подключить туннель по профилю. Ошибку службы возвращает текстом.
func (c *Client) Connect(r model.ConnectRequest) error {
	_, err := c.call(request{Method: methodConnect, Connect: &r})
	return err
}

// Disconnect просит службу отключить туннель.
func (c *Client) Disconnect() error {
	_, err := c.call(request{Method: methodDisconnect})
	return err
}

// Status возвращает текущее состояние службы.
func (c *Client) Status() (model.Status, error) {
	m, err := c.call(request{Method: methodGetStatus})
	if err != nil {
		return model.Status{}, err
	}
	if m.Status == nil {
		return model.Status{}, errors.New("ipc: в ответе нет состояния")
	}
	return *m.Status, nil
}

// Logs возвращает журнал службы.
func (c *Client) Logs() ([]string, error) {
	m, err := c.call(request{Method: methodGetLogs})
	if err != nil {
		return nil, err
	}
	return m.Logs, nil
}
