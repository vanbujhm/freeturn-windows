package dnsproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/windows"

	"github.com/samosvalishe/free-turn-proxy/mobile"

	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/split"
)

const (
	// ApplyWait - сколько ответ ждёт маршрута для адресов имени под правилом.
	ApplyWait = 1500 * time.Millisecond
	// QueryTimeout - срок на запрос по всем серверам стороны вместе.
	QueryTimeout = 3 * time.Second
	// MaxInflight - сколько запросов обрабатывается одновременно. UDP-запрос сверх этого
	// отбрасывается, программа повторит его сама, TCP ждёт очереди.
	MaxInflight = 512
	// tcpIdle - сколько TCP-соединение программы ждёт следующего запроса.
	tcpIdle = 10 * time.Second
)

// Listen - адрес прокси сеанса.
var Listen = netip.MustParseAddrPort("127.0.0.53:53")

// options - то, что подменяют тесты.
type options struct {
	port      uint16 // порт DNS-серверов
	applyWait time.Duration
	timeout   time.Duration
	bind      func(side Side, up Upstreams, fd uintptr) error
}

// Proxy - работающий DNS-прокси сеанса.
type Proxy struct {
	cfg  Config
	o    options
	udp  net.PacketConn
	tcp  net.Listener
	sem  chan struct{}
	ctx  context.Context
	stop context.CancelFunc
	wg   sync.WaitGroup // циклы приёма

	mu sync.RWMutex
	up Upstreams

	closeOnce sync.Once
}

// Start открывает приём по UDP и TCP на cfg.Listen. Порт TCP тот же, что у UDP.
func Start(cfg Config) (*Proxy, error) {
	return start(cfg, options{port: 53, applyWait: ApplyWait, timeout: QueryTimeout, bind: bindSocket})
}

func start(cfg Config, o options) (*Proxy, error) {
	udp, tcp, err := listen(cfg.Listen)
	if err != nil {
		return nil, err
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, string) {}
	}
	ctx, stop := context.WithCancel(context.Background())
	p := &Proxy{cfg: cfg, o: o, udp: udp, tcp: tcp, sem: make(chan struct{}, MaxInflight), ctx: ctx, stop: stop, up: cfg.Upstreams}
	p.wg.Add(2)
	go p.serveUDP()
	go p.serveTCP()
	return p, nil
}

// listen открывает UDP и TCP на одном порту. Порт 0 (тесты) выбирает система для UDP, и тот же
// номер для TCP может оказаться занят или зарезервирован: тогда берётся другой.
func listen(addr netip.AddrPort) (net.PacketConn, net.Listener, error) {
	lc := net.ListenConfig{Control: exclusive}
	attempts := 1
	if addr.Port() == 0 {
		attempts = 10
	}
	var err error
	for range attempts {
		var udp net.PacketConn
		udp, err = lc.ListenPacket(context.Background(), "udp4", addr.String())
		if err != nil {
			return nil, nil, err
		}
		port := uint16(udp.LocalAddr().(*net.UDPAddr).Port)
		var tcp net.Listener
		tcp, err = lc.Listen(context.Background(), "tcp4", netip.AddrPortFrom(addr.Addr(), port).String())
		if err == nil {
			return udp, tcp, nil
		}
		udp.Close()
	}
	return nil, nil, err
}

// exclusive не даёт другой программе занять тот же адрес поверх прокси.
func exclusive(_, _ string, c syscall.RawConn) error {
	var err error
	if cerr := c.Control(func(fd uintptr) {
		err = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, ^windows.SO_REUSEADDR, 1)
	}); cerr != nil {
		return cerr
	}
	return err
}

// Addr - адрес приёма. Нужен тестам, слушающим порт 0.
func (p *Proxy) Addr() netip.AddrPort { return p.udp.LocalAddr().(*net.UDPAddr).AddrPort() }

// SetUpstreams меняет серверы и интерфейсы сторон, например после смены физической сети.
func (p *Proxy) SetUpstreams(u Upstreams) {
	p.mu.Lock()
	p.up = u
	p.mu.Unlock()
}

func (p *Proxy) upstreams() Upstreams {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.up
}

// Close закрывает приём и ждёт выхода его циклов. Запросы в работе обрываются: их ожидание
// серверов и маршрута отменяется.
func (p *Proxy) Close() {
	p.closeOnce.Do(func() {
		p.stop()
		p.udp.Close()
		p.tcp.Close()
		p.wg.Wait()
	})
}

func (p *Proxy) serveUDP() {
	defer p.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, from, err := p.udp.ReadFrom(buf)
		if err != nil {
			if p.ctx.Err() != nil {
				return
			}
			continue // ICMP «порт недоступен» от прошлого ответа: на Windows это ошибка чтения
		}
		select {
		case p.sem <- struct{}{}:
		default:
			continue
		}
		raw := append([]byte(nil), buf[:n]...)
		go func() {
			defer func() { <-p.sem }()
			if resp := p.handle("udp", raw); resp != nil {
				_, _ = p.udp.WriteTo(resp, from)
			}
		}()
	}
}

func (p *Proxy) serveTCP() {
	defer p.wg.Done()
	for {
		c, err := p.tcp.Accept()
		if err != nil {
			if p.ctx.Err() != nil {
				return
			}
			continue
		}
		go p.serveConn(c)
	}
}

func (p *Proxy) serveConn(c net.Conn) {
	defer c.Close()
	go func() { <-p.ctx.Done(); c.Close() }()
	for {
		_ = c.SetReadDeadline(time.Now().Add(tcpIdle))
		raw, err := readTCP(c)
		if err != nil {
			return
		}
		select {
		case p.sem <- struct{}{}:
		case <-p.ctx.Done():
			return
		}
		resp := p.handle("tcp", raw)
		<-p.sem
		if resp == nil {
			return
		}
		_ = c.SetWriteDeadline(time.Now().Add(tcpIdle))
		if err := writeTCP(c, resp); err != nil {
			return
		}
	}
}

// handle отвечает на один запрос. nil: отвечать нечего (заголовок не разобрался).
func (p *Proxy) handle(network string, raw []byte) []byte {
	var parser dnsmessage.Parser
	hdr, err := parser.Start(raw)
	if err != nil || hdr.Response {
		return nil
	}
	qs, err := parser.AllQuestions()
	if err != nil || len(qs) != 1 {
		return failure(hdr, nil, dnsmessage.RCodeFormatError)
	}
	q := qs[0]
	began := time.Now()
	name := strings.TrimSuffix(q.Name.String(), ".")
	up := p.upstreams()
	cfg := p.cfg
	cfg.Upstreams = up
	ch := Choose(cfg, name)

	entry := model.QueryEntry{
		Time: began, Name: name, Type: strings.TrimPrefix(q.Type.String(), "Type"),
		Upstream: string(ch.Upstream), Route: string(ch.Route), Rule: ch.Rule,
	}
	resp, err := p.exchange(p.ctx, network, raw, hdr.ID, ch.Upstream, up)
	if err != nil {
		resp = failure(hdr, &q, dnsmessage.RCodeServerFailure)
		entry.RCode = rcodeText(dnsmessage.RCodeServerFailure)
	} else {
		rcode, addrs := inspect(resp)
		entry.RCode, entry.Addrs = rcodeText(rcode), addrs
		if ch.Rule != "" && rcode == dnsmessage.RCodeSuccess && p.cfg.Sink != nil {
			if usable := routable(addrs); len(usable) > 0 {
				entry.Late = !p.apply(usable)
			}
		}
	}
	entry.Took = time.Since(began)
	if p.cfg.Log != nil {
		p.cfg.Log.Add(entry)
	}
	return resp
}

// apply ждёт маршрута не дольше applyWait. Имя в журнал службы не пишется.
func (p *Proxy) apply(addrs []netip.Addr) bool {
	ctx, cancel := context.WithTimeout(p.ctx, p.o.applyWait)
	defer cancel()
	err := p.cfg.Sink.Apply(ctx, addrs)
	if err == nil {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		err = errors.New("маршрут не успел встать")
	}
	p.cfg.Logf(mobile.LevelWarn, "маршрут для адреса из DNS не поставлен до ответа: "+err.Error())
	return false
}

// inspect достаёт код ответа и адреса A и AAAA из раздела ответов.
func inspect(resp []byte) (dnsmessage.RCode, []netip.Addr) {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return dnsmessage.RCodeServerFailure, nil
	}
	if err := p.SkipAllQuestions(); err != nil {
		return h.RCode, nil
	}
	var addrs []netip.Addr
	for {
		rh, err := p.AnswerHeader()
		if err != nil {
			break
		}
		switch rh.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return h.RCode, addrs
			}
			addrs = append(addrs, netip.AddrFrom4(r.A))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return h.RCode, addrs
			}
			addrs = append(addrs, netip.AddrFrom16(r.AAAA).Unmap())
		default:
			if err := p.SkipAnswer(); err != nil {
				return h.RCode, addrs
			}
		}
	}
	return h.RCode, addrs
}

func routable(addrs []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if !split.Unroutable(a) {
			out = append(out, a)
		}
	}
	return out
}

// failure строит ответ с кодом ошибки на запрос hdr. q: вопрос, если он был.
func failure(hdr dnsmessage.Header, q *dnsmessage.Question, rcode dnsmessage.RCode) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: hdr.ID, Response: true, OpCode: hdr.OpCode, RecursionDesired: hdr.RecursionDesired,
		RecursionAvailable: true, RCode: rcode,
	})
	if q != nil {
		if err := b.StartQuestions(); err == nil {
			_ = b.Question(*q)
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

func rcodeText(r dnsmessage.RCode) string {
	switch r {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	default:
		return strconv.Itoa(int(r))
	}
}
