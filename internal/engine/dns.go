package engine

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"

	"github.com/vanbujhm/freeturn-windows/internal/dnsproxy"
	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// MaxDynamicAddrs - сколько новых адресов из ответов DNS сеанс принимает сверх разрешённых
// заранее. Дальше маршруты не ставятся: таблица маршрутов и сессия WFP не бесконечны.
const MaxDynamicAddrs = 4096

// ErrDNSLimit: адресов из DNS за сеанс больше MaxDynamicAddrs.
var ErrDNSLimit = errors.New("предел адресов из DNS за сеанс")

// proxyDNS - адрес DNS-прокси, его получают адаптер туннеля, NRPT и разрешение брандмауэра.
var proxyDNS = dnsproxy.Listen.Addr()

// startProxy запускает DNS-прокси сеанса. Сбой не срывает подключение: оно идёт по прежней
// схеме, без поддоменов и журнала запросов. Остановка кладётся на стек отката до запуска.
func (e *Engine) startProxy(s *session) {
	if e.d.DNSProxy == nil {
		return
	}
	var i4, i6 uint32
	if e.d.TunnelIndexes != nil {
		i4, i6 = e.d.TunnelIndexes(s.luid)
	}
	a := &applier{e: e, s: s, waiting: map[netip.Addr]*batch{}}
	e.mu.Lock()
	s.tun4, s.tun6 = i4, i6
	cfg := dnsproxy.Config{
		Listen:     dnsproxy.Listen,
		Domains:    slices.Clone(s.rules.Domains),
		TunnelOnly: s.req.Options.TunnelOnly(),
		SplitOff:   s.req.Options.SplitOff,
		Upstreams:  s.upstreams(),
		Sink:       a,
		Log:        e.d.QueryLog,
		Logf:       e.logf,
	}
	e.mu.Unlock()
	s.push(func() {
		e.mu.Lock()
		p := s.proxy
		s.proxy = nil
		e.mu.Unlock()
		if p != nil {
			p.Close()
		}
	})
	p, err := e.d.DNSProxy.Start(cfg)
	if err != nil {
		e.warn(model.WarnDNSProxy, err.Error())
		e.logf(levelWarn, "DNS-прокси не запущен, поддомены и журнал запросов не работают: "+err.Error())
		return
	}
	e.mu.Lock()
	s.proxy = p
	e.mu.Unlock()
}

// upstreams собирает серверы сторон для прокси. Вызывается под e.mu.
func (s *session) upstreams() dnsproxy.Upstreams {
	return dnsproxy.Upstreams{
		Direct:  slices.Clone(s.ph.DNS),
		Tunnel:  slices.Clone(s.cfg.DNS),
		Direct4: s.ph.Index4, Direct6: s.ph.Index6,
		Tunnel4: s.tun4, Tunnel6: s.tun6,
	}
}

// ProxyActive сообщает, что DNS-прокси текущего сеанса работает.
func (e *Engine) ProxyActive() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sess != nil && e.sess.proxy != nil
}

// applier - Sink движка: ставит разрешения и маршруты для адресов из ответов DNS. Одновременные
// вызовы склеиваются в партии: пока одна применяется, адреса следующих копятся, и сессия WFP не
// пересоздаётся на каждый ответ. Каждый вызов ждёт партию, в которую попали его адреса.
type applier struct {
	e *Engine
	s *session

	mu      sync.Mutex
	open    *batch                // копит адреса до следующего применения
	running bool                  // идёт применение
	waiting map[netip.Addr]*batch // адреса, ещё не применённые
	dynamic int                   // новых адресов за сеанс
}

type batch struct {
	addrs []netip.Addr
	done  chan struct{}
	err   error
}

func (a *applier) Apply(ctx context.Context, addrs []netip.Addr) error {
	if err := a.s.stopped(); err != nil {
		return err
	}
	// Ждущие проверяются раньше известных: партия кладёт адреса в s.resolved до того, как
	// встал маршрут. Порядок замков: a.mu, потом e.mu; под e.mu a.mu никто не берёт.
	a.mu.Lock()
	var wait []*batch
	var fresh []netip.Addr
	a.e.mu.Lock()
	for _, x := range addrs {
		x = x.Unmap()
		if !x.IsValid() || slices.Contains(fresh, x) {
			continue
		}
		if b := a.waiting[x]; b != nil {
			if !slices.Contains(wait, b) {
				wait = append(wait, b)
			}
			continue
		}
		if !slices.Contains(a.s.resolved, x) {
			fresh = append(fresh, x)
		}
	}
	a.e.mu.Unlock()
	if a.dynamic+len(fresh) > MaxDynamicAddrs {
		a.mu.Unlock()
		a.e.warnOnce(model.Warning{Code: model.WarnDNSLimit})
		return ErrDNSLimit
	}
	if len(fresh) > 0 {
		if a.open == nil {
			a.open = &batch{done: make(chan struct{})}
		}
		b := a.open
		b.addrs = append(b.addrs, fresh...)
		for _, x := range fresh {
			a.waiting[x] = b
		}
		a.dynamic += len(fresh)
		if !slices.Contains(wait, b) {
			wait = append(wait, b)
		}
		if !a.running {
			a.running = true
			go a.run()
		}
	}
	a.mu.Unlock()

	for _, b := range wait {
		select {
		case <-b.done:
			if b.err != nil {
				return b.err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// run применяет партии по одной, пока они копятся.
func (a *applier) run() {
	for {
		a.mu.Lock()
		b := a.open
		a.open = nil
		if b == nil {
			a.running = false
			a.mu.Unlock()
			return
		}
		a.mu.Unlock()

		b.err = a.e.applyBatch(a.s, b.addrs)

		a.mu.Lock()
		for _, x := range b.addrs {
			delete(a.waiting, x)
		}
		a.mu.Unlock()
		close(b.done)
	}
}

// applyBatch добавляет адреса к адресам доменов сеанса и применяет их, как сверка доменов:
// сначала брандмауэр, потом маршруты.
func (e *Engine) applyBatch(s *session, addrs []netip.Addr) error {
	s.netMu.Lock()
	defer s.netMu.Unlock()
	if err := s.stopped(); err != nil {
		return err
	}
	e.mu.Lock()
	added := s.addResolved(addrs)
	opts := s.firewallOptions()
	ph := s.ph
	e.mu.Unlock()
	if !added {
		return nil
	}
	return e.applyAddresses(s, ph, opts)
}
