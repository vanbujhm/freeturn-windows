package dnsproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/vanbujhm/freeturn-windows/internal/protect"
)

var (
	errNoServers = errors.New("dnsproxy: у стороны нет DNS-серверов")
	errNotBound  = errors.New("dnsproxy: сокет не привязан к интерфейсу стороны")
	errNoAnswer  = errors.New("dnsproxy: серверы не ответили")
)

// bindSocket привязывает сокет к интерфейсу стороны через IP_UNICAST_IF: сокету физического
// интерфейса туннель не мешает, а сокету туннеля не нужны маршруты на DNS конфига.
func bindSocket(side Side, up Upstreams, fd uintptr) error {
	p := protect.New()
	if side == SideTunnel {
		p.SetInterface(up.Tunnel4, up.Tunnel6)
	} else {
		p.SetInterface(up.Direct4, up.Direct6)
	}
	if !p.Protect(int(fd)) {
		return errNotBound
	}
	return nil
}

// exchange пересылает запрос серверам стороны по очереди тем же транспортом, каждому равная
// доля срока. Ответ без ошибки и NXDOMAIN окончательны. Ошибка: все серверы молчат или
// ответили ошибкой, программе уходит SERVFAIL.
func (p *Proxy) exchange(ctx context.Context, network string, raw []byte, id uint16, ch Choice, up Upstreams) ([]byte, error) {
	side := ch.Upstream
	servers := up.Direct
	if side == SideTunnel {
		servers = up.Tunnel
	}
	if len(servers) == 0 {
		return nil, errNoServers
	}
	share := p.o.timeout / time.Duration(len(servers))
	for _, server := range servers {
		try, done := context.WithTimeout(ctx, share)
		resp, err := p.ask(try, network, netip.AddrPortFrom(server, p.o.port), raw, id, ch, up)
		done()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			continue
		}
		var h dnsmessage.Parser
		hdr, err := h.Start(resp)
		if err != nil {
			continue
		}
		if hdr.RCode == dnsmessage.RCodeSuccess || hdr.RCode == dnsmessage.RCodeNameError {
			return resp, nil
		}
	}
	return nil, errNoAnswer
}

// ask спрашивает один сервер. Ответ с чужим ID отбрасывается.
func (p *Proxy) ask(ctx context.Context, network string, server netip.AddrPort, raw []byte, id uint16, ch Choice, up Upstreams) ([]byte, error) {
	var d net.Dialer
	if !ch.Unbound {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var bindErr error
			if err := c.Control(func(fd uintptr) { bindErr = p.o.bind(ch.Upstream, up, fd) }); err != nil {
				return err
			}
			return bindErr
		}
	}
	c, err := d.DialContext(ctx, network, server.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	if network == "tcp" {
		if err := writeTCP(c, raw); err != nil {
			return nil, err
		}
		resp, err := readTCP(c)
		if err != nil {
			return nil, err
		}
		if !sameID(resp, id) {
			return nil, errNoAnswer
		}
		return resp, nil
	}
	if _, err := c.Write(raw); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if sameID(buf[:n], id) {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

func sameID(msg []byte, id uint16) bool {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	return err == nil && h.Response && h.ID == id
}

func readTCP(c net.Conn) ([]byte, error) {
	var n [2]byte
	if _, err := io.ReadFull(c, n[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(n[:]))
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, err
	}
	return b, nil
}

func writeTCP(c net.Conn, msg []byte) error {
	_, err := c.Write(append(binary.BigEndian.AppendUint16(make([]byte, 0, len(msg)+2), uint16(len(msg))), msg...))
	return err
}
