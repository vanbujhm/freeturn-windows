package engine

import (
	"context"
	"net/netip"
	"time"

	"github.com/vanbujhm/freeturn-windows/internal/firewall"
	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/tunnel"
	"github.com/vanbujhm/freeturn-windows/internal/wgconf"
)

// Core управляет ядром. Start возвращается сразу, состояние приходит в OnCoreState.
type Core interface {
	Start(p model.Profile, listen netip.AddrPort) error
	Stop()
	Reconnect()
	Wake()
	Rates() (txTotal, rxTotal, txRate, rxRate int64)
}

// TunnelDevice - работающее устройство WireGuard с адаптером.
type TunnelDevice interface {
	LUID() uint64
	WaitHandshake(ctx context.Context) error
	Stats() (tunnel.Stats, error)
	Close()
}

// Tunnels создаёт адаптер и устройство. Пир подключается к ep, локальному порту ядра.
type Tunnels interface {
	Open(cfg *wgconf.Config, ep netip.AddrPort) (TunnelDevice, error)
}

// Network меняет настройки сети Windows.
type Network interface {
	FindPhysical(exclude uint64) (model.Physical, error)
	ConfigureInterface(luid uint64, addrs []netip.Prefix, mtu int) error
	ApplyTunnelRoutes(luid uint64, allowed []netip.Prefix, dns []netip.Addr) error
	ClearTunnel(luid uint64) error
	SetBypass(ph model.Physical, p []netip.Prefix) error
	ClearBypass() error
	OtherTunnel(exclude uint64) (string, bool)
	// FakeIPTunnel: туннельный адаптер (не exclude) с DNS в 198.18.0.0/15 (fake-ip Mihomo).
	FakeIPTunnel(exclude uint64) (string, bool)
}

// Firewall ставит и снимает kill switch. Движок не вызывает его методы одновременно, кроме
// одного случая: Disable во время установки, которая не кончилась за FirewallGrace.
type Firewall interface {
	Enable(firewall.Options) error
	Update(firewall.Options) error
	Disable()
}

// Protector выводит сокеты ядра мимо туннеля через физический интерфейс.
type Protector interface {
	SetInterface(index4, index6 uint32)
}

// Resolver разрешает домены через DNS физического интерфейса. Отмена ctx прерывает
// работу, домен без адресов просто не попадает в результат. Resolve вызывается одновременно
// из нескольких горутин.
type Resolver interface {
	Resolve(ctx context.Context, domains []string, ph model.Physical) []netip.Addr
}

// Deps - всё, что движок получает снаружи. OnChange и Logf необязательны, остальные поля
// нужны всегда. Нулевые таймауты заменяются значениями из спецификации. OnChange и Logf не
// должны блокироваться: OnChange вызывается и из потока событий ядра, а Logf ещё и под
// session.netMu, откат ждёт этот замок.
type Deps struct {
	Core     Core
	Tunnels  Tunnels
	Net      Network
	FW       Firewall
	Protect  Protector
	Resolver Resolver

	FreePort func() (netip.AddrPort, error)
	// Classify переводит текст ошибки ядра в код. Служба передаёт corehost.Classify.
	Classify func(string) model.ErrorCode
	OnChange func(model.Status)
	Logf     func(level, msg string)
	Now      func() time.Time

	CoreTimeout, HandshakeTimeout time.Duration // 60 с и 20 с
	// FirewallGrace - сколько Disconnect ждёт идущий вызов брандмауэра, прежде чем снять
	// блокировку мимо него. 6 с: на 1 с больше срока начала транзакции WFP.
	FirewallGrace time.Duration
}

const (
	defaultCoreTimeout      = 60 * time.Second
	defaultHandshakeTimeout = 20 * time.Second
	defaultFirewallGrace    = 6 * time.Second
)
