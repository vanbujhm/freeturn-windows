// Пакет protect исключает сокеты клиента из туннеля через IP_UNICAST_IF.
// Windows-аналог VpnService.protect: сокет привязывается к физическому
// интерфейсу, и маршрут по умолчанию через адаптер на него не действует.
package protect

import (
	"encoding/binary"
	"sync/atomic"

	"golang.org/x/sys/windows"
)

const (
	// ipUnicastIf и ipv6UnicastIf - опция 31 на уровнях IPPROTO_IP и IPPROTO_IPV6.
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
)

// Protector привязывает сокеты к физическому интерфейсу. Реализует mobile.Protector.
type Protector struct {
	index4 atomic.Uint32
	index6 atomic.Uint32
}

// New возвращает Protector без интерфейса: до SetInterface Protect отказывает.
func New() *Protector {
	return &Protector{}
}

// SetInterface задаёт индексы физического интерфейса для IPv4 и IPv6.
// Индекс 0 означает «не задан».
func (p *Protector) SetInterface(index4, index6 uint32) {
	p.index4.Store(index4)
	p.index6.Store(index6)
}

// encodeIndex4 переводит индекс в сетевой порядок байт: IP_UNICAST_IF
// ожидает его именно так, в отличие от IPV6_UNICAST_IF.
func encodeIndex4(index uint32) uint32 {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], index)
	return binary.NativeEndian.Uint32(b[:])
}

// Protect пробует оба семейства: двухстековый сокет Go принимает любую из опций.
// Успех любого варианта даёт true. Без заданных индексов возвращает false.
func (p *Protector) Protect(fd int) bool {
	i4, i6 := p.index4.Load(), p.index6.Load()
	if i4 == 0 && i6 == 0 {
		return false
	}
	h := windows.Handle(fd)
	ok := false
	if i4 != 0 {
		if windows.SetsockoptInt(h, windows.IPPROTO_IP, ipUnicastIf, int(encodeIndex4(i4))) == nil {
			ok = true
		}
	}
	if i6 != 0 {
		if windows.SetsockoptInt(h, windows.IPPROTO_IPV6, ipv6UnicastIf, int(i6)) == nil {
			ok = true
		}
	}
	return ok
}
