package netcfg

import (
	"errors"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// procGetBestRoute2: в winipcfg и x/sys обёртки нет.
var procGetBestRoute2 = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetBestRoute2")

// BestRoute возвращает LUID интерфейса, через который Windows отправит пакет на dst сейчас.
// Только читает таблицу маршрутов.
func BestRoute(dst netip.Addr) (uint64, error) {
	if !dst.IsValid() {
		return 0, errors.New("netcfg: пустой адрес")
	}
	var dest, source winipcfg.RawSockaddrInet
	if err := dest.SetAddr(dst.Unmap()); err != nil {
		return 0, err
	}
	var row winipcfg.MibIPforwardRow2
	r, _, _ := procGetBestRoute2.Call(
		0, // InterfaceLuid
		0, // InterfaceIndex
		0, // SourceAddress
		uintptr(unsafe.Pointer(&dest)),
		0, // AddressSortOptions
		uintptr(unsafe.Pointer(&row)),
		uintptr(unsafe.Pointer(&source)),
	)
	if r != 0 {
		return 0, windows.Errno(r)
	}
	return uint64(row.InterfaceLUID), nil
}
