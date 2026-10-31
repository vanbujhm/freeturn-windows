package corehost

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// coreDefaultPort - порт ядра по умолчанию, его FreePort не отдаёт.
const coreDefaultPort = 9000

// Classify переводит сообщение об ошибке ядра в код ошибки. Незнакомое сообщение - ErrCore.
func Classify(errMsg string) model.ErrorCode {
	switch {
	case strings.Contains(errMsg, "INVALID_JOIN_LINK"):
		return model.ErrInvalidCallLink
	case strings.Contains(errMsg, "CALL_FULL"):
		return model.ErrCallFull
	case strings.Contains(errMsg, "ANON_BLOCKED"):
		return model.ErrAnonBlocked
	case strings.Contains(errMsg, "FATAL_CAPTCHA_FAILED_NO_STREAMS"):
		return model.ErrCaptchaFailed
	default:
		return model.ErrCore
	}
}

// FreePort находит свободный UDP-порт на 127.0.0.1: занимает, читает номер и освобождает.
// Порт 9000 пропускается, чтобы не пересечься с адресом ядра по умолчанию.
func FreePort() (netip.AddrPort, error) {
	for range 10 {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("corehost: поиск свободного порта: %w", err)
		}
		ap, err := netip.ParseAddrPort(c.LocalAddr().String())
		c.Close()
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("corehost: разбор адреса %v: %w", c.LocalAddr(), err)
		}
		if ap.Port() != coreDefaultPort {
			return ap, nil
		}
	}
	return netip.AddrPort{}, fmt.Errorf("corehost: не удалось найти свободный порт, отличный от %d", coreDefaultPort)
}
