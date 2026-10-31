package corehost

import (
	"net/netip"

	"github.com/samosvalishe/free-turn-proxy/mobile"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// Sink - приёмник событий ядра (состояние, журнал, капча).
type Sink = mobile.EventSink

// Host управляет единственной сессией ядра. Состояние ядра глобально,
// поэтому в процессе живёт один Host.
type Host struct{}

// New задаёт каталог состояния, приёмник событий и защиту сокетов ядра.
// Вызывается один раз за процесс.
func New(stateDir string, sink Sink, protector mobile.Protector) *Host {
	mobile.SetStateDir(stateDir)
	mobile.SetEventSink(sink)
	mobile.SetProtect(protector)
	return &Host{}
}

// Start запускает ядро для профиля: UDP-релей слушает listen, WireGuard подключается к нему.
func (h *Host) Start(p model.Profile, listen netip.AddrPort) error {
	cfg, err := BuildConfigJSON(p, listen)
	if err != nil {
		return err
	}
	return mobile.Start(cfg)
}

// Stop останавливает ядро и ждёт освобождения ресурсов.
func (h *Host) Stop() { mobile.Stop() }

// Reconnect пересоздаёт TURN-аллокации, не трогая туннель.
func (h *Host) Reconnect() { mobile.Reconnect() }

// Wake форсирует пересоздание аллокаций после пробуждения системы.
func (h *Host) Wake() { mobile.Wake() }

// Rates возвращает суммарный и текущий трафик ядра в байтах и байтах в секунду.
func (h *Host) Rates() (txTotal, rxTotal, txRate, rxRate int64) {
	s := mobile.GetState()
	return s.TxTotal, s.RxTotal, s.TxRate, s.RxRate
}
