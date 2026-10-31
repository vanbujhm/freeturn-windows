// Пакет tunnel поднимает WireGuard-устройство поверх адаптера Wintun.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"

	"github.com/vanbujhm/freeturn-windows/internal/wgconf"
)

// AdapterName - имя адаптера Wintun в системе.
const AdapterName = "FreeTurn"

// ErrNoWintun: wintun.dll не загружается, туннель поднять нечем.
var ErrNoWintun = errors.New("tunnel: нет wintun.dll")

// handshakePollInterval - период опроса времени последнего рукопожатия.
const handshakePollInterval = 250 * time.Millisecond

// adapterGUID фиксирует GUID адаптера, чтобы Windows не плодила сетевые профили
// при каждом подключении. Не совпадает с адаптерами других VPN.
var adapterGUID = windows.GUID{
	Data1: 0x7E0B0F52, Data2: 0x5C3D, Data3: 0x4F1B,
	Data4: [8]byte{0x9A, 0x6E, 0x3D, 0x1C, 0x2B, 0x7A, 0x4F, 0x10},
}

func init() {
	tun.WintunTunnelType = "FreeTurn"
}

// Stats - счётчики туннеля по всем пирам.
type Stats struct {
	RxBytes, TxBytes int64
	// LastHandshake нулевое, пока рукопожатия не было.
	LastHandshake time.Time
}

// Device - работающее WireGuard-устройство с адаптером Wintun.
type Device struct {
	dev  *device.Device
	luid uint64
	once sync.Once
}

// Open создаёт адаптер и поднимает WireGuard с пиром, подключённым к endpoint.
// При любой ошибке созданное закрывается. Нужны права администратора и wintun.dll рядом с exe.
func Open(cfg *wgconf.Config, endpoint netip.AddrPort, logf func(string, ...any)) (*Device, error) {
	if cfg == nil {
		return nil, errors.New("tunnel: пустой конфиг")
	}
	uapi, err := cfg.UAPIFor(endpoint)
	if err != nil {
		return nil, err
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}

	tdev, err := tun.CreateTUNWithRequestedGUID(AdapterName, &adapterGUID, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("tunnel: создание адаптера: %w", err)
	}
	withLUID, ok := tdev.(interface{ LUID() uint64 })
	if !ok {
		tdev.Close()
		return nil, errors.New("tunnel: адаптер не отдаёт LUID")
	}
	luid := withLUID.LUID()

	// Подробный журнал устройства не нужен: в журнал идут только ошибки.
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: logf}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: настройка WireGuard: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: запуск WireGuard: %w", err)
	}
	return &Device{dev: dev, luid: luid}, nil
}

// LUID возвращает LUID адаптера.
func (d *Device) LUID() uint64 { return d.luid }

// WaitHandshake ждёт первого рукопожатия до отмены ctx.
func (d *Device) WaitHandshake(ctx context.Context) error {
	t := time.NewTicker(handshakePollInterval)
	defer t.Stop()
	for {
		st, err := d.Stats()
		if err != nil {
			return err
		}
		if !st.LastHandshake.IsZero() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Stats читает счётчики устройства.
func (d *Device) Stats() (Stats, error) {
	raw, err := d.dev.IpcGet()
	if err != nil {
		return Stats{}, fmt.Errorf("tunnel: чтение статистики: %w", err)
	}
	return parseStats(raw), nil
}

// Close останавливает WireGuard и удаляет адаптер. Повторный вызов безопасен.
func (d *Device) Close() {
	d.once.Do(d.dev.Close)
}

// CheckDLL проверяет, что wintun.dll загружается оттуда же, откуда её берёт пакет wintun.
// Отдельная проверка нужна ради понятной ошибки: файл мог удалить антивирус.
func CheckDLL() error {
	const search = windows.LOAD_LIBRARY_SEARCH_APPLICATION_DIR | windows.LOAD_LIBRARY_SEARCH_SYSTEM32
	h, err := windows.LoadLibraryEx("wintun.dll", 0, search)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoWintun, err)
	}
	windows.FreeLibrary(h)
	return nil
}

// RemoveStale убирает адаптер, оставшийся от прошлого запуска. Отсутствие адаптера не ошибка.
// Закрытие открытого через OpenAdapter дескриптора адаптер не удаляет: Wintun удаляет только
// адаптер, созданный этим процессом. Поэтому существующий адаптер закрывается, затем создаётся
// заново (с тем же именем и GUID он переиспользуется) и закрывается, что его удаляет.
func RemoveStale() error {
	if err := CheckDLL(); err != nil {
		return err
	}
	old, err := wintun.OpenAdapter(AdapterName)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("tunnel: проверка старого адаптера: %w", err)
	}
	old.Close()

	a, err := wintun.CreateAdapter(AdapterName, tun.WintunTunnelType, &adapterGUID)
	if err != nil {
		return fmt.Errorf("tunnel: захват старого адаптера: %w", err)
	}
	if err := a.Close(); err != nil {
		return fmt.Errorf("tunnel: удаление старого адаптера: %w", err)
	}
	return nil
}

func isNotFound(err error) bool {
	return errors.Is(err, windows.ERROR_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}

// parseStats разбирает ответ IpcGet. Алгоритм повторяет parseStats из tunnel/awg ядра.
func parseStats(uapi string) Stats {
	var st Stats
	var handshakeSec int64

	for _, ln := range strings.Split(uapi, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(ln), "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "rx_bytes":
			st.RxBytes += n
		case "tx_bytes":
			st.TxBytes += n
		case "last_handshake_time_sec":
			if n > handshakeSec {
				handshakeSec = n
			}
		}
	}
	if handshakeSec > 0 {
		st.LastHandshake = time.Unix(handshakeSec, 0)
	}
	return st
}
