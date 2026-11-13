package netcfg

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Правило NRPT направляет все имена (".") на DNS-прокси сеанса. Ключ локальной политики
// Dnscache применяет сразу после записи и снимает сразу после удаления: это проверила проба
// scripts/nrpt-probe.ps1.
const (
	nrptBase   = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	nrptPrefix = "{FreeTurn-"
)

var nrptName = regexp.MustCompile(`^\{FreeTurn-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$`)

var (
	nrptMu  sync.Mutex
	nrptKey string // записанный ключ сеанса
)

var (
	dnsapi                 = windows.NewLazySystemDLL("dnsapi.dll")
	procFlushResolverCache = dnsapi.NewProc("DnsFlushResolverCache")
)

func newNRPTKeyName() (string, error) {
	g, err := windows.GenerateGUID()
	if err != nil {
		return "", err
	}
	return nrptPrefix + strings.Trim(g.String(), "{}") + "}", nil
}

// ownNRPTKey сообщает, что имя - ключ, созданный FreeTurn. Только такие ключи служба снимает.
func ownNRPTKey(name string) bool { return nrptName.MatchString(name) }

// AddNRPT пишет правило NRPT для "." на server. Ключ уже записан: ничего не делает.
func AddNRPT(server netip.Addr) error {
	nrptMu.Lock()
	defer nrptMu.Unlock()
	if nrptKey != "" {
		return nil
	}
	name, err := newNRPTKeyName()
	if err != nil {
		return err
	}
	path := nrptBase + `\` + name
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("NRPT: %w", err)
	}
	err = errors.Join(
		k.SetStringsValue("Name", []string{"."}),
		k.SetStringValue("GenericDNSServers", server.String()),
		k.SetDWordValue("ConfigOptions", 8),
		k.SetDWordValue("Version", 2),
	)
	k.Close()
	if err != nil {
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, path)
		return fmt.Errorf("NRPT: %w", err)
	}
	nrptKey = name
	// В кеше Dnscache лежат ответы, полученные до подключения: без сброса поддомены из него шли
	// бы мимо прокси, и маршрут для них не встал бы.
	flushDNSCache()
	return nil
}

// RemoveNRPT снимает правило сеанса и сбрасывает кеш DNS: в нём лежат ответы прокси. Без ключа
// ничего не делает. При ошибке ключ остаётся запомненным и попадёт в файл состояния.
func RemoveNRPT() error {
	nrptMu.Lock()
	defer nrptMu.Unlock()
	if nrptKey == "" {
		return nil
	}
	if err := deleteNRPTKey(nrptKey); err != nil {
		return err
	}
	nrptKey = ""
	flushDNSCache()
	return nil
}

// AppliedNRPT возвращает имя записанного ключа или пустую строку.
func AppliedNRPT() string {
	nrptMu.Lock()
	defer nrptMu.Unlock()
	return nrptKey
}

// RemoveAllNRPT снимает все ключи FreeTurn. Нужен при старте службы и при удалении программы.
func RemoveAllNRPT() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptBase, registry.ENUMERATE_SUB_KEYS)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("NRPT: %w", err)
	}
	names, err := k.ReadSubKeyNames(-1)
	k.Close()
	if err != nil {
		return fmt.Errorf("NRPT: %w", err)
	}
	var errs []error
	removed := false
	for _, name := range names {
		if ownNRPTKey(name) {
			errs = append(errs, deleteNRPTKey(name))
			removed = true
		}
	}
	if removed {
		flushDNSCache()
	}
	return errors.Join(errs...)
}

func deleteNRPTKey(name string) error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptBase+`\`+name)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("NRPT: %w", err)
	}
	return nil
}

func flushDNSCache() {
	if procFlushResolverCache.Find() == nil {
		_, _, _ = procFlushResolverCache.Call()
	}
}
