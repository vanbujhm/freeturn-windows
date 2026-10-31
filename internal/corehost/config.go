// Пакет corehost оборачивает фасад ядра (пакет mobile) под нужды службы:
// сборка JSON-конфига из профиля, запуск и остановка, разбор ошибок ядра.
package corehost

import (
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/samosvalishe/free-turn-proxy/mobile"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// BuildConfigJSON накладывает значения профиля на mobile.DefaultConfigJSON().
// Так новые поля ядра не ломают сборку, а строгий разбор ядра ловит опечатки в именах.
// Встроенный туннель ядра не используется: WireGuard поднимает пакет tunnel,
// поэтому секция tunnel остаётся по умолчанию, routes выключен, режим прокси udp.
// debug включает подробный журнал ядра.
func BuildConfigJSON(p model.Profile, listen netip.AddrPort, debug bool) (string, error) {
	if !listen.IsValid() {
		return "", fmt.Errorf("corehost: неверный адрес прослушивания %v", listen)
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(mobile.DefaultConfigJSON()), &cfg); err != nil {
		return "", fmt.Errorf("corehost: разбор конфига по умолчанию: %w", err)
	}

	cfg["peer"] = p.Peer
	cfg["clientId"] = p.ClientID
	cfg["provider"] = p.Provider
	cfg["routes"] = false

	proxy := section(cfg, "proxy")
	proxy["mode"] = "udp"
	proxy["listen"] = listen.String()

	turn := section(cfg, "turn")
	if p.Threads > 0 {
		turn["n"] = p.Threads
	}
	if p.Transport != "" {
		turn["transport"] = p.Transport
	}

	vk := section(cfg, "vk")
	vk["links"] = callLinks(p)
	if p.StreamsPerCred > 0 {
		vk["streamsPerCred"] = p.StreamsPerCred
	}
	vk["manualCaptcha"] = p.ManualCaptcha

	obf := section(cfg, "obf")
	if p.ObfProfile != "" {
		obf["profile"] = p.ObfProfile
	}
	if p.ObfKey != "" {
		obf["key"] = p.ObfKey
	}
	if p.ObfTimingMs > 0 {
		obf["timingMs"] = p.ObfTimingMs
	}

	dns := section(cfg, "dns")
	if p.DNSMode != "" {
		dns["mode"] = p.DNSMode
	}
	if len(p.DNSServers) > 0 {
		dns["servers"] = p.DNSServers
	}

	section(cfg, "log")["debug"] = debug

	out, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("corehost: сборка конфига: %w", err)
	}
	return string(out), nil
}

// callLinks даёт ссылки на звонок для vk; для direct список пуст.
func callLinks(p model.Profile) []string {
	if p.Provider == "vk" && p.CallLink != "" {
		return []string{p.CallLink}
	}
	return []string{}
}

// section возвращает вложенный объект конфига, создавая его при отсутствии.
func section(cfg map[string]any, name string) map[string]any {
	if s, ok := cfg[name].(map[string]any); ok {
		return s
	}
	s := map[string]any{}
	cfg[name] = s
	return s
}
