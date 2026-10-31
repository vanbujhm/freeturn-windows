package corehost

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/samosvalishe/free-turn-proxy/mobile"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// Тестовые значения: ссылки и ключи выдуманы, в настоящие не превращаются.
const (
	testListen = "127.0.0.1:40123"
	testLink   = "test-call-link-0000"
)

func testProfile() model.Profile {
	return model.Profile{
		ID:             "p1",
		Name:           "тест",
		Provider:       "vk",
		Peer:           "203.0.113.5:56000",
		Transport:      "udp",
		ObfProfile:     "rtpopus",
		ObfKey:         strings.Repeat("ab", 32), // 32 байта hex, выдуманный
		ObfTimingMs:    30,
		Threads:        8,
		StreamsPerCred: 4,
		MTU:            1280,
		ClientID:       "test-client-id-0000",
		CallLink:       testLink,
		DNSMode:        "doh",
		DNSServers:     []string{"1.1.1.1", "9.9.9.9"},
		WGConfig:       "не используется",
	}
}

func buildMap(t *testing.T, p model.Profile) map[string]any {
	t.Helper()
	raw, err := BuildConfigJSON(p, netip.MustParseAddrPort(testListen))
	if err != nil {
		t.Fatalf("BuildConfigJSON: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("json: %v", err)
	}
	return m
}

func sec(t *testing.T, m map[string]any, name string) map[string]any {
	t.Helper()
	s, ok := m[name].(map[string]any)
	if !ok {
		t.Fatalf("нет секции %q в %v", name, m)
	}
	return s
}

func TestBuildConfigJSONValid(t *testing.T) {
	for _, provider := range []string{"vk", "direct"} {
		p := testProfile()
		p.Provider = provider
		if provider == "direct" {
			p.CallLink = ""
		}
		raw, err := BuildConfigJSON(p, netip.MustParseAddrPort(testListen))
		if err != nil {
			t.Fatalf("%s: BuildConfigJSON: %v", provider, err)
		}
		if msg := mobile.ValidateConfig(raw); msg != "" {
			t.Errorf("%s: ValidateConfig: %s", provider, msg)
		}
	}
}

func TestBuildConfigHasNoTunnel(t *testing.T) {
	m := buildMap(t, testProfile())
	if m["routes"] != false {
		t.Errorf("routes = %v, want false", m["routes"])
	}
	if got := sec(t, m, "proxy")["mode"]; got != "udp" {
		t.Errorf("proxy.mode = %v, want udp", got)
	}
	tun := sec(t, m, "tunnel")
	if tun["mode"] != "none" || tun["config"] != "" {
		t.Errorf("tunnel = %v, want mode none и пустой config", tun)
	}
}

func TestBuildConfigListen(t *testing.T) {
	m := buildMap(t, testProfile())
	if got := sec(t, m, "proxy")["listen"]; got != testListen {
		t.Errorf("proxy.listen = %v, want %s", got, testListen)
	}
}

func TestBuildConfigFields(t *testing.T) {
	p := testProfile()
	m := buildMap(t, p)

	if m["peer"] != p.Peer || m["clientId"] != p.ClientID || m["provider"] != "vk" {
		t.Errorf("верхний уровень: %v", m)
	}
	vk := sec(t, m, "vk")
	links, _ := vk["links"].([]any)
	if len(links) != 1 || links[0] != testLink {
		t.Errorf("vk.links = %v, want [%s]", vk["links"], testLink)
	}
	if vk["streamsPerCred"] != float64(4) {
		t.Errorf("vk.streamsPerCred = %v", vk["streamsPerCred"])
	}
	obf := sec(t, m, "obf")
	if obf["profile"] != p.ObfProfile || obf["key"] != p.ObfKey || obf["timingMs"] != float64(30) {
		t.Errorf("obf = %v", obf)
	}
	dns := sec(t, m, "dns")
	servers, _ := dns["servers"].([]any)
	if dns["mode"] != "doh" || len(servers) != 2 || servers[0] != "1.1.1.1" {
		t.Errorf("dns = %v", dns)
	}
	turn := sec(t, m, "turn")
	if turn["n"] != float64(8) || turn["transport"] != "udp" {
		t.Errorf("turn = %v", turn)
	}
}

func TestBuildConfigDirectHasNoLinks(t *testing.T) {
	p := testProfile()
	p.Provider = "direct"
	p.CallLink = "не должна попасть"
	vk := sec(t, buildMap(t, p), "vk")
	if links, _ := vk["links"].([]any); len(links) != 0 {
		t.Errorf("vk.links = %v, want пусто", vk["links"])
	}
}

func TestBuildConfigKeepsDefaults(t *testing.T) {
	var def map[string]any
	if err := json.Unmarshal([]byte(mobile.DefaultConfigJSON()), &def); err != nil {
		t.Fatal(err)
	}
	p := model.Profile{Provider: "vk", Peer: "203.0.113.5:56000", ClientID: "c", CallLink: testLink}
	m := buildMap(t, p)

	defTurn, turn := sec(t, def, "turn"), sec(t, m, "turn")
	for _, k := range []string{"n", "transport", "host", "port"} {
		if defTurn[k] != turn[k] {
			t.Errorf("turn.%s = %v, want по умолчанию %v", k, turn[k], defTurn[k])
		}
	}
	defObf, obf := sec(t, def, "obf"), sec(t, m, "obf")
	if defObf["profile"] != obf["profile"] {
		t.Errorf("obf.profile = %v, want %v", obf["profile"], defObf["profile"])
	}
	if sec(t, def, "dns")["mode"] != sec(t, m, "dns")["mode"] {
		t.Errorf("dns.mode не по умолчанию")
	}
	// Секции, которых нет в профиле, не теряются.
	for _, k := range []string{"kcp", "log"} {
		if _, ok := m[k]; !ok {
			t.Errorf("секция %q потеряна", k)
		}
	}
}

func TestBuildConfigRejectsMissingPeerKeepsError(t *testing.T) {
	p := testProfile()
	p.Peer = ""
	raw, err := BuildConfigJSON(p, netip.MustParseAddrPort(testListen))
	if err != nil {
		t.Fatal(err)
	}
	if mobile.ValidateConfig(raw) == "" {
		t.Error("пустой peer должен отвергаться ядром")
	}
}
