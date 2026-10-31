package wgconf

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func fakeKeyBytes(b byte) []byte {
	raw := make([]byte, KeyLen)
	for i := range raw {
		raw[i] = b
	}
	return raw
}

func fakeKey(b byte) string { return base64.StdEncoding.EncodeToString(fakeKeyBytes(b)) }

// conf собирает конфиг: extraIface - дополнительные строки [Interface], peers - число пиров.
func conf(extraIface string, peers int) string {
	var sb strings.Builder
	sb.WriteString("[Interface]\nPrivateKey = " + fakeKey(1) + "\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n")
	sb.WriteString(extraIface)
	for i := 0; i < peers; i++ {
		sb.WriteString("\n[Peer]\nPublicKey = " + fakeKey(byte(2+i)) + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = vps:51820\nPersistentKeepalive = 25\n")
	}
	return sb.String()
}

func mustParse(t *testing.T, text string, mtu int) *Config {
	t.Helper()
	cfg, err := ParseForTunnel(text, mtu)
	if err != nil {
		t.Fatalf("ParseForTunnel: %v", err)
	}
	return cfg
}

func TestParseForTunnelPlainWG(t *testing.T) {
	cfg := mustParse(t, conf("", 1), 0)
	if cfg.MTU != 1280 {
		t.Errorf("MTU = %d, want 1280", cfg.MTU)
	}
	if want := []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}; len(cfg.Addresses) != 1 || cfg.Addresses[0] != want[0] {
		t.Errorf("Addresses = %v", cfg.Addresses)
	}
	if len(cfg.DNS) != 1 || cfg.DNS[0] != netip.MustParseAddr("1.1.1.1") {
		t.Errorf("DNS = %v", cfg.DNS)
	}
	if got := cfg.AllowedPrefixes(); len(got) != 1 || got[0] != netip.MustParsePrefix("0.0.0.0/0") {
		t.Errorf("AllowedPrefixes = %v", got)
	}
}

func TestParseForTunnelMTU(t *testing.T) {
	text := conf("MTU = 1400\n", 1)
	if got := mustParse(t, text, 0).MTU; got != 1400 {
		t.Errorf("override 0: MTU = %d, want 1400", got)
	}
	if got := mustParse(t, text, 1300).MTU; got != 1300 {
		t.Errorf("override 1300: MTU = %d, want 1300", got)
	}
}

func TestParseForTunnelAmnezia(t *testing.T) {
	cfg := mustParse(t, conf("Jc = 4\nJmin = 8\nJmax = 80\nS1 = 15\nH1 = 1\n", 1), 0)
	uapi, err := cfg.UAPIFor(netip.MustParseAddrPort("127.0.0.1:40123"))
	if err != nil {
		t.Fatalf("UAPIFor: %v", err)
	}
	for _, want := range []string{"jc=4\n", "s1=15\n", "h1=1\n"} {
		if !strings.Contains(uapi, want) {
			t.Errorf("UAPI не содержит %q:\n%s", want, uapi)
		}
	}
}

func TestParseForTunnelIgnoresScripts(t *testing.T) {
	scripts := "PreUp = echo a\nPostUp = echo b\nPreDown = echo c\nPostDown = echo d\n"
	with := mustParse(t, conf(scripts, 1), 0)
	without := mustParse(t, conf("", 1), 0)
	a, err := with.UAPIFor(netip.MustParseAddrPort("127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := without.UAPIFor(netip.MustParseAddrPort("127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	if a != b || with.MTU != without.MTU || len(with.Addresses) != len(without.Addresses) {
		t.Errorf("скрипты изменили Config:\n%s\n---\n%s", a, b)
	}
}

func TestParseForTunnelPeerCount(t *testing.T) {
	for _, n := range []int{0, 2} {
		_, err := ParseForTunnel(conf("", n), 0)
		if !errors.Is(err, ErrPeerCount) {
			t.Errorf("пиров %d: err = %v, want ErrPeerCount", n, err)
		}
	}
}

func TestUAPIForSetsEndpoint(t *testing.T) {
	cfg := mustParse(t, conf("", 1), 0)
	uapi, err := cfg.UAPIFor(netip.MustParseAddrPort("127.0.0.1:40123"))
	if err != nil {
		t.Fatalf("UAPIFor: %v", err)
	}
	if !strings.Contains(uapi, "endpoint=127.0.0.1:40123\n") {
		t.Errorf("нет подставленного endpoint:\n%s", uapi)
	}
	if strings.Contains(uapi, "vps:51820") {
		t.Errorf("исходный endpoint попал в UAPI:\n%s", uapi)
	}
	if cfg.Peers[0].Endpoint != "vps:51820" {
		t.Errorf("UAPIFor изменил исходный Config: %q", cfg.Peers[0].Endpoint)
	}
}

func TestUAPIHasHexPrivateKey(t *testing.T) {
	cfg := mustParse(t, conf("", 1), 0)
	uapi, err := cfg.UAPIFor(netip.MustParseAddrPort("127.0.0.1:40123"))
	if err != nil {
		t.Fatalf("UAPIFor: %v", err)
	}
	if want := "private_key=" + hex.EncodeToString(fakeKeyBytes(1)); !strings.Contains(uapi, want) {
		t.Errorf("нет %q", want)
	}
}
