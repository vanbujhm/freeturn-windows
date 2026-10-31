package secretmask

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/wgconf"
)

func TestMaskReplaces(t *testing.T) {
	if got := New("secret").Mask("a secret b"); got != "a *** b" {
		t.Errorf("got %q", got)
	}
}

func TestMaskEmptySecretIgnored(t *testing.T) {
	if got := New("").Mask("a b"); got != "a b" {
		t.Errorf("got %q", got)
	}
}

func TestMaskLongestFirst(t *testing.T) {
	if got := New("abc", "abcdef").Mask("abcdef"); got != "***" {
		t.Errorf("got %q", got)
	}
}

func TestForProfileCoversEverything(t *testing.T) {
	var priv, psk wgconf.Key
	for i := range priv {
		priv[i] = 7
		psk[i] = 9
	}
	cfg := &wgconf.Config{
		PrivateKey: priv,
		Peers:      []wgconf.Peer{{PresharedKey: psk}, {}},
	}
	p := model.Profile{
		ObfKey:   "obf-key-value",
		ClientID: "client-id-value",
		CallLink: "https://calls.example.test/join/room-segment-1?x=1",
	}
	secrets := []string{
		base64.StdEncoding.EncodeToString(priv[:]),
		hex.EncodeToString(priv[:]),
		base64.StdEncoding.EncodeToString(psk[:]),
		hex.EncodeToString(psk[:]),
		p.ObfKey, p.ClientID, p.CallLink, "room-segment-1",
	}
	m := ForProfile(p, cfg)
	for _, s := range secrets {
		if got := m.Mask("x " + s + " y"); strings.Contains(got, s) {
			t.Errorf("секрет %q не замаскирован: %q", s, got)
		}
	}
}

func TestForProfileNilConfig(t *testing.T) {
	m := ForProfile(model.Profile{ObfKey: "k1"}, nil)
	if got := m.Mask("k1"); got != "***" {
		t.Errorf("got %q", got)
	}
}

func TestForProfileShortSegmentNotMasked(t *testing.T) {
	m := ForProfile(model.Profile{CallLink: "https://host/join"}, nil)
	if got := m.Mask("join the call"); got != "join the call" {
		t.Errorf("got %q", got)
	}
	if got := m.Mask("https://host/join"); got != "***" {
		t.Errorf("ссылка целиком не замаскирована: %q", got)
	}
}

func TestMaskNilSafe(t *testing.T) {
	var nilMasker *Masker
	if got := nilMasker.Mask("abc"); got != "abc" {
		t.Errorf("nil: %q", got)
	}
	if got := (&Masker{}).Mask("abc"); got != "abc" {
		t.Errorf("zero: %q", got)
	}
}
