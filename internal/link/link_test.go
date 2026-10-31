package link

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"testing"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// encode собирает ссылку из набора полей, как это делает приложение-источник.
func encode(m map[string]any) string {
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return "freeturn://" + base64.RawURLEncoding.EncodeToString(b)
}

func base(extra map[string]any) map[string]any {
	m := map[string]any{"v": 1, "provider": "vk", "peer": "203.0.113.5:56000"}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestParseFull(t *testing.T) {
	raw := encode(map[string]any{
		"v": 1, "provider": "vk", "peer": "203.0.113.5:56000", "transport": "udp",
		"obf": "quic", "key": "ZmFrZS1rZXk", "timing": 20, "n": 10, "spc": 4,
		"cid": "0123456789abcdef", "vk": "https://example.test/call/FAKE",
		"dns": "custom", "dnss": "1.1.1.1, ,8.8.8.8 ", "mcap": true, "name": "Тест",
		"wg": "[Interface]\nPrivateKey = ZmFrZQ==\n", "mtu": 1300,
	})
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "Тест" || p.Provider != "vk" || p.Peer != "203.0.113.5:56000" ||
		p.Transport != "udp" || p.ObfProfile != "quic" || p.ObfKey != "ZmFrZS1rZXk" ||
		p.ObfTimingMs != 20 || p.Threads != 10 || p.StreamsPerCred != 4 || p.MTU != 1300 ||
		p.ClientID != "0123456789abcdef" || p.CallLink != "https://example.test/call/FAKE" ||
		p.DNSMode != "custom" || !slices.Equal(p.DNSServers, []string{"1.1.1.1", "8.8.8.8"}) ||
		!p.ManualCaptcha || p.WGConfig != "[Interface]\nPrivateKey = ZmFrZQ==\n" {
		t.Fatalf("профиль не совпал: %+v", p)
	}
	if p.ID != "" || p.GeneratedClientID {
		t.Fatalf("Parse не должен выдавать ID и признак сгенерированного Client ID: %+v", p)
	}
}

func TestParseNameFallsBackToPeer(t *testing.T) {
	p, err := Parse(encode(base(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "203.0.113.5:56000" {
		t.Fatalf("Name = %q", p.Name)
	}
}

func TestParseNumbersAsStrings(t *testing.T) {
	p, err := Parse(encode(base(map[string]any{"n": "10", "timing": "20"})))
	if err != nil {
		t.Fatal(err)
	}
	if p.Threads != 10 || p.ObfTimingMs != 20 {
		t.Fatalf("Threads=%d ObfTimingMs=%d", p.Threads, p.ObfTimingMs)
	}
}

func TestParseMcapBoolAndString(t *testing.T) {
	for _, v := range []any{true, "true", "TRUE"} {
		p, err := Parse(encode(base(map[string]any{"mcap": v})))
		if err != nil {
			t.Fatal(err)
		}
		if !p.ManualCaptcha {
			t.Fatalf("mcap=%v: ManualCaptcha false", v)
		}
	}
	p, err := Parse(encode(base(map[string]any{"mcap": false})))
	if err != nil || p.ManualCaptcha {
		t.Fatalf("mcap=false: %+v %v", p, err)
	}
}

func TestParseIgnoresListenBondKcp(t *testing.T) {
	raw := encode(base(map[string]any{
		"listen": "127.0.0.1:9000", "bond": true,
		"kcp": map[string]any{"nodelay": 1, "interval": 10, "acknodelay": true},
	}))
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Peer != "203.0.113.5:56000" || p.Provider != "vk" {
		t.Fatalf("%+v", p)
	}
}

func TestParseObfNoneByDefault(t *testing.T) {
	p, err := Parse(encode(base(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if p.ObfProfile != "none" {
		t.Fatalf("ObfProfile = %q", p.ObfProfile)
	}
	p, err = Parse(encode(base(map[string]any{"obf": "  "})))
	if err != nil || p.ObfProfile != "none" {
		t.Fatalf("пустой obf: %q %v", p.ObfProfile, err)
	}
}

func TestParseDirectProvider(t *testing.T) {
	p, err := Parse(encode(map[string]any{"v": 1, "provider": "direct", "peer": "203.0.113.5:56000"}))
	if err != nil {
		t.Fatal(err)
	}
	if p.Provider != "direct" || p.Threads != 0 {
		t.Fatalf("%+v", p)
	}
}

func TestParseUppercaseScheme(t *testing.T) {
	raw := encode(base(nil))
	raw = "FREETURN://" + raw[len("freeturn://"):]
	if _, err := Parse(raw); err != nil {
		t.Fatal(err)
	}
}

func TestParseStripsFragmentAndQuery(t *testing.T) {
	raw := encode(base(nil))
	for _, suffix := range []string{"#name", "?x=1", "?x=1#name"} {
		if _, err := Parse(raw + suffix); err != nil {
			t.Fatalf("%q: %v", suffix, err)
		}
	}
}

func TestParseTrimsSpaceAndNewlines(t *testing.T) {
	raw := encode(base(map[string]any{"wg": "[Interface]\nPrivateKey = ZmFrZQ==\n"}))
	mid := len(raw) / 2
	broken := "  " + raw[:mid] + "\r\n" + raw[mid:] + "\r\n"
	p, err := Parse(broken)
	if err != nil {
		t.Fatal(err)
	}
	if p.Peer != "203.0.113.5:56000" {
		t.Fatalf("%+v", p)
	}
}

func TestParseAcceptsPadding(t *testing.T) {
	b, _ := json.Marshal(base(nil))
	raw := "freeturn://" + base64.URLEncoding.EncodeToString(b)
	if _, err := Parse(raw); err != nil {
		t.Fatal(err)
	}
}

func TestParseTruncatedPayload(t *testing.T) {
	raw := encode(base(map[string]any{"wg": "[Interface]\nPrivateKey = ZmFrZQ==\n"}))
	for _, cut := range []int{len(raw) / 2, len(raw) - 1, len(raw) - 2, len(raw) - 3} {
		_, err := Parse(raw[:cut])
		if !errors.Is(err, ErrPayload) {
			t.Fatalf("обрезка до %d: err = %v", cut, err)
		}
	}
}

func TestParseGarbage(t *testing.T) {
	if _, err := Parse("hello"); !errors.Is(err, ErrScheme) {
		t.Fatalf("hello: %v", err)
	}
	if _, err := Parse(""); !errors.Is(err, ErrScheme) {
		t.Fatalf("пусто: %v", err)
	}
	if _, err := Parse("freeturn://"); !errors.Is(err, ErrPayload) {
		t.Fatalf("freeturn://: %v", err)
	}
	if _, err := Parse("freeturn://!!!!"); !errors.Is(err, ErrPayload) {
		t.Fatalf("не base64: %v", err)
	}
	notObject := "freeturn://" + base64.RawURLEncoding.EncodeToString([]byte(`[1,2]`))
	if _, err := Parse(notObject); !errors.Is(err, ErrPayload) {
		t.Fatalf("не объект: %v", err)
	}
}

func TestParseUnsupportedVersion(t *testing.T) {
	if _, err := Parse(encode(base(map[string]any{"v": 2}))); !errors.Is(err, ErrVersion) {
		t.Fatalf("v=2: %v", err)
	}
	m := base(nil)
	delete(m, "v")
	if _, err := Parse(encode(m)); !errors.Is(err, ErrVersion) {
		t.Fatalf("без v: %v", err)
	}
}

func TestParseRequired(t *testing.T) {
	for _, drop := range []string{"provider", "peer"} {
		m := base(nil)
		delete(m, drop)
		if _, err := Parse(encode(m)); !errors.Is(err, ErrRequired) {
			t.Fatalf("без %s: %v", drop, err)
		}
	}
	if _, err := Parse(encode(base(map[string]any{"peer": "  "}))); !errors.Is(err, ErrRequired) {
		t.Fatalf("пустой peer: %v", err)
	}
}

func TestParseTCPMode(t *testing.T) {
	for _, mode := range []string{"tcp", "TCP"} {
		if _, err := Parse(encode(base(map[string]any{"mode": mode}))); !errors.Is(err, ErrTCPMode) {
			t.Fatalf("mode=%s: %v", mode, err)
		}
	}
}

func TestMissing(t *testing.T) {
	p, err := Parse(encode(base(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Missing(); !slices.Equal(got, []model.Field{model.FieldCallLink, model.FieldWGConfig}) {
		t.Fatalf("vk без vk и wg: %v", got)
	}

	p, _ = Parse(encode(base(map[string]any{"vk": "https://example.test/call/FAKE"})))
	if got := p.Missing(); !slices.Equal(got, []model.Field{model.FieldWGConfig}) {
		t.Fatalf("vk без wg: %v", got)
	}

	p, _ = Parse(encode(base(map[string]any{"wg": "[Interface]\n"})))
	if got := p.Missing(); !slices.Equal(got, []model.Field{model.FieldCallLink}) {
		t.Fatalf("vk без vk: %v", got)
	}

	p, _ = Parse(encode(map[string]any{"v": 1, "provider": "direct", "peer": "203.0.113.5:56000"}))
	if got := p.Missing(); !slices.Equal(got, []model.Field{model.FieldWGConfig}) {
		t.Fatalf("direct без vk: %v", got)
	}

	p, _ = Parse(encode(base(map[string]any{"vk": "https://example.test/call/FAKE", "wg": "[Interface]\n"})))
	if got := p.Missing(); len(got) != 0 {
		t.Fatalf("всё есть: %v", got)
	}
}

func TestNewClientIDFormat(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{32}$`)
	a, b := NewClientID(), NewClientID()
	if !re.MatchString(a) || !re.MatchString(b) {
		t.Fatalf("формат: %q %q", a, b)
	}
	if a == b {
		t.Fatal("два Client ID совпали")
	}
}
