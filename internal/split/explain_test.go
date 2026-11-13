package split

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

func rulesOf(values ...string) []model.Rule {
	out := make([]model.Rule, 0, len(values))
	for _, v := range values {
		out = append(out, model.Rule{Value: v})
	}
	return out
}

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(s))
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

func TestExplain(t *testing.T) {
	only := func(o model.Options) model.Options { o.SplitMode = model.SplitOnly; return o }
	cases := []struct {
		name     string
		opts     model.Options
		input    string
		addrs    []netip.Addr
		verdict  Verdict
		match    string
		addr     string
		offMatch string
		splitOff bool
	}{
		{"ip по правилу ip", model.Options{Rules: rulesOf("1.2.3.4")}, "1.2.3.4", nil, VerdictDirect, "1.2.3.4", "1.2.3.4", "", false},
		{"ip по правилу ip, only", only(model.Options{Rules: rulesOf("1.2.3.4")}), "1.2.3.4", nil, VerdictTunnel, "1.2.3.4", "1.2.3.4", "", false},
		{"нет совпадения", model.Options{Rules: rulesOf("1.2.3.4")}, "5.5.5.5", nil, VerdictTunnel, "", "", "", false},
		{"нет совпадения, only", only(model.Options{Rules: rulesOf("1.2.3.4")}), "5.5.5.5", nil, VerdictDirect, "", "", "", false},
		{"самая узкая подсеть", model.Options{Rules: rulesOf("10.0.0.0/8", "10.1.0.0/16")}, "10.1.2.3", nil, VerdictDirect, "10.1.0.0/16", "10.1.2.3", "", false},
		{"ip узже подсети", model.Options{Rules: rulesOf("10.0.0.0/8", "10.1.2.3")}, "10.1.2.3", nil, VerdictDirect, "10.1.2.3", "10.1.2.3", "", false},
		{"ipv6", model.Options{Rules: rulesOf("2001:db8::/32")}, "2001:db8::1", nil, VerdictDirect, "2001:db8::/32", "2001:db8::1", "", false},
		{"домен по имени", model.Options{Rules: rulesOf("example.com")}, " Example.COM. ", nil, VerdictDirect, "example.com", "", "", false},
		{"юникод-домен", model.Options{Rules: rulesOf("почта.рф")}, "Почта.РФ.", nil, VerdictDirect, "xn--80a1acny.xn--p1ai", "", "", false},
		{"поддомен совпадает с правилом домена", model.Options{Rules: rulesOf("example.com")}, "www.example.com", nil, VerdictDirect, "example.com", "", "", false},
		{"похожий суффикс не совпадает", model.Options{Rules: rulesOf("example.com")}, "badexample.com", nil, VerdictTunnel, "", "", "", false},
		{"адрес домена в подсети", model.Options{Rules: rulesOf("93.184.0.0/16")}, "example.org", addrs("93.184.216.34"), VerdictDirect, "93.184.0.0/16", "93.184.216.34", "", false},
		{"выключенное правило", model.Options{Rules: []model.Rule{{Value: "1.2.3.4", Off: true}}}, "1.2.3.4", nil, VerdictTunnel, "", "", "1.2.3.4", false},
		{"действующее важнее выключенного", model.Options{Rules: []model.Rule{{Value: "10.0.0.0/8"}, {Value: "10.1.2.3", Off: true}}}, "10.1.2.3", nil, VerdictDirect, "10.0.0.0/8", "10.1.2.3", "", false},
		{"раздельное выключено", model.Options{SplitOff: true, Rules: rulesOf("1.2.3.4")}, "1.2.3.4", nil, VerdictTunnel, "", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Explain(c.opts, c.input, c.addrs)
			if err != nil {
				t.Fatal(err)
			}
			if got.Verdict != c.verdict || got.Match.Rule.Value != c.match || got.OffMatch.Rule.Value != c.offMatch || got.SplitOff != c.splitOff {
				t.Fatalf("Explain = %+v", got)
			}
			if a := got.Match.Addr; (c.addr == "" && a.IsValid()) || (c.addr != "" && a != netip.MustParseAddr(c.addr)) {
				t.Fatalf("Match.Addr = %v, want %q", a, c.addr)
			}
		})
	}
}

func TestExplainErrors(t *testing.T) {
	cases := map[string]error{
		"":              ErrInvalid,
		"x y":           ErrInvalid,
		"*.example.com": ErrWildcard,
		"10.0.0.0/8":    ErrSubnetInput,
	}
	for in, want := range cases {
		if _, err := Explain(model.Options{}, in, nil); !errors.Is(err, want) {
			t.Errorf("Explain(%q) err = %v, want %v", in, err, want)
		}
	}
}

func TestExplainSubdomain(t *testing.T) {
	o := model.Options{Rules: rulesOf("example.com")}
	ex, err := Explain(o, "www.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ex.Match.Rule.Value != "example.com" || ex.Verdict != VerdictDirect {
		t.Fatalf("поддомен: %+v", ex)
	}
	o.Rules[0].Off = true
	ex, err = Explain(o, "www.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ex.OffMatch.Rule.Value != "example.com" || ex.Match.Rule.Value != "" {
		t.Fatalf("выключенное правило для поддомена: %+v", ex)
	}
}
