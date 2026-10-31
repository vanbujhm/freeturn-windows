package split

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		in   string
		want model.Rule
	}{
		{"203.0.113.7", model.Rule{Kind: model.RuleIP, Value: "203.0.113.7"}},
		{"203.0.113.0/24", model.Rule{Kind: model.RuleSubnet, Value: "203.0.113.0/24"}},
		{"Example.COM.", model.Rule{Kind: model.RuleDomain, Value: "example.com"}},
		{"  198.51.100.0/24 \n", model.Rule{Kind: model.RuleSubnet, Value: "198.51.100.0/24"}},
	}
	for _, c := range cases {
		got, err := Classify(c.in)
		if err != nil || got != c.want {
			t.Errorf("Classify(%q) = %+v, %v; want %+v", c.in, got, err, c.want)
		}
	}
}

func TestClassifyCyrillicDomain(t *testing.T) {
	got, err := Classify("Почта.РФ")
	want := model.Rule{Kind: model.RuleDomain, Value: "xn--80a1acny.xn--p1ai"}
	if err != nil || got != want {
		t.Errorf("got %+v, %v; want %+v", got, err, want)
	}
}

func TestClassifyRejects(t *testing.T) {
	for _, in := range []string{"", "   ", "not a domain!", "300.1.1.1/40", "300.1.1.1", "-a.example.com", "a..b"} {
		if _, err := Classify(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("Classify(%q): err = %v, want ErrInvalid", in, err)
		}
	}
	_, err := Classify("*.example.com")
	if !errors.Is(err, ErrWildcard) {
		t.Fatalf("err = %v, want ErrWildcard", err)
	}
	if !strings.Contains(err.Error(), "шаблон") {
		t.Errorf("текст ошибки не про шаблоны: %q", err)
	}
}

func TestCompilePrefixes(t *testing.T) {
	c := Compile([]model.Rule{
		{Kind: model.RuleIP, Value: "203.0.113.7"},
		{Kind: model.RuleIP, Value: "2001:db8::1"},
		{Kind: model.RuleSubnet, Value: "203.0.113.9/24"},
		{Kind: model.RuleDomain, Value: "example.com"},
	})
	want := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.7/32"),
		netip.MustParsePrefix("2001:db8::1/128"),
		netip.MustParsePrefix("203.0.113.0/24"),
	}
	if len(c.Prefixes) != len(want) {
		t.Fatalf("Prefixes = %v, want %v", c.Prefixes, want)
	}
	for i := range want {
		if c.Prefixes[i] != want[i] {
			t.Errorf("Prefixes[%d] = %v, want %v", i, c.Prefixes[i], want[i])
		}
	}
	if len(c.Domains) != 1 || c.Domains[0] != "example.com" {
		t.Errorf("Domains = %v", c.Domains)
	}
	if len(c.Skipped) != 0 {
		t.Errorf("Skipped = %v", c.Skipped)
	}
}

func TestCompileSkipsDefaultRoute(t *testing.T) {
	c := Compile([]model.Rule{
		{Kind: model.RuleSubnet, Value: "0.0.0.0/0"},
		{Kind: model.RuleSubnet, Value: "::/0"},
		{Kind: model.RuleSubnet, Value: "0.0.0.0/1"},
		{Kind: model.RuleSubnet, Value: "::/1"},
	})
	if len(c.Prefixes) != 0 {
		t.Errorf("Prefixes = %v, want empty", c.Prefixes)
	}
	if len(c.Skipped) != 4 {
		t.Fatalf("Skipped = %v", c.Skipped)
	}
	for _, s := range c.Skipped {
		if s.Reason != "default_route" {
			t.Errorf("%+v: Reason = %q", s.Rule, s.Reason)
		}
	}
}

func TestCompileSkipsTooWide(t *testing.T) {
	c := Compile([]model.Rule{
		{Kind: model.RuleSubnet, Value: "10.0.0.0/7"},
		{Kind: model.RuleSubnet, Value: "2001::/15"},
		{Kind: model.RuleSubnet, Value: "10.0.0.0/8"},
		{Kind: model.RuleSubnet, Value: "2001::/16"},
	})
	if len(c.Prefixes) != 2 {
		t.Errorf("Prefixes = %v, want /8 и /16", c.Prefixes)
	}
	if len(c.Skipped) != 2 {
		t.Fatalf("Skipped = %v", c.Skipped)
	}
	for _, s := range c.Skipped {
		if s.Reason != "too_wide" {
			t.Errorf("%+v: Reason = %q", s.Rule, s.Reason)
		}
	}
}

func TestCompileDedups(t *testing.T) {
	c := Compile([]model.Rule{
		{Kind: model.RuleSubnet, Value: "203.0.113.0/24"},
		{Kind: model.RuleSubnet, Value: "203.0.113.5/24"},
		{Kind: model.RuleDomain, Value: "example.com"},
		{Kind: model.RuleDomain, Value: "Example.com."},
	})
	if len(c.Prefixes) != 1 || len(c.Domains) != 1 {
		t.Errorf("Prefixes = %v, Domains = %v", c.Prefixes, c.Domains)
	}
}

func TestCompileSkipsInvalid(t *testing.T) {
	c := Compile([]model.Rule{{Kind: model.RuleSubnet, Value: "bad value!"}})
	if len(c.Skipped) != 1 || c.Skipped[0].Reason != "invalid" {
		t.Errorf("Skipped = %v", c.Skipped)
	}
}
