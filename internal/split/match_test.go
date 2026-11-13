package split

import "testing"

func TestMatch(t *testing.T) {
	rules := []string{"example.com", "a.example.com", "xn--80a1acny.xn--p1ai", "org"}
	cases := []struct {
		name, rule string
		ok         bool
	}{
		{"example.com", "example.com", true},
		{"www.example.com", "example.com", true},
		{"WWW.Example.COM.", "example.com", true},
		{"x.a.example.com", "a.example.com", true},
		{"a.example.com", "a.example.com", true},
		{"badexample.com", "", false},
		{"example.com.evil.net", "", false},
		{"почта.рф", "xn--80a1acny.xn--p1ai", true},
		{"mail.почта.рф", "xn--80a1acny.xn--p1ai", true},
		{"iana.org", "org", true},
		{"", "", false},
		{".", "", false},
		{"bad..name", "", false},
	}
	for _, c := range cases {
		rule, ok := MatchDomain(rules, c.name)
		if rule != c.rule || ok != c.ok {
			t.Errorf("MatchDomain(%q) = %q, %v; ожидалось %q, %v", c.name, rule, ok, c.rule, c.ok)
		}
	}
}
