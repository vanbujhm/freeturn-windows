package dnsproxy

import (
	"net/netip"
	"testing"
)

func TestChoose(t *testing.T) {
	withTunnelDNS := Upstreams{
		Direct: []netip.Addr{netip.MustParseAddr("192.0.2.53")},
		Tunnel: []netip.Addr{netip.MustParseAddr("198.51.100.53")},
	}
	noTunnelDNS := Upstreams{Direct: withTunnelDNS.Direct}
	domains := []string{"example.com"}
	cases := []struct {
		name string
		cfg  Config
		host string
		want Choice
	}{
		{"раздельное выключено", Config{Domains: domains, SplitOff: true, Upstreams: withTunnelDNS}, "www.example.com",
			Choice{Route: SideTunnel, Upstream: SideTunnel}},
		{"обход: имя под правилом", Config{Domains: domains, Upstreams: withTunnelDNS}, "www.example.com",
			Choice{Rule: "example.com", Route: SideDirect, Upstream: SideDirect}},
		{"обход: имя не под правилом", Config{Domains: domains, Upstreams: withTunnelDNS}, "iana.org",
			Choice{Route: SideTunnel, Upstream: SideTunnel}},
		{"только список: имя под правилом", Config{Domains: domains, TunnelOnly: true, Upstreams: withTunnelDNS}, "www.example.com",
			Choice{Rule: "example.com", Route: SideTunnel, Upstream: SideTunnel}},
		{"только список: имя не под правилом", Config{Domains: domains, TunnelOnly: true, Upstreams: withTunnelDNS}, "iana.org",
			Choice{Route: SideDirect, Upstream: SideDirect}},
		{"нет DNS конфига: туннельное имя у физического DNS", Config{Domains: domains, Upstreams: noTunnelDNS}, "iana.org",
			Choice{Route: SideTunnel, Upstream: SideDirect}},
		{"нет DNS конфига, только список", Config{Domains: domains, TunnelOnly: true, Upstreams: noTunnelDNS}, "example.com",
			Choice{Rule: "example.com", Route: SideTunnel, Upstream: SideDirect}},
		{"нет DNS конфига, раздельное выключено", Config{SplitOff: true, Upstreams: noTunnelDNS}, "iana.org",
			Choice{Route: SideTunnel, Upstream: SideDirect}},
	}
	for _, c := range cases {
		if got := Choose(c.cfg, c.host); got != c.want {
			t.Errorf("%s: Choose(%q) = %+v, ожидалось %+v", c.name, c.host, got, c.want)
		}
	}
}
