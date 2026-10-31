// Код этого файла собственный (не из ядра): разбор для одного пира и подмена Endpoint.

package wgconf

import (
	"errors"
	"net/netip"
)

// ErrPeerCount возвращается, если в конфиге не ровно один пир.
var ErrPeerCount = errors.New("wgconf: нужен ровно один [Peer]")

// ParseForTunnel разбирает конфиг для туннеля через TURN: ровно один пир.
// mtuOverride > 0 заменяет MTU из конфига.
func ParseForTunnel(text string, mtuOverride int) (*Config, error) {
	cfg, err := parse(text)
	if err != nil {
		return nil, err
	}
	if len(cfg.Peers) != 1 {
		return nil, ErrPeerCount
	}
	if mtuOverride > 0 {
		cfg.MTU = mtuOverride
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// UAPIFor сериализует конфиг, подставляя endpoint вместо исходного.
// Работает на копии, сам Config не меняется.
func (c *Config) UAPIFor(endpoint netip.AddrPort) (string, error) {
	cp := *c
	cp.Peers = make([]Peer, len(c.Peers))
	copy(cp.Peers, c.Peers)
	if len(cp.Peers) > 0 {
		cp.Peers[0].Endpoint = endpoint.String()
	}
	return UAPI(&cp)
}

// AllowedPrefixes возвращает AllowedIPs всех пиров.
func (c *Config) AllowedPrefixes() []netip.Prefix {
	var out []netip.Prefix
	for i := range c.Peers {
		out = append(out, c.Peers[i].AllowedIPs...)
	}
	return out
}
