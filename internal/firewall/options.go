/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package firewall

import "net/netip"

// Options описывает, что разрешено при включённой блокировке.
type Options struct {
	TunLUID  uint64       // 0: адаптера ещё нет, разрешение для него не ставится
	DNS      []netip.Addr // пусто: DNS не ограничивается
	AllowLAN bool
	Bypass   []netip.Prefix
}

// step один шаг установки правил внутри транзакции.
type step struct {
	name    string
	install func(session uintptr, baseObjects *baseObjects) error
}

// buildSteps возвращает шаги в порядке установки. Веса как в wireguard-windows,
// локальная сеть и исключения идут с весом адаптера.
func buildSteps(o Options) []step {
	steps := []step{{"service", func(session uintptr, bo *baseObjects) error {
		return permitService(session, bo, 15)
	}}}

	if len(o.DNS) > 0 {
		steps = append(steps, step{"dns", func(session uintptr, bo *baseObjects) error {
			return blockDNS(o.DNS, session, bo, 15, 14)
		}})
	}

	steps = append(steps, step{"loopback", func(session uintptr, bo *baseObjects) error {
		return permitLoopback(session, bo, 13)
	}})

	if o.TunLUID != 0 {
		steps = append(steps, step{"tun", func(session uintptr, bo *baseObjects) error {
			return permitTunInterface(session, bo, 12, o.TunLUID)
		}})
	}

	steps = append(steps,
		step{"dhcp", func(session uintptr, bo *baseObjects) error {
			if err := permitDHCPIPv4(session, bo, 12); err != nil {
				return err
			}
			return permitDHCPIPv6(session, bo, 12)
		}},
		step{"ndp", func(session uintptr, bo *baseObjects) error {
			return permitNdp(session, bo, 12)
		}},
	)

	if o.AllowLAN {
		steps = append(steps, step{"lan", func(session uintptr, bo *baseObjects) error {
			return permitSubnets(session, bo, 12, lanPrefixes())
		}})
	}

	if len(o.Bypass) > 0 {
		steps = append(steps, step{"bypass", func(session uintptr, bo *baseObjects) error {
			return permitSubnets(session, bo, 12, o.Bypass)
		}})
	}

	return append(steps, step{"blockAll", func(session uintptr, bo *baseObjects) error {
		return blockAll(session, bo, 0)
	}})
}

// lanPrefixes возвращает частные, канальные и многоадресные сети.
func lanPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}
}
