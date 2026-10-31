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

// step один шаг установки правил внутри транзакции. install получает сам шаг и берёт вес
// из него: так тест проверяет те значения, что уходят в WFP.
type step struct {
	name       string
	weight     uint8 // вес разрешений шага
	denyWeight uint8 // вес запрета, только у шага dns
	install    func(s step, session uintptr, bo *baseObjects) error
}

// buildSteps возвращает шаги в порядке установки. Веса как в wireguard-windows, локальная
// сеть и исключения идут с весом адаптера: ниже запрета DNS, чтобы адрес из них не открывал
// порт 53.
func buildSteps(o Options) []step {
	steps := []step{{name: "service", weight: 15, install: func(s step, session uintptr, bo *baseObjects) error {
		return permitService(session, bo, s.weight)
	}}}

	if len(o.DNS) > 0 {
		steps = append(steps, step{name: "dns", weight: 15, denyWeight: 14, install: func(s step, session uintptr, bo *baseObjects) error {
			return blockDNS(o.DNS, session, bo, s.weight, s.denyWeight)
		}})
	}

	steps = append(steps, step{name: "loopback", weight: 13, install: func(s step, session uintptr, bo *baseObjects) error {
		return permitLoopback(session, bo, s.weight)
	}})

	if o.TunLUID != 0 {
		steps = append(steps, step{name: "tun", weight: 12, install: func(s step, session uintptr, bo *baseObjects) error {
			return permitTunInterface(session, bo, s.weight, o.TunLUID)
		}})
	}

	steps = append(steps,
		step{name: "dhcp", weight: 12, install: func(s step, session uintptr, bo *baseObjects) error {
			if err := permitDHCPIPv4(session, bo, s.weight); err != nil {
				return err
			}
			return permitDHCPIPv6(session, bo, s.weight)
		}},
		step{name: "ndp", weight: 12, install: func(s step, session uintptr, bo *baseObjects) error {
			return permitNdp(session, bo, s.weight)
		}},
	)

	if o.AllowLAN {
		steps = append(steps, step{name: "lan", weight: 12, install: func(s step, session uintptr, bo *baseObjects) error {
			return permitSubnets(session, bo, s.weight, lanPrefixes())
		}})
	}

	if len(o.Bypass) > 0 {
		steps = append(steps, step{name: "bypass", weight: 12, install: func(s step, session uintptr, bo *baseObjects) error {
			return permitSubnets(session, bo, s.weight, o.Bypass)
		}})
	}

	return append(steps, step{name: "blockAll", weight: 0, install: func(s step, session uintptr, bo *baseObjects) error {
		return blockAll(session, bo, s.weight)
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
