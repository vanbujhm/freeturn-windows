/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package firewall

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// subnetSet держит условия вместе со значениями, на которые они указывают.
type subnetSet struct {
	v4, v6   []wtFwpmFilterCondition0
	v4Values []wtFwpV4AddrAndMask
	v6Values []wtFwpV6AddrAndMask
}

// subnetConditions строит по одному условию на подсеть. Запас ёмкости выделен заранее:
// условия хранят адреса элементов, поэтому срезы значений не должны переезжать.
func subnetConditions(prefixes []netip.Prefix) (*subnetSet, error) {
	set := &subnetSet{
		v4Values: make([]wtFwpV4AddrAndMask, 0, len(prefixes)),
		v6Values: make([]wtFwpV6AddrAndMask, 0, len(prefixes)),
	}
	for _, p := range prefixes {
		if !p.IsValid() {
			return nil, fmt.Errorf("firewall: недопустимая подсеть %v", p)
		}
		p = p.Masked()
		// Адрес вида ::ffff:a.b.c.d на слоях IPv6 не встречается, это подсеть IPv4.
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}

		if p.Addr().Is4() {
			// WFP ждёт адрес и маску в порядке байт хоста. Сдвиг на 32 в Go даёт 0.
			a := p.Addr().As4()
			set.v4Values = append(set.v4Values, wtFwpV4AddrAndMask{
				addr: binary.BigEndian.Uint32(a[:]),
				mask: ^uint32(0) << (32 - p.Bits()),
			})
			set.v4 = append(set.v4, remoteAddressCondition(cFWP_V4_ADDR_MASK,
				unsafe.Pointer(&set.v4Values[len(set.v4Values)-1])))
			continue
		}

		set.v6Values = append(set.v6Values, wtFwpV6AddrAndMask{
			addr:         p.Addr().As16(),
			prefixLength: uint8(p.Bits()),
		})
		set.v6 = append(set.v6, remoteAddressCondition(cFWP_V6_ADDR_MASK,
			unsafe.Pointer(&set.v6Values[len(set.v6Values)-1])))
	}
	return set, nil
}

func remoteAddressCondition(valueType wtFwpDataType, value unsafe.Pointer) wtFwpmFilterCondition0 {
	return wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: valueType,
			value: uintptr(value),
		},
	}
}

// permitSubnets разрешает обмен с подсетями на слоях подключения и приёма, по образцу
// permitLoopback. На каждую подсеть свой фильтр: условий в одном фильтре могло бы
// оказаться слишком много при длинном списке исключений.
func permitSubnets(session uintptr, baseObjects *baseObjects, weight uint8, prefixes []netip.Prefix) error {
	set, err := subnetConditions(prefixes)
	if err != nil {
		return wrapErr(err)
	}

	layers := []struct {
		name       string
		key        windows.GUID
		conditions []wtFwpmFilterCondition0
	}{
		{"Permit outbound to subnet (IPv4)", cFWPM_LAYER_ALE_AUTH_CONNECT_V4, set.v4},
		{"Permit inbound from subnet (IPv4)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, set.v4},
		{"Permit outbound to subnet (IPv6)", cFWPM_LAYER_ALE_AUTH_CONNECT_V6, set.v6},
		{"Permit inbound from subnet (IPv6)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, set.v6},
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		numFilterConditions: 1,
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	for _, layer := range layers {
		displayData, err := createWtFwpmDisplayData0(layer.name, "")
		if err != nil {
			return wrapErr(err)
		}
		filter.displayData = *displayData
		filter.layerKey = layer.key

		for i := range layer.conditions {
			filter.filterCondition = &layer.conditions[i]
			err = fwpmFilterAdd0(session, &filter, 0, &filterID)
			if err != nil {
				return wrapErr(err)
			}
		}
	}

	runtime.KeepAlive(set)
	return nil
}
