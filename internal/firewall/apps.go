/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package firewall

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// blockApps запрещает программам обмен на слоях подключения и приёма. Разрешения адаптера
// туннеля, loopback и LAN стоят выше и пропускают программу туда, всё остальное ей закрыто.
// Путь без файла пропускается: список таких путей вызывающему отдаёт missingApps.
func blockApps(session uintptr, baseObjects *baseObjects, weight uint8, paths []string) error {
	layers := []appLayer{
		{"Block app outside tunnel (IPv4 outbound)", cFWPM_LAYER_ALE_AUTH_CONNECT_V4},
		{"Block app outside tunnel (IPv4 inbound)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4},
		{"Block app outside tunnel (IPv6 outbound)", cFWPM_LAYER_ALE_AUTH_CONNECT_V6},
		{"Block app outside tunnel (IPv6 inbound)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6},
	}
	for _, path := range paths {
		appID, err := appIDFromPath(path)
		if err != nil {
			continue
		}
		err = blockApp(session, baseObjects, weight, appID, layers)
		fwpmFreeMemory0(unsafe.Pointer(&appID))
		if err != nil {
			return wrapErr(err)
		}
	}
	return nil
}

type appLayer struct {
	name string
	key  windows.GUID
}

func blockApp(session uintptr, baseObjects *baseObjects, weight uint8, appID *wtFwpByteBlob, layers []appLayer) error {
	condition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_ALE_APP_ID,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_BYTE_BLOB_TYPE,
			value: uintptr(unsafe.Pointer(appID)),
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		numFilterConditions: 1,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&condition)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_BLOCK,
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

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	runtime.KeepAlive(appID)
	runtime.KeepAlive(&condition)
	return nil
}
