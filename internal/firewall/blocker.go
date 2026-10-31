/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package firewall

import (
	"errors"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type wfpObjectInstaller func(uintptr) error

// Fundamental FreeTurn specific WFP objects.
type baseObjects struct {
	provider windows.GUID
	filters  windows.GUID
}

// Постоянные ключи провайдера и подуровня FreeTurn. Ключи WFP уникальны во всей системе,
// поэтому их две пары: Update держит старую и новую сессии одновременно, а вторая сессия
// с теми же ключами получила бы FWP_E_ALREADY_EXISTS. Пары чередуются.
var sessionKeys = [2]baseObjects{
	{
		// d95aa1a2-3009-4590-8b30-6e791a093a70
		provider: windows.GUID{Data1: 0xd95aa1a2, Data2: 0x3009, Data3: 0x4590, Data4: [8]byte{0x8b, 0x30, 0x6e, 0x79, 0x1a, 0x09, 0x3a, 0x70}},
		// a05ca6cd-b50c-472a-b5b4-1c2b9367e7ca
		filters: windows.GUID{Data1: 0xa05ca6cd, Data2: 0xb50c, Data3: 0x472a, Data4: [8]byte{0xb5, 0xb4, 0x1c, 0x2b, 0x93, 0x67, 0xe7, 0xca}},
	},
	{
		// b40cf949-0728-42da-abe5-b7c35964eb64
		provider: windows.GUID{Data1: 0xb40cf949, Data2: 0x0728, Data3: 0x42da, Data4: [8]byte{0xab, 0xe5, 0xb7, 0xc3, 0x59, 0x64, 0xeb, 0x64}},
		// bf80dcbf-dcce-487d-806a-b1d052b11eb6
		filters: windows.GUID{Data1: 0xbf80dcbf, Data2: 0xdcce, Data3: 0x487d, Data4: [8]byte{0x80, 0x6a, 0xb1, 0xd0, 0x52, 0xb1, 0x1e, 0xb6}},
	},
}

func createWfpSession() (uintptr, error) {
	sessionDisplayData, err := createWtFwpmDisplayData0("FreeTurn", "FreeTurn dynamic session")
	if err != nil {
		return 0, wrapErr(err)
	}

	session := wtFwpmSession0{
		displayData:          *sessionDisplayData,
		flags:                cFWPM_SESSION_FLAG_DYNAMIC,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}

	sessionHandle := uintptr(0)

	err = fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&sessionHandle))
	if err != nil {
		return 0, wrapErr(err)
	}

	return sessionHandle, nil
}

func registerBaseObjects(session uintptr, keys baseObjects) (*baseObjects, error) {
	bo := &keys

	//
	// Register provider.
	//
	{
		displayData, err := createWtFwpmDisplayData0("FreeTurn", "FreeTurn provider")
		if err != nil {
			return nil, wrapErr(err)
		}
		provider := wtFwpmProvider0{
			providerKey: bo.provider,
			displayData: *displayData,
		}
		err = fwpmProviderAdd0(session, &provider, 0)
		if err != nil {
			// TODO: cleanup entire call chain of these if failure?
			return nil, wrapErr(err)
		}
	}

	//
	// Register filters sublayer.
	//
	{
		displayData, err := createWtFwpmDisplayData0("FreeTurn filters", "Permissive and blocking filters")
		if err != nil {
			return nil, wrapErr(err)
		}
		sublayer := wtFwpmSublayer0{
			subLayerKey: bo.filters,
			displayData: *displayData,
			providerKey: &bo.provider,
			weight:      ^uint16(0),
		}
		err = fwpmSubLayerAdd0(session, &sublayer, 0)
		if err != nil {
			return nil, wrapErr(err)
		}
	}

	return bo, nil
}

// installSession открывает динамическую сессию и ставит все правила одной транзакцией.
// Правила живут, пока жива сессия: они исчезают и при падении процесса.
func installSession(o Options, keys baseObjects) (uintptr, error) {
	session, err := createWfpSession()
	if err != nil {
		return 0, wrapErr(err)
	}

	objectInstaller := func(session uintptr) error {
		baseObjects, err := registerBaseObjects(session, keys)
		if err != nil {
			return wrapErr(err)
		}
		for _, s := range buildSteps(o) {
			err = s.install(session, baseObjects)
			if err != nil {
				return wrapErr(err)
			}
		}
		return nil
	}

	err = runTransaction(session, objectInstaller)
	if err != nil {
		fwpmEngineClose0(session)
		return 0, wrapErr(err)
	}

	return session, nil
}

// guard хранит состояние блокировки. WFP вынесен в поля, чтобы порядок действий
// проверялся тестами без настоящей блокировки.
type guard struct {
	mu           sync.Mutex
	session      uintptr
	slot         int // индекс пары sessionKeys, занятой session
	install      func(o Options, keys baseObjects) (uintptr, error)
	closeSession func(session uintptr)
}

var current = guard{
	install:      installSession,
	closeSession: func(session uintptr) { fwpmEngineClose0(session) },
}

// Enable включает блокировку. Если она уже включена, возвращает ошибку.
func Enable(o Options) error { return current.enable(o) }

// Update меняет разрешения: создаёт новую сессию и только после её успеха закрывает
// старую, поэтому блокировка не прерывается. При сбое старая сессия остаётся.
// Если блокировка выключена, работает как Enable.
func Update(o Options) error { return current.update(o) }

// Disable снимает блокировку.
func Disable() { current.disable() }

// Enabled сообщает, включена ли блокировка.
func Enabled() bool { return current.enabled() }

func (g *guard) enable(o Options) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.session != 0 {
		return errors.New("The firewall has already been enabled")
	}
	return g.start(o)
}

func (g *guard) update(o Options) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.session == 0 {
		return g.start(o)
	}
	next := 1 - g.slot
	session, err := g.install(o, sessionKeys[next])
	if err != nil {
		return wrapErr(err)
	}
	g.closeSession(g.session)
	g.session, g.slot = session, next
	return nil
}

func (g *guard) start(o Options) error {
	session, err := g.install(o, sessionKeys[g.slot])
	if err != nil {
		return wrapErr(err)
	}
	g.session = session
	return nil
}

func (g *guard) disable() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.session != 0 {
		g.closeSession(g.session)
		g.session = 0
	}
}

func (g *guard) enabled() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.session != 0
}
