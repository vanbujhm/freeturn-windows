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

func registerBaseObjects(session uintptr) (*baseObjects, error) {
	bo := &baseObjects{}
	var err error
	bo.provider, err = windows.GenerateGUID()
	if err != nil {
		return nil, wrapErr(err)
	}
	bo.filters, err = windows.GenerateGUID()
	if err != nil {
		return nil, wrapErr(err)
	}

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
// Правила живут, пока жива сессия: они исчезают и при падении процесса. Ключи провайдера
// и подуровня у каждой сессии свои: ключи WFP уникальны во всей системе, а Update держит
// старую и новую сессии одновременно.
func installSession(o Options) (uintptr, error) {
	session, err := createWfpSession()
	if err != nil {
		return 0, wrapErr(err)
	}

	objectInstaller := func(session uintptr) error {
		baseObjects, err := registerBaseObjects(session)
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
	install      func(o Options) (uintptr, error)
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
	session, err := g.install(o)
	if err != nil {
		return wrapErr(err)
	}
	g.closeSession(g.session)
	g.session = session
	return nil
}

func (g *guard) start(o Options) error {
	session, err := g.install(o)
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
