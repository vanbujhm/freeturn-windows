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

// txnWaitTimeoutMs ограничивает ожидание начала транзакции. Блокировка транзакций WFP общая
// на систему, и чужая зависшая транзакция не должна держать нас бесконечно. По истечении
// срока установка возвращает ошибку.
const txnWaitTimeoutMs = 5000

// errDisabledDuringInstall возвращают Enable и Update, если Disable пришёл во время
// установки. Новая сессия к этому моменту уже закрыта.
var errDisabledDuringInstall = errors.New("firewall: блокировку сняли во время установки")

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
		txnWaitTimeoutInMSec: txnWaitTimeoutMs,
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
			err = s.install(s, session, baseObjects)
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
//
// Установка идёт вне mu: срок txnWaitTimeoutMs покрывает только начало транзакции, а
// открытие сессии и добавление фильтров им не ограничены. Disable берёт только mu, поэтому
// установку не ждёт вообще: он повышает epoch, и опоздавшая установка закрывает свою сессию.
type guard struct {
	installMu    sync.Mutex // одна установка за раз
	mu           sync.Mutex // защищает session и epoch, не держится при вызовах WFP
	session      uintptr
	epoch        uint64 // число вызовов Disable
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
	g.installMu.Lock()
	defer g.installMu.Unlock()
	session, epoch := g.snapshot()
	if session != 0 {
		return errors.New("The firewall has already been enabled")
	}
	return g.replace(o, epoch)
}

func (g *guard) update(o Options) error {
	g.installMu.Lock()
	defer g.installMu.Unlock()
	_, epoch := g.snapshot()
	return g.replace(o, epoch)
}

func (g *guard) snapshot() (session uintptr, epoch uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.session, g.epoch
}

// replace ставит новую сессию и только после успеха закрывает прежнюю, если она была.
func (g *guard) replace(o Options, epoch uint64) error {
	session, err := g.install(o)
	if err != nil {
		return wrapErr(err)
	}

	g.mu.Lock()
	if g.epoch != epoch {
		g.mu.Unlock()
		g.closeSession(session)
		return errDisabledDuringInstall
	}
	old := g.session
	g.session = session
	g.mu.Unlock()

	if old != 0 {
		g.closeSession(old)
	}
	return nil
}

func (g *guard) disable() {
	g.mu.Lock()
	g.epoch++
	session := g.session
	g.session = 0
	g.mu.Unlock()

	if session != 0 {
		g.closeSession(session)
	}
}

func (g *guard) enabled() bool {
	session, _ := g.snapshot()
	return session != 0
}
