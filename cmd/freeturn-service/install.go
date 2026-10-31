package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wintun"

	"github.com/vanbujhm/freeturn-windows/internal/tunnel"
)

const (
	// recoveryResetSeconds - через сколько секунд без падений счётчик падений обнуляется.
	recoveryResetSeconds = 24 * 60 * 60
	stopTimeout          = 15 * time.Second
	stopPoll             = 250 * time.Millisecond
)

// errStopTimeout: служба не остановилась за отведённое время.
var errStopTimeout = errors.New("служба не остановилась за 15 секунд")

// serviceConfig - настройки службы. SID службы нужен брандмауэру: разрешение привязано к нему.
func serviceConfig() mgr.Config {
	return mgr.Config{
		StartType:   mgr.StartAutomatic,
		DisplayName: "FreeTurn",
		Description: "Туннель FreeTurn",
		SidType:     windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}
}

// updatedConfig накладывает настройки на текущие. Менять надо только свои поля: остальные
// UpdateConfig передаёт в ChangeServiceConfig как есть, а нулевой тип службы там ошибка.
func updatedConfig(cur mgr.Config, exe string) mgr.Config {
	want := serviceConfig()
	cur.StartType = want.StartType
	cur.DisplayName = want.DisplayName
	cur.Description = want.Description
	cur.SidType = want.SidType
	cur.BinaryPathName = syscall.EscapeArg(exe)
	return cur
}

func recoveryActions() []mgr.RecoveryAction {
	return []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}
}

// install регистрирует службу и запускает её. Если она уже есть, обновляет настройки.
func install() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := createOrUpdate(m, exe)
	if err != nil {
		return err
	}
	defer s.Close()

	if err := s.SetRecoveryActions(recoveryActions(), recoveryResetSeconds); err != nil {
		return fmt.Errorf("действия при сбое: %w", err)
	}
	// Без этого флага SCM перезапускает только упавший процесс, а не службу, которая сама
	// вышла с кодом ошибки, например когда не открылся канал.
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("действия при сбое: %w", err)
	}
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("запуск службы: %w", err)
	}
	return nil
}

func createOrUpdate(m *mgr.Mgr, exe string) (*mgr.Service, error) {
	s, err := m.OpenService(serviceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		s, err = m.CreateService(serviceName, exe, serviceConfig())
		if err != nil {
			return nil, fmt.Errorf("создание службы: %w", err)
		}
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("открытие службы: %w", err)
	}
	cur, err := s.Config()
	if err == nil {
		err = s.UpdateConfig(updatedConfig(cur, exe))
	}
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("обновление службы: %w", err)
	}
	return s, nil
}

// uninstall останавливает и удаляет службу, потом убирает следы. Туннель снимает сама служба
// при остановке. Драйвер трогается только после удаления службы: WintunDeleteDriver не удаляет
// занятый драйвер, например нужный Amnezia, поэтому его ошибка здесь не важна.
func uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("SCM: %w", err)
	}
	defer m.Disconnect()

	if err := removeService(m); err != nil {
		return err
	}
	// Адаптер остаётся, только если служба упала и больше не запускалась.
	_ = tunnel.RemoveStale()
	_ = wintun.Uninstall()

	p, err := programDataPaths()
	if err != nil {
		return err
	}
	return os.RemoveAll(p.root)
}

// removeService останавливает службу и удаляет её. Если она не остановилась, удаление
// откладывается системой до её завершения, а uninstall возвращает ошибку и дальше не идёт:
// драйвер и файлы ещё заняты. Служба исчезает, когда закрыт её дескриптор, это делает defer.
func removeService(m *mgr.Mgr) error {
	s, err := m.OpenService(serviceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("открытие службы: %w", err)
	}
	defer s.Close()

	_, err = s.Control(svc.Stop)
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) &&
		!errors.Is(err, windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL) {
		return fmt.Errorf("остановка службы: %w", err)
	}
	stopErr := waitStopped(s.Query, stopTimeout, stopPoll)
	if err := s.Delete(); err != nil {
		return errors.Join(stopErr, fmt.Errorf("удаление службы: %w", err))
	}
	return stopErr
}

// waitStopped опрашивает службу, пока она не остановится или не выйдет срок.
func waitStopped(query func() (svc.Status, error), timeout, poll time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		st, err := query()
		if err != nil {
			return fmt.Errorf("состояние службы: %w", err)
		}
		if st.State == svc.Stopped {
			return nil
		}
		if time.Now().After(deadline) {
			return errStopTimeout
		}
		time.Sleep(poll)
	}
}
