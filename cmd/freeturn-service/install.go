package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wintun"

	"github.com/vanbujhm/freeturn-windows/internal/netcfg"
	"github.com/vanbujhm/freeturn-windows/internal/statefile"
	"github.com/vanbujhm/freeturn-windows/internal/tunnel"
)

const (
	// recoveryResetSeconds - через сколько секунд без падений счётчик падений обнуляется.
	recoveryResetSeconds = 24 * 60 * 60
	startTimeout         = 30 * time.Second
	stopTimeout          = 15 * time.Second
	stopPoll             = 250 * time.Millisecond
)

var (
	// errStopTimeout: служба не остановилась за отведённое время.
	errStopTimeout = errors.New("служба не остановилась за 15 секунд")
	// errStartFailed: служба завершилась при запуске, причину она пишет в журнал событий.
	errStartFailed = errors.New("служба не запустилась, причина в журнале событий Windows")
	// errStartTimeout: служба не сообщила о запуске за отведённое время.
	errStartTimeout = errors.New("служба не запустилась за 30 секунд")
)

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

// install регистрирует службу и запускает её. Если она уже есть, обновляет настройки. Каталог
// закрывается здесь, с правами установщика: так он готов раньше первого запуска службы, и
// пользователь не успевает его подбросить.
func install() error {
	if _, note, err := prepareDataDir(); err != nil {
		return err
	} else if note != "" {
		fmt.Println(note)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("SCM: %w", err)
	}
	defer m.Disconnect()

	if err := registerEventSource(); err != nil {
		return fmt.Errorf("источник журнала событий: %w", err)
	}

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
	return waitStarted(s.Query, startTimeout, stopPoll)
}

// registerEventSource регистрирует источник заново: Install считает уже существующий ошибкой, а
// install запускают и поверх старой установки.
func registerEventSource() error {
	_ = eventlog.Remove(serviceName)
	return eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
}

// waitStarted ждёт, чем кончится запуск: Start только просит SCM начать.
func waitStarted(query func() (svc.Status, error), timeout, poll time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		st, err := query()
		if err != nil {
			return fmt.Errorf("состояние службы: %w", err)
		}
		switch st.State {
		case svc.Running:
			return nil
		case svc.Stopped:
			return errStartFailed
		}
		if time.Now().After(deadline) {
			return errStartTimeout
		}
		time.Sleep(poll)
	}
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
	_ = eventlog.Remove(serviceName) // источника может и не быть
	removeWintun(tunnel.CheckDLL, tunnel.RemoveStale, wintun.Uninstall)
	return removeData()
}

// removeWintun убирает адаптер и драйвер, если есть чем: без wintun.dll удаление идёт дальше.
// Адаптер остаётся, только если служба упала и больше не запускалась.
func removeWintun(check, removeAdapter, removeDriver func() error) {
	if check() != nil {
		return
	}
	_ = removeAdapter()
	_ = removeDriver()
}

// removeData снимает маршруты и удаляет каталог. Сначала каталог проверяется, как при запуске:
// список маршрутов из подброшенного файла выполнялся бы с правами администратора.
func removeData() error {
	p, _, err := prepareDataDir()
	if err != nil {
		return err
	}
	return errors.Join(removeSavedRoutes(p.state, netcfg.RemoveRoutes), os.RemoveAll(p.root))
}

// removeSavedRoutes снимает маршруты обхода из файла состояния. Они остаются, только если служба
// упала и больше не запускалась, а другого списка после удаления файла не будет.
func removeSavedRoutes(path string, remove func([]netcfg.BypassRoute) error) error {
	s, err := statefile.Load(path)
	if err != nil {
		return err
	}
	return remove(s.Bypass)
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
