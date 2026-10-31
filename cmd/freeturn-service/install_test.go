package main

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestServiceConfig(t *testing.T) {
	c := serviceConfig()
	if c.StartType != mgr.StartAutomatic {
		t.Errorf("StartType = %d", c.StartType)
	}
	// Без SID службы firewall.Enable не сможет построить разрешение для неё.
	if c.SidType != windows.SERVICE_SID_TYPE_UNRESTRICTED {
		t.Errorf("SidType = %d", c.SidType)
	}
	if c.DisplayName != "FreeTurn" || c.Description != "Туннель FreeTurn" {
		t.Errorf("имя %q, описание %q", c.DisplayName, c.Description)
	}
}

// Повторная установка меняет только своё: ChangeServiceConfig не принимает нулевой тип службы.
func TestUpdatedConfig(t *testing.T) {
	cur := mgr.Config{
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:        mgr.StartManual,
		ErrorControl:     mgr.ErrorNormal,
		BinaryPathName:   `C:\old\FreeTurnService.exe`,
		ServiceStartName: "LocalSystem",
	}
	got := updatedConfig(cur, `C:\Program Files\FreeTurn\FreeTurnService.exe`)

	if got.ServiceType != cur.ServiceType || got.ErrorControl != cur.ErrorControl ||
		got.ServiceStartName != cur.ServiceStartName {
		t.Errorf("потеряны поля: %+v", got)
	}
	if got.BinaryPathName != `"C:\Program Files\FreeTurn\FreeTurnService.exe"` {
		t.Errorf("путь %s", got.BinaryPathName)
	}
	if got.StartType != mgr.StartAutomatic || got.SidType != windows.SERVICE_SID_TYPE_UNRESTRICTED ||
		got.DisplayName != "FreeTurn" || got.Description != "Туннель FreeTurn" {
		t.Errorf("конфигурация не обновлена: %+v", got)
	}
}

func TestRecoveryActions(t *testing.T) {
	want := []time.Duration{time.Second, 5 * time.Second, 30 * time.Second}
	got := recoveryActions()
	if len(got) != len(want) {
		t.Fatalf("действий %d", len(got))
	}
	for i, a := range got {
		if a.Type != mgr.ServiceRestart || a.Delay != want[i] {
			t.Errorf("действие %d: %+v", i, a)
		}
	}
}

func TestWaitStopped(t *testing.T) {
	polls := 0
	err := waitStopped(func() (svc.Status, error) {
		polls++
		if polls < 3 {
			return svc.Status{State: svc.StopPending}, nil
		}
		return svc.Status{State: svc.Stopped}, nil
	}, time.Minute, time.Millisecond)
	if err != nil || polls != 3 {
		t.Fatalf("ошибка %v, опросов %d", err, polls)
	}
}

func TestWaitStoppedTimeout(t *testing.T) {
	err := waitStopped(func() (svc.Status, error) {
		return svc.Status{State: svc.StopPending}, nil
	}, 20*time.Millisecond, time.Millisecond)
	if !errors.Is(err, errStopTimeout) {
		t.Fatalf("ошибка %v", err)
	}
}

func TestWaitStoppedQueryError(t *testing.T) {
	failure := errors.New("SCM недоступен")
	err := waitStopped(func() (svc.Status, error) {
		return svc.Status{}, failure
	}, time.Minute, time.Millisecond)
	if !errors.Is(err, failure) {
		t.Fatalf("ошибка %v", err)
	}
}
