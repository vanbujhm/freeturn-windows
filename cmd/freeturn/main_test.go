package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/profile"
)

func TestLinkArg(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{nil, ""},
		{[]string{`C:\FreeTurn.exe`, "--tray"}, ""},
		{[]string{`C:\FreeTurn.exe`, "freeturn://abc"}, "freeturn://abc"},
		{[]string{"FREETURN://abc"}, "FREETURN://abc"},
		{[]string{`"freeturn://abc"`}, "freeturn://abc"},
		{[]string{"--tray", "  freeturn://abc  "}, "freeturn://abc"},
		{[]string{"https://example.test/freeturn://x"}, ""},
	}
	for _, c := range cases {
		if got := linkArg(c.args); got != c.want {
			t.Errorf("linkArg(%q) = %q, ожидалось %q", c.args, got, c.want)
		}
	}
}

func TestMarshalError(t *testing.T) {
	e := newError(codeIncomplete, "не хватает", nil)
	e.Fields = []model.Field{model.FieldWGConfig}
	raw := marshalError(e)
	var got struct {
		Code   string
		Fields []string
	}
	if err := json.Unmarshal(raw, &got); err != nil || got.Code != codeIncomplete || len(got.Fields) != 1 || got.Fields[0] != "wgConfig" {
		t.Fatalf("JSON ошибки %s, %v", raw, err)
	}
	if marshalError(errors.New("чужая ошибка")) != nil {
		t.Fatal("чужая ошибка закодирована как ошибка API")
	}
}

func TestLookOfPhase(t *testing.T) {
	cases := map[model.Phase]trayLook{
		model.PhaseIdle:         lookIdle,
		model.PhaseConnecting:   lookBusy,
		model.PhaseCaptcha:      lookBusy,
		model.PhaseReconnecting: lookBusy,
		model.PhaseConnected:    lookOn,
		model.PhaseError:        lookError,
		model.PhaseBlocked:      lookBlocked,
	}
	for p, want := range cases {
		if got := lookOfPhase(p); got != want {
			t.Errorf("lookOfPhase(%s) = %d, ожидалось %d", p, got, want)
		}
	}
	for _, l := range []trayLook{lookOn, lookBusy, lookBlocked} {
		if !canDisconnect(l) {
			t.Errorf("для вида %d нет пункта «Отключить»", l)
		}
	}
	for _, l := range []trayLook{lookIdle, lookDown, lookError} {
		if canDisconnect(l) {
			t.Errorf("для вида %d предложено отключение", l)
		}
	}
}

func TestTrayIconsDecode(t *testing.T) {
	for l, c := range lookColors {
		img, err := png.Decode(bytes.NewReader(circleIcon(c)))
		if err != nil {
			t.Fatalf("вид %d: %v", l, err)
		}
		if b := img.Bounds(); b.Dx() != 32 || b.Dy() != 32 {
			t.Fatalf("вид %d: размер %v", l, b)
		}
		if _, _, _, a := img.At(16, 16).RGBA(); a == 0 {
			t.Fatalf("вид %d: центр прозрачный", l)
		}
		if _, _, _, a := img.At(0, 0).RGBA(); a != 0 {
			t.Fatalf("вид %d: угол закрашен", l)
		}
	}
}

func TestShowOnSecondLaunch(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{`C:\FreeTurn.exe`}, true},
		{[]string{`C:\FreeTurn.exe`, "--tray"}, false},
		{[]string{`C:\FreeTurn.exe`, "--tray", "freeturn://abc"}, true},
		{[]string{`C:\FreeTurn.exe`, "freeturn://abc"}, true},
	}
	for _, c := range cases {
		if got := showOnSecondLaunch(c.args); got != c.want {
			t.Errorf("showOnSecondLaunch(%q) = %v, ожидалось %v", c.args, got, c.want)
		}
	}
}

func TestLoadSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")

	if s, reset := loadSettings(path); reset || !s.Autostart {
		t.Fatalf("нет файла: reset=%v %+v", reset, s)
	}
	if err := profile.SaveSettings(path, profile.Settings{ConnectOnLaunch: true}); err != nil {
		t.Fatal(err)
	}
	if s, reset := loadSettings(path); reset || !s.ConnectOnLaunch {
		t.Fatalf("исправный файл: reset=%v %+v", reset, s)
	}
	for name, body := range map[string]string{"мусор": "не json {", "не тот тип": `{"Autostart": "да"}`, "пустой": ""} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		s, reset := loadSettings(path)
		if !reset || !s.Options.KillSwitch || !s.Autostart {
			t.Errorf("%s: reset=%v, настройки не по умолчанию: %+v", name, reset, s)
		}
	}
	// Каталог вместо файла: прочитать нельзя, запуск идёт с настройками по умолчанию.
	dirAsFile := filepath.Join(dir, "dir")
	if err := os.Mkdir(dirAsFile, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, reset := loadSettings(dirAsFile); !reset {
		t.Error("нечитаемый файл не помечен как сброшенный")
	}
}

func TestDisconnectWithinLimit(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	svc := &blockingService{block: block}
	start := time.Now()
	disconnectWithin(svc, 50*time.Millisecond)
	if d := time.Since(start); d < 40*time.Millisecond || d > 2*time.Second {
		t.Fatalf("ожидание %v, нужно около лимита", d)
	}
	fast := &fakeService{}
	start = time.Now()
	disconnectWithin(fast, 5*time.Second)
	if time.Since(start) > time.Second || fast.disconnects != 1 {
		t.Fatalf("быстрое отключение: %v, вызовов %d", time.Since(start), fast.disconnects)
	}
}

// blockingService не отвечает на Disconnect, пока тест не закончится.
type blockingService struct {
	fakeService
	block chan struct{}
}

func (b *blockingService) Disconnect() error {
	<-b.block
	return nil
}
