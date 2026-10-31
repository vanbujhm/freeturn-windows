package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"image/png"
	"testing"

	"github.com/vanbujhm/freeturn-windows/internal/model"
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
		model.PhaseError:        lookBad,
		model.PhaseBlocked:      lookBad,
	}
	for p, want := range cases {
		if got := lookOfPhase(p); got != want {
			t.Errorf("lookOfPhase(%s) = %d, ожидалось %d", p, got, want)
		}
	}
	for _, l := range []trayLook{lookOn, lookBusy, lookBad} {
		if !canDisconnect(l) {
			t.Errorf("для вида %d нет пункта «Отключить»", l)
		}
	}
	for _, l := range []trayLook{lookIdle, lookDown} {
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
