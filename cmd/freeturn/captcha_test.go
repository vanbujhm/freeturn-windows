package main

import (
	"slices"
	"testing"

	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

func TestCaptchaURLAllowed(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"http://127.0.0.1:1234/x", true},
		{"http://localhost:1/", true},
		{"http://127.0.0.1:65535", true},
		{"https://127.0.0.1:1/", false},
		{"http://127.0.0.2:1/", false},
		{"http://evil.example/", false},
		{"http://127.0.0.1.evil.example/", false},
		{"http://127.0.0.1.evil.example:1/", false},
		{"http://user@127.0.0.1:1/", false},
		{"http://127.0.0.1:1@evil.example/", false},
		{`http://127.0.0.1:1\@evil.example/`, false},
		{"javascript:alert(1)", false},
		{"file:///C:/Windows/System32/calc.exe", false},
		{"http://127.0.0.1/", false}, // порт обязателен
		{"http://127.0.0.1:0/", false},
		{"http://127.0.0.1:70000/", false},
		{"http://127.0.0.1:12ab/", false},
		{"http://localhost./", false},
		{"http://127.0.0.1:1/\nx", false},
		{" http://127.0.0.1:1/", false},
		{"//127.0.0.1:1/", false},
		{"", false},
	}
	for _, c := range cases {
		if got := captchaURLAllowed(c.url); got != c.want {
			t.Errorf("captchaURLAllowed(%q) = %v, ждали %v", c.url, got, c.want)
		}
	}
}

const okURL = "http://127.0.0.1:5000/c"

func capStatus(url string) model.Status {
	return model.Status{Phase: model.PhaseCaptcha, CaptchaURL: url}
}

func TestDecideCaptcha(t *testing.T) {
	cases := []struct {
		name string
		prev string
		st   model.Status
		want captchaAction
	}{
		{"нет капчи", "", model.Status{Phase: model.PhaseConnecting}, captchaKeep},
		{"новая капча", "", capStatus(okURL), captchaOpen},
		{"тот же адрес", okURL, capStatus(okURL), captchaKeep},
		{"другой адрес", okURL, capStatus("http://localhost:6000/d"), captchaOpen},
		{"адрес пропал", okURL, capStatus(""), captchaClose},
		{"фаза ушла", okURL, model.Status{Phase: model.PhaseConnected, CaptchaURL: okURL}, captchaClose},
		{"фаза ушла без адреса", okURL, model.Status{Phase: model.PhaseIdle}, captchaClose},
		{"чужой адрес", "", capStatus("http://evil.example/"), captchaRefuse},
		{"чужой адрес повторно", "http://evil.example/", capStatus("http://evil.example/"), captchaKeep},
		{"адрес вне фазы капчи", "", model.Status{Phase: model.PhaseConnecting, CaptchaURL: okURL}, captchaKeep},
	}
	for _, c := range cases {
		if got := decideCaptcha(c.prev, c.st); got != c.want {
			t.Errorf("%s: %v, ждали %v", c.name, got, c.want)
		}
	}
}

func TestCaptchaManager(t *testing.T) {
	var ops, logs []string
	m := &captchaManager{
		open:  func(u string) { ops = append(ops, "open "+u) },
		close: func() { ops = append(ops, "close") },
		logf:  func(s string) { logs = append(logs, s) },
	}
	m.Update(model.Status{Phase: model.PhaseConnecting})
	m.Update(capStatus(okURL))
	m.Update(capStatus(okURL)) // повтор: окно не трогаем, закрытое человеком не открываем заново
	m.Update(capStatus("http://evil.example/"))
	m.Update(capStatus("http://evil.example/"))
	m.Update(capStatus("http://localhost:7/"))
	m.Update(model.Status{Phase: model.PhaseConnected})
	m.Update(model.Status{Phase: model.PhaseConnected})
	want := []string{"open " + okURL, "close", "open http://localhost:7/", "close"}
	if !slices.Equal(ops, want) {
		t.Fatalf("операции %v, ждали %v", ops, want)
	}
	if len(logs) != 1 || logs[0] != captchaRefusedLog {
		t.Fatalf("журнал %v", logs)
	}
}

func TestCaptchaWindowOptions(t *testing.T) {
	o := captchaWindowOptions(okURL)
	if o.Name != captchaName || o.Name == "main" || o.URL != okURL || o.Title != "Проверка VK" {
		t.Fatalf("параметры окна: %+v", o)
	}
	if o.Width != 480 || o.Height != 720 || o.MinWidth != 360 || o.MinHeight != 560 || o.DisableResize {
		t.Fatalf("размеры: %+v", o)
	}
	for _, p := range []application.PermissionType{
		application.PermissionMicrophone, application.PermissionCamera, application.PermissionGeolocation,
		application.PermissionNotifications, application.PermissionClipboardRead,
	} {
		if o.Permissions[p] != application.PermissionDeny {
			t.Errorf("разрешение %d не отклонено: %v", p, o.Permissions[p])
		}
	}
	for _, k := range []application.CoreWebView2PermissionKind{
		application.CoreWebView2PermissionKindUnknownPermission, application.CoreWebView2PermissionKindOtherSensors,
	} {
		if o.Windows.Permissions[k] != application.CoreWebView2PermissionStateDeny {
			t.Errorf("вид %d не отклонён", k)
		}
	}
}

func autoStatus(url string) model.Status {
	return model.Status{Phase: model.PhaseConnecting, AutoCaptchaURL: url}
}

func TestDecideAutoCaptcha(t *testing.T) {
	cases := []struct {
		name string
		prev string
		st   model.Status
		want captchaAction
	}{
		{"нет проверки", "", model.Status{Phase: model.PhaseConnecting}, captchaKeep},
		{"новая проверка", "", autoStatus(okURL), captchaOpen},
		{"тот же адрес", okURL, autoStatus(okURL), captchaKeep},
		{"проверка кончилась", okURL, autoStatus(""), captchaClose},
		{"служба пропала", okURL, model.Status{}, captchaClose},
		{"чужой адрес", "", autoStatus("http://evil.example/"), captchaRefuse},
		{"ручная капча не открывает скрытое окно", "", capStatus(okURL), captchaKeep},
	}
	for _, c := range cases {
		if got := decideAutoCaptcha(c.prev, c.st); got != c.want {
			t.Errorf("%s: %v, ждали %v", c.name, got, c.want)
		}
	}
}

// Скрытое окно автоматической проверки живёт отдельно от окна ручной капчи.
func TestCaptchaManagerAuto(t *testing.T) {
	var ops, logs []string
	m := &captchaManager{
		open:      func(u string) { ops = append(ops, "open "+u) },
		close:     func() { ops = append(ops, "close") },
		openAuto:  func(u string) { ops = append(ops, "auto "+u) },
		closeAuto: func() { ops = append(ops, "autoClose") },
		logf:      func(s string) { logs = append(logs, s) },
	}
	m.Update(autoStatus(okURL))
	m.Update(autoStatus(okURL))
	m.Update(model.Status{Phase: model.PhaseConnecting})
	m.Update(autoStatus("http://evil.example/"))
	m.Update(model.Status{Phase: model.PhaseCaptcha, CaptchaURL: okURL})
	// Отклонённый адрес запоминается, как у окна ручной капчи: повтор не пишет в журнал, а
	// следующее состояние без адреса закрывает уже закрытое окно ещё раз, это безвредно.
	want := []string{"auto " + okURL, "autoClose", "autoClose", "autoClose", "open " + okURL}
	if !slices.Equal(ops, want) {
		t.Fatalf("операции %v, ждали %v", ops, want)
	}
	if len(logs) != 1 || logs[0] != captchaRefusedLog {
		t.Fatalf("журнал %v", logs)
	}
}

func TestCaptchaAutoWindowOptions(t *testing.T) {
	o := captchaAutoWindowOptions(okURL)
	if o.Name != captchaAutoName || o.Name == captchaName || o.Name == "main" || o.URL != okURL || !o.Hidden {
		t.Fatalf("параметры окна: %+v", o)
	}
	if o.Permissions[application.PermissionMicrophone] != application.PermissionDeny ||
		o.Permissions[application.PermissionClipboardRead] != application.PermissionDeny ||
		o.Windows.Permissions[application.CoreWebView2PermissionKindUnknownPermission] != application.CoreWebView2PermissionStateDeny {
		t.Fatalf("разрешения: %+v %+v", o.Permissions, o.Windows.Permissions)
	}
}
