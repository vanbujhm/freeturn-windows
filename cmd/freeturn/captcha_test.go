package main

import (
	"slices"
	"testing"

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
