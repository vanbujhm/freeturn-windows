package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/wailsapp/wails/v3/pkg/application"
)

func TestRuntimeRequestAllowed(t *testing.T) {
	const mainID = 3
	cases := []struct {
		name                                    string
		path, id, windowName, origin, fetchSite string
		mainID                                  uint32
		want                                    bool
	}{
		{"главное окно", "/wails/runtime", "3", "", "", "", mainID, true},
		{"главное окно, свой источник", "/wails/runtime", "3", "main", "http://wails.localhost", "same-origin", mainID, true},
		{"окно капчи", "/wails/runtime", "4", "", "", "", mainID, false},
		{"окно капчи, чужой источник", "/wails/runtime", "4", "", "http://127.0.0.1:5000", "cross-site", mainID, false},
		{"номер главного, но чужой источник", "/wails/runtime", "3", "", "http://127.0.0.1:5000", "", mainID, false},
		{"номер главного, источник null", "/wails/runtime", "3", "", "null", "", mainID, false},
		{"номер главного, обманный хост", "/wails/runtime", "3", "", "http://wails.localhost.evil.example", "", mainID, false},
		{"межсайтовый запрос без Origin", "/wails/runtime", "3", "", "", "cross-site", mainID, false},
		{"чужое имя окна", "/wails/runtime", "3", "captcha", "", "", mainID, false},
		{"без номера окна", "/wails/runtime", "", "", "", "", mainID, false},
		{"номер не число", "/wails/runtime", "x", "", "", "", mainID, false},
		{"главное окно ещё не создано", "/wails/runtime", "0", "", "", "", 0, false},
		{"полезная нагрузка событий", "/wails/eventpayload/1", "4", "", "", "", mainID, false},
		{"поток", "/wails/stream/x", "4", "", "", "", mainID, false},
		{"неизвестный путь под wails", "/wails/other", "4", "", "", "", mainID, false},
		{"скрипт среды выполнения", "/wails/runtime.js", "4", "", "", "", mainID, true},
		{"обычный файл", "/assets/index.js", "4", "", "http://127.0.0.1:5000", "", mainID, true},
		{"корень", "/", "", "", "", "", mainID, true},
	}
	for _, c := range cases {
		if got := runtimeRequestAllowed(c.path, c.id, c.windowName, c.origin, c.fetchSite, c.mainID); got != c.want {
			t.Errorf("%s: %v, ждали %v", c.name, got, c.want)
		}
	}
}

func TestRuntimeGuardHandler(t *testing.T) {
	mainWindowID.Store(3)
	t.Cleanup(func() { mainWindowID.Store(0) })
	reached := 0
	h := runtimeGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached++ }))

	do := func(id string) int {
		r := httptest.NewRequest(http.MethodPost, "/wails/runtime", nil)
		r.Header.Set("x-wails-window-id", id)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if code := do("4"); code != http.StatusForbidden || reached != 0 {
		t.Fatalf("чужое окно: код %d, дошло %d", code, reached)
	}
	if code := do("3"); code != http.StatusOK || reached != 1 {
		t.Fatalf("главное окно: код %d, дошло %d", code, reached)
	}
}

func TestMainEmitter(t *testing.T) {
	var sent []*application.CustomEvent
	emit := newMainEmitter(func(ev *application.CustomEvent) { sent = append(sent, ev) })

	emit("status", "один")
	emit("service-down")
	emit("many", 1, "два")
	emit("struct", UpdateInfo{Version: "1.0.0"})

	if len(sent) != 4 {
		t.Fatalf("отправлено %d событий, ждали 4 (по одному на вызов)", len(sent))
	}
	want := []struct {
		name string
		data any
	}{
		{"status", "один"},
		{"service-down", nil},
		{"many", []any{1, "два"}},
		{"struct", UpdateInfo{Version: "1.0.0"}},
	}
	for i, w := range want {
		if sent[i].Name != w.name || !reflect.DeepEqual(sent[i].Data, w.data) || sent[i].Sender != "" {
			t.Errorf("событие %d: %+v, ждали %+v", i, sent[i], w)
		}
	}
}

func TestEventDataShape(t *testing.T) {
	if eventData(nil) != nil {
		t.Fatal("пустой список должен давать nil")
	}
	if got := eventData([]any{"a"}); got != "a" {
		t.Fatalf("одно значение: %v", got)
	}
	if got, ok := eventData([]any{"a", "b"}).([]any); !ok || len(got) != 2 {
		t.Fatalf("несколько значений: %v", got)
	}
}
