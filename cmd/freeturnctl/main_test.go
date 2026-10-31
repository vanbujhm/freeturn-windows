package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/vanbujhm/freeturn-windows/internal/link"
	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// testKey - сгенерированный ключ: base64 от 32 байт значения b.
func testKey(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

// makeLink собирает ссылку из полей.
func makeLink(t *testing.T, fields map[string]any) string {
	t.Helper()
	data, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return "freeturn://" + base64.RawURLEncoding.EncodeToString(data)
}

func baseLink(t *testing.T) string {
	t.Helper()
	return makeLink(t, map[string]any{
		"v": 1, "provider": "vk", "peer": "203.0.113.1:56000",
		"vk": "https://call.example.test/join/fromlink", "wg": "из ссылки",
	})
}

func fileBytes(t *testing.T, f map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseConnectFileOverlays(t *testing.T) {
	wg := "[Interface]\nPrivateKey = " + testKey(1) + "\n"
	req, err := parseConnectFile(fileBytes(t, map[string]any{
		"link":          baseLink(t),
		"wgConfig":      wg,
		"callLink":      "https://call.example.test/join/fromfile",
		"manualCaptcha": true,
		"options": map[string]any{
			"killSwitch": true,
			"allowLAN":   true,
			"rules":      []map[string]any{{"kind": "domain", "value": "example.test"}},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	p := req.Profile
	if p.Peer != "203.0.113.1:56000" || p.Provider != "vk" {
		t.Errorf("поля ссылки потеряны: %+v", p)
	}
	if p.WGConfig != wg || p.CallLink != "https://call.example.test/join/fromfile" || !p.ManualCaptcha {
		t.Errorf("поля файла не наложены: %+v", p)
	}
	o := req.Options
	if !o.KillSwitch || !o.AllowLAN ||
		!slices.Equal(o.Rules, []model.Rule{{Kind: model.RuleDomain, Value: "example.test"}}) {
		t.Errorf("настройки %+v", o)
	}
}

func TestParseConnectFileKeepsLinkFields(t *testing.T) {
	req, err := parseConnectFile(fileBytes(t, map[string]any{"link": baseLink(t)}))
	if err != nil {
		t.Fatal(err)
	}
	if req.Profile.WGConfig != "из ссылки" || req.Profile.CallLink != "https://call.example.test/join/fromlink" {
		t.Errorf("пустые поля файла затёрли ссылку: %+v", req.Profile)
	}
}

// Текст ошибки разбора цитирует содержимое ссылки, поэтому наружу идёт только категория.
func TestRejectedLinkPrintsOnlyCategory(t *testing.T) {
	const marker = "ТОЛЬКО-В-ФАЙЛЕ"
	tests := []struct {
		name string
		link string
		want error
	}{
		{"схема", "http://" + marker, link.ErrScheme},
		{"обрезана", "freeturn://" + marker, link.ErrPayload},
		{"версия", makeLink(t, map[string]any{"v": marker, "provider": "vk", "peer": "203.0.113.1:1"}), link.ErrVersion},
		{"нет полей", makeLink(t, map[string]any{"v": 1, "name": marker}), link.ErrRequired},
		{"tcp", makeLink(t, map[string]any{"v": 1, "mode": "tcp", "name": marker}), link.ErrTCPMode},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConnectFile(fileBytes(t, map[string]any{"link": tt.link}))
			if !errors.Is(err, tt.want) {
				t.Fatalf("ошибка %v", err)
			}
			if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), tt.link) {
				t.Fatalf("в ошибке содержимое ссылки: %v", err)
			}
		})
	}
}

func TestBadFileDoesNotEcho(t *testing.T) {
	_, err := parseConnectFile([]byte(`{"link": "freeturn://секрет`))
	if err == nil {
		t.Fatal("неверный JSON принят")
	}
	if strings.Contains(err.Error(), "секрет") {
		t.Fatalf("в ошибке содержимое файла: %v", err)
	}
}

// fakeService стоит на месте канала.
type fakeService struct {
	connected    []model.ConnectRequest
	disconnected int
	status       model.Status
	logs         []string
	err          error
}

func (f *fakeService) Connect(r model.ConnectRequest) error {
	f.connected = append(f.connected, r)
	return f.err
}

func (f *fakeService) Disconnect() error {
	f.disconnected++
	return f.err
}

func (f *fakeService) Status() (model.Status, error) { return f.status, f.err }
func (f *fakeService) Logs() ([]string, error)       { return f.logs, f.err }

func TestConnectNeverEchoesFile(t *testing.T) {
	secret := testKey(7)
	path := filepath.Join(t.TempDir(), "connect.json")
	data := fileBytes(t, map[string]any{"link": baseLink(t), "wgConfig": secret})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	svc := &fakeService{}
	var out bytes.Buffer
	if err := execute([]string{"connect", path}, svc, &out); err != nil {
		t.Fatal(err)
	}
	if len(svc.connected) != 1 || svc.connected[0].Profile.WGConfig != secret {
		t.Fatalf("запрос %+v", svc.connected)
	}
	if strings.Contains(out.String(), secret) {
		t.Fatalf("вывод содержит ключ: %s", out.String())
	}
}

func TestConnectUnreadableFile(t *testing.T) {
	svc := &fakeService{}
	err := execute([]string{"connect", filepath.Join(t.TempDir(), "нет.json")}, svc, &bytes.Buffer{})
	if err == nil || len(svc.connected) != 0 {
		t.Fatalf("ошибка %v, запросы %d", err, len(svc.connected))
	}
}

func TestStatusPrintsPhase(t *testing.T) {
	svc := &fakeService{status: model.Status{Phase: model.PhaseConnected, Streams: 4}}
	var out bytes.Buffer
	if err := execute([]string{"status"}, svc, &out); err != nil {
		t.Fatal(err)
	}
	var got model.Status
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("вывод не JSON: %v", err)
	}
	if got.Phase != model.PhaseConnected || got.Streams != 4 {
		t.Fatalf("статус %+v", got)
	}
}

func TestDisconnectAndLogs(t *testing.T) {
	svc := &fakeService{logs: []string{"первая", "вторая"}}
	var out bytes.Buffer
	if err := execute([]string{"disconnect"}, svc, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if svc.disconnected != 1 {
		t.Fatalf("Disconnect %d раз", svc.disconnected)
	}
	if err := execute([]string{"logs"}, svc, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "первая\nвторая\n" {
		t.Fatalf("журнал %q", out.String())
	}
}

// connect передаёт ключи, поэтому по умолчанию канал обязан принадлежать службе. Без этого их
// получил бы тот, кто занял имя канала раньше неё.
func TestExpectedOwner(t *testing.T) {
	owner, err := expectedOwner(false)
	if err != nil {
		t.Fatal(err)
	}
	if owner == nil || !owner.IsWellKnown(windows.WinLocalSystemSid) {
		t.Fatalf("владелец по умолчанию %v", owner)
	}
	owner, err = expectedOwner(true)
	if err != nil || owner != nil {
		t.Fatalf("-console: владелец %v, ошибка %v", owner, err)
	}
}

func TestValidCommand(t *testing.T) {
	good := [][]string{{"status"}, {"disconnect"}, {"logs"}, {"connect", "файл.json"}}
	for _, cmd := range good {
		if !validCommand(cmd) {
			t.Errorf("%v отвергнута", cmd)
		}
	}
	bad := [][]string{nil, {"connect"}, {"status", "лишнее"}, {"неизвестная"}, {"connect", "а", "б"}}
	for _, cmd := range bad {
		if validCommand(cmd) {
			t.Errorf("%v принята", cmd)
		}
	}
}
