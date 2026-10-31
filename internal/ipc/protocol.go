// Package ipc связывает окно и службу по именованному каналу. Сообщения это JSON по
// строкам, у каждого есть поле type: req, resp или event.
//
// ConnectRequest несёт секреты и идёт только от клиента к серверу: тип ответа и события
// его не содержат, поэтому профиль не может попасть в ответ или событие по ошибке.
// Пакет ничего не пишет в журнал.
package ipc

import (
	"time"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

const (
	// PipePath - имя канала службы.
	PipePath = `\\.\pipe\FreeTurnService`
	// PipeSDDL: SYSTEM и администраторы полный доступ, вошедшие пользователи чтение и запись.
	PipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"
)

// Виды сообщений (поле type).
const (
	typeReq   = "req"
	typeResp  = "resp"
	typeEvent = "event"
)

// Команды окна (поле method).
const (
	methodConnect    = "Connect"
	methodDisconnect = "Disconnect"
	methodGetStatus  = "GetStatus"
	methodGetLogs    = "GetLogs"
)

// Виды событий.
const (
	KindStatus = "status"
	KindLog    = "log"
)

const (
	// maxServerLine - предел строки от клиента. Больше: клиент отключается.
	maxServerLine = 1 << 20
	// maxClientLine - предел строки от службы. Выше серверного: журнал может быть длинным.
	maxClientLine = 16 << 20
	// queueLimit - размер очереди событий одного клиента.
	queueLimit = 256
	// respLimit - сколько ответов может ждать записи. Клиент шлёт запросы по одному и ждёт
	// ответ, так что превышение значит, что он ничего не читает.
	respLimit = 16
	// writeTimeout - сколько писатель ждёт клиента, который не читает, до отключения.
	writeTimeout = 30 * time.Second
)

// Event - событие службы. Kind: "status" или "log".
type Event struct {
	Kind   string        `json:"kind"`
	Status *model.Status `json:"status,omitempty"`
	Log    string        `json:"log,omitempty"`
}

// request - сообщение от клиента.
type request struct {
	Type    string                `json:"type"`
	ID      uint64                `json:"id"`
	Method  string                `json:"method"`
	Connect *model.ConnectRequest `json:"connect,omitempty"`
}

// response - ответ службы на запрос с тем же id.
type response struct {
	Type   string        `json:"type"`
	ID     uint64        `json:"id"`
	Err    string        `json:"err,omitempty"`
	Status *model.Status `json:"status,omitempty"`
	Logs   []string      `json:"logs,omitempty"`
}

// eventMsg - событие в проводе.
type eventMsg struct {
	Type  string `json:"type"`
	Event Event  `json:"event"`
}

// serverMsg - всё, что клиент может получить от службы. Поля Connect здесь нет.
type serverMsg struct {
	Type   string        `json:"type"`
	ID     uint64        `json:"id"`
	Err    string        `json:"err"`
	Status *model.Status `json:"status"`
	Logs   []string      `json:"logs"`
	Event  Event         `json:"event"`
}
