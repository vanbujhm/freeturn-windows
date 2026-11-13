package model

import (
	"net/netip"
	"time"
)

// Via - интерфейс, через который Windows сейчас отправляет пакет на адрес.
type Via string

const (
	ViaTunnel Via = "tunnel" // адаптер туннеля
	ViaDirect Via = "direct" // физический интерфейс сессии
	ViaOther  Via = "other"  // любой другой адаптер
)

// ProbeNotConnected - текст ошибки проверки маршрута без подключения. Движок возвращает его
// как ошибку, канал передаёт окну и узнаёт по нему, что туннеля нет.
const ProbeNotConnected = "not_connected"

// ProbeHop - адрес и интерфейс его маршрута. Via пуст, если маршрут узнать не удалось.
type ProbeHop struct {
	Addr netip.Addr
	Via  Via
	// Local: адрес идёт напрямую маршрутом подключённой подсети (роутер, принтер).
	Local bool
	// Outside: туннель ведёт весь трафик, кроме списка, но адреса нет в AllowedIPs профиля.
	Outside bool
}

// QueryEntry - запись журнала DNS-запросов: что спросила программа, у какой стороны и куда
// пойдёт трафик адресов. Upstream и Route: "tunnel" или "direct".
type QueryEntry struct {
	Seq      uint64
	Time     time.Time
	Name     string
	Type     string // A, AAAA, HTTPS, ...
	Addrs    []netip.Addr
	Upstream string
	Route    string
	Rule     string // значение сработавшего правила или пусто
	RCode    string
	Took     time.Duration
	Late     bool // ответ ушёл до применения маршрута
}

// QueryPage - записи журнала после заданного номера. Active: прокси сеанса работает.
type QueryPage struct {
	Entries []QueryEntry
	Last    uint64
	Active  bool
}
