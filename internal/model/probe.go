package model

import "net/netip"

// Via - интерфейс, через который Windows сейчас отправляет пакет на адрес.
type Via string

const (
	ViaTunnel Via = "tunnel" // адаптер туннеля
	ViaDirect Via = "direct" // физический интерфейс сессии
	ViaOther  Via = "other"  // любой другой адаптер
)

// ProbeHop - адрес и интерфейс его маршрута. Via пуст, если маршрут узнать не удалось.
type ProbeHop struct {
	Addr netip.Addr
	Via  Via
	// Local: адрес идёт напрямую маршрутом подключённой подсети (роутер, принтер).
	Local bool
	// Outside: туннель ведёт весь трафик, кроме списка, но адреса нет в AllowedIPs профиля.
	Outside bool
}
