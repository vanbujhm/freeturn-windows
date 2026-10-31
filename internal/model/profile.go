// Package model содержит простые типы, которыми обмениваются окно, служба и ядро.
// Все поля открытые и годятся для JSON.
package model

import (
	"net/netip"
	"strings"
)

// Field называет обязательное поле профиля, которого не хватает для подключения.
type Field string

const (
	FieldCallLink Field = "callLink"
	FieldWGConfig Field = "wgConfig"
)

// Profile описывает один профиль подключения.
type Profile struct {
	ID, Name, Provider, Peer, Transport       string
	ObfProfile, ObfKey                        string
	ObfTimingMs, Threads, StreamsPerCred, MTU int
	ClientID, CallLink, DNSMode               string
	DNSServers                                []string
	ManualCaptcha, GeneratedClientID          bool
	WGConfig                                  string
}

// Missing возвращает поля, без которых профиль нельзя подключить.
// Ссылка на звонок нужна всем провайдерам, кроме direct.
func (p Profile) Missing() []Field {
	var missing []Field
	if p.Provider != "direct" && strings.TrimSpace(p.CallLink) == "" {
		missing = append(missing, FieldCallLink)
	}
	if strings.TrimSpace(p.WGConfig) == "" {
		missing = append(missing, FieldWGConfig)
	}
	return missing
}

// RuleKind задаёт вид правила обхода туннеля.
type RuleKind string

const (
	RuleIP     RuleKind = "ip"
	RuleSubnet RuleKind = "subnet"
	RuleDomain RuleKind = "domain"
)

// Rule исключает адрес, подсеть или домен из туннеля.
type Rule struct {
	Kind  RuleKind
	Value string
}

// Options задаёт параметры одного подключения, не относящиеся к профилю.
type Options struct {
	KillSwitch, AllowLAN bool
	Rules                []Rule
}

// ConnectRequest передаётся от окна службе при подключении.
type ConnectRequest struct {
	Profile Profile
	Options Options
}

// Physical описывает физический интерфейс, через который идёт трафик мимо туннеля.
type Physical struct {
	LUID               uint64
	Index4, Index6     uint32
	Gateway4, Gateway6 netip.Addr
	DNS                []netip.Addr
}
