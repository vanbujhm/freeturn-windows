// Package link разбирает ссылки freeturn:// в профиль подключения.
package link

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

const scheme = "freeturn://"

// Ошибки разбора. Parse оборачивает их через %w, проверять нужно errors.Is.
var (
	ErrScheme   = errors.New("ссылка должна начинаться с freeturn://")
	ErrPayload  = errors.New("ссылка повреждена или обрезана")
	ErrVersion  = errors.New("неподдерживаемая версия ссылки")
	ErrRequired = errors.New("в ссылке нет provider или peer")
	ErrTCPMode  = errors.New("режим tcp не поддерживается")
)

// Parse разбирает ссылку freeturn:// в профиль.
// Пробелы и переносы строк из мессенджеров убираются до декодирования.
// Поля listen, bond и kcp игнорируются: на Windows ими управляет служба.
func Parse(raw string) (model.Profile, error) {
	text := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, raw)
	if len(text) < len(scheme) || !strings.EqualFold(text[:len(scheme)], scheme) {
		return model.Profile{}, ErrScheme
	}
	payload := text[len(scheme):]
	if i := strings.IndexByte(payload, '#'); i >= 0 {
		payload = payload[:i]
	}
	if i := strings.IndexByte(payload, '?'); i >= 0 {
		payload = payload[:i]
	}
	if payload == "" {
		return model.Profile{}, fmt.Errorf("%w: пусто после freeturn://", ErrPayload)
	}

	values, err := decode(payload)
	if err != nil {
		return model.Profile{}, err
	}

	if values["v"] != "1" {
		return model.Profile{}, fmt.Errorf("%w: %q", ErrVersion, values["v"])
	}
	if strings.EqualFold(values["mode"], "tcp") {
		return model.Profile{}, ErrTCPMode
	}
	if strings.TrimSpace(values["provider"]) == "" || strings.TrimSpace(values["peer"]) == "" {
		return model.Profile{}, ErrRequired
	}

	p := model.Profile{
		Name:           values["name"],
		Provider:       values["provider"],
		Peer:           values["peer"],
		Transport:      values["transport"],
		ObfProfile:     values["obf"],
		ObfKey:         values["key"],
		ObfTimingMs:    intValue(values["timing"]),
		Threads:        intValue(values["n"]),
		StreamsPerCred: intValue(values["spc"]),
		MTU:            intValue(values["mtu"]),
		ClientID:       values["cid"],
		CallLink:       values["vk"],
		DNSMode:        values["dns"],
		DNSServers:     splitList(values["dnss"]),
		ManualCaptcha:  strings.EqualFold(values["mcap"], "true"),
		WGConfig:       values["wg"],
	}
	if strings.TrimSpace(p.Name) == "" {
		p.Name = p.Peer
	}
	if strings.TrimSpace(p.ObfProfile) == "" {
		p.ObfProfile = "none"
	}
	return p, nil
}

// NewClientID возвращает 16 случайных байт в hex (32 символа).
func NewClientID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand не возвращает ошибку на поддерживаемых платформах.
		panic(err)
	}
	return hex.EncodeToString(b)
}

// decode превращает base64url-часть ссылки в плоскую карту значений.
// Строки теряют кавычки, числа и булевы остаются текстом, поэтому
// "n":10 и "n":"10" равноправны.
func decode(payload string) (map[string]string, error) {
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(payload, "="))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPayload, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPayload, err)
	}
	values := make(map[string]string, len(fields))
	for k, v := range fields {
		values[k] = rawText(v)
	}
	return values, nil
}

func rawText(v json.RawMessage) string {
	s := strings.TrimSpace(string(v))
	if s == "null" {
		return ""
	}
	if strings.HasPrefix(s, `"`) {
		var str string
		if err := json.Unmarshal(v, &str); err == nil {
			return str
		}
	}
	return s
}

func intValue(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
