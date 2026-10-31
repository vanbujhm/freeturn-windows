// Package secretmask прячет секреты в строках журнала и сообщений об ошибках.
package secretmask

import (
	"encoding/base64"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/wgconf"
)

// Replacement подставляется вместо каждого секрета.
const Replacement = "***"

// Masker заменяет известные секреты в строках.
type Masker struct {
	r *strings.Replacer
}

// New создаёт Masker. Пустые секреты и повторы пропускаются,
// длинные секреты заменяются раньше коротких.
func New(secrets ...string) *Masker {
	seen := map[string]bool{}
	var list []string
	for _, s := range secrets {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		list = append(list, s)
	}
	sort.SliceStable(list, func(i, j int) bool { return len(list[i]) > len(list[j]) })
	pairs := make([]string, 0, len(list)*2)
	for _, s := range list {
		pairs = append(pairs, s, Replacement)
	}
	return &Masker{r: strings.NewReplacer(pairs...)}
}

// ForProfile собирает все секреты профиля и разобранного конфига WireGuard.
// Конфиг может быть nil, если профиль ещё не разобран.
func ForProfile(p model.Profile, c *wgconf.Config) *Masker {
	secrets := []string{p.ObfKey, p.ClientID, p.CallLink, lastSegment(p.CallLink)}
	if c != nil {
		secrets = append(secrets, keyForms(c.PrivateKey)...)
		for _, peer := range c.Peers {
			secrets = append(secrets, keyForms(peer.PresharedKey)...)
		}
	}
	return New(secrets...)
}

// keyForms даёт ключ в base64 и hex: так он встречается в конфиге и в UAPI.
func keyForms(k wgconf.Key) []string {
	if k.IsZero() {
		return nil
	}
	return []string{base64.StdEncoding.EncodeToString(k[:]), hex.EncodeToString(k[:])}
}

// lastSegment возвращает последний сегмент пути ссылки без запроса и якоря.
func lastSegment(link string) string {
	if i := strings.IndexAny(link, "?#"); i >= 0 {
		link = link[:i]
	}
	if i := strings.Index(link, "://"); i >= 0 {
		link = link[i+3:]
	}
	link = strings.TrimRight(link, "/")
	if i := strings.LastIndex(link, "/"); i >= 0 {
		return link[i+1:]
	}
	return ""
}

// Mask заменяет все секреты в строке.
func (m *Masker) Mask(s string) string {
	return m.r.Replace(s)
}
