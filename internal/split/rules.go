// Package split разбирает правила обхода туннеля: что идёт мимо него напрямую.
package split

import (
	"errors"
	"net/netip"
	"strings"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// Коды причин пропуска правила. Окно превращает их в текст.
const (
	ReasonDefaultRoute = "default_route"
	ReasonTooWide      = "too_wide"
	ReasonInvalid      = "invalid"
)

// Самые широкие допустимые префиксы: правило шире почти целиком обходит туннель.
const (
	minBits4 = 8
	minBits6 = 16
)

var (
	// ErrInvalid означает, что ввод не адрес, не подсеть и не домен.
	ErrInvalid = errors.New("не похоже на адрес, подсеть или домен")
	// ErrWildcard означает, что введён шаблон, а шаблоны не поддерживаются.
	ErrWildcard = errors.New("шаблоны со звёздочкой не поддерживаются, укажите домен целиком")
)

// Skip описывает правило, которое не попало в обход, и причину.
type Skip struct {
	Rule   model.Rule
	Reason string
}

// Compiled хранит правила в виде, готовом для маршрутов и разрешения имён.
type Compiled struct {
	Prefixes []netip.Prefix // ip и subnet
	Domains  []string
	Skipped  []Skip // причина для журнала
}

// Classify определяет вид правила по вводу пользователя и приводит значение к норме.
func Classify(value string) (model.Rule, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return model.Rule{}, ErrInvalid
	}
	if strings.Contains(v, "*") {
		return model.Rule{}, ErrWildcard
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return model.Rule{Kind: model.RuleIP, Value: a.Unmap().String()}, nil
	}
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return model.Rule{}, ErrInvalid
		}
		return model.Rule{Kind: model.RuleSubnet, Value: p.Masked().String()}, nil
	}
	d, ok := normalizeDomain(v)
	if !ok {
		return model.Rule{}, ErrInvalid
	}
	return model.Rule{Kind: model.RuleDomain, Value: d}, nil
}

// normalizeDomain приводит домен к нижнему регистру без точки на конце
// и проверяет его по правилам имён узлов.
func normalizeDomain(v string) (string, bool) {
	d := strings.ToLower(strings.TrimSuffix(v, "."))
	if d == "" || len(d) > 253 {
		return "", false
	}
	labels := strings.Split(d, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", false
			}
		}
	}
	// Верхний уровень из одних цифр бывает только у неверного IPv4, вроде 300.1.1.1.
	if last := labels[len(labels)-1]; strings.Trim(last, "0123456789") == "" {
		return "", false
	}
	return d, true
}

// Compile превращает правила в префиксы и домены. Слишком широкие и неверные
// правила не ломают подключение: они попадают в Skipped, а дубли убираются.
// Вид правила определяется по значению, а не по полю Kind.
func Compile(rules []model.Rule) Compiled {
	var c Compiled
	seenPrefix := map[netip.Prefix]bool{}
	seenDomain := map[string]bool{}
	for _, r := range rules {
		norm, err := Classify(r.Value)
		if err != nil {
			c.Skipped = append(c.Skipped, Skip{Rule: r, Reason: ReasonInvalid})
			continue
		}
		if norm.Kind == model.RuleDomain {
			if !seenDomain[norm.Value] {
				seenDomain[norm.Value] = true
				c.Domains = append(c.Domains, norm.Value)
			}
			continue
		}
		p, ok := toPrefix(norm)
		if !ok {
			c.Skipped = append(c.Skipped, Skip{Rule: r, Reason: ReasonInvalid})
			continue
		}
		if reason := tooWide(p); reason != "" {
			c.Skipped = append(c.Skipped, Skip{Rule: r, Reason: reason})
			continue
		}
		if !seenPrefix[p] {
			seenPrefix[p] = true
			c.Prefixes = append(c.Prefixes, p)
		}
	}
	return c
}

// toPrefix даёт префикс для нормализованного правила ip или subnet.
func toPrefix(r model.Rule) (netip.Prefix, bool) {
	if r.Kind == model.RuleIP {
		a, err := netip.ParseAddr(r.Value)
		if err != nil {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	p, err := netip.ParsePrefix(r.Value)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// tooWide возвращает код причины, если префикс слишком широк, иначе пустую строку.
func tooWide(p netip.Prefix) string {
	bits := p.Bits()
	if bits <= 1 {
		return ReasonDefaultRoute
	}
	min := minBits6
	if p.Addr().Is4() {
		min = minBits4
	}
	if bits < min {
		return ReasonTooWide
	}
	return ""
}
