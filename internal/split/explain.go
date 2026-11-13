package split

import (
	"errors"
	"net/netip"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

// Verdict - куда по правилам идёт трафик адреса.
type Verdict string

const (
	VerdictTunnel Verdict = "tunnel"
	VerdictDirect Verdict = "direct"
)

// ErrSubnetInput: проверка принимает адрес или сайт, подсеть проверять нечего.
var ErrSubnetInput = errors.New("проверяется адрес или сайт, а не подсеть")

// Match - совпавшее правило. Нулевое значение: ни одно правило не совпало.
type Match struct {
	Rule model.Rule
	// Addr - адрес, по которому совпало правило IP или подсети. Пуст при совпадении по имени.
	Addr netip.Addr
}

// Explanation - ответ проверки по правилам.
type Explanation struct {
	Input    model.Rule // нормализованный ввод
	Verdict  Verdict
	Match    Match // действующее правило
	OffMatch Match // выключенное правило, которое совпало бы, если действующего нет
	SplitOff bool  // раздельное туннелирование выключено, всё идёт через туннель
}

// Explain сопоставляет адрес или домен с правилами. addrs - адреса домена, если они
// известны: они сверяются с правилами IP и подсетей. Доменное правило действует и для
// поддоменов, см. MatchDomain.
func Explain(o model.Options, input string, addrs []netip.Addr) (Explanation, error) {
	in, err := Classify(input)
	if err != nil {
		return Explanation{}, err
	}
	if in.Kind == model.RuleSubnet {
		return Explanation{}, ErrSubnetInput
	}
	ex := Explanation{Input: in}
	if o.SplitOff {
		ex.SplitOff = true
		ex.Verdict = VerdictTunnel
		return ex, nil
	}
	if in.Kind == model.RuleIP {
		addrs = []netip.Addr{netip.MustParseAddr(in.Value)}
	}
	var on, off []model.Rule
	for _, r := range o.Rules {
		norm, err := Classify(r.Value)
		if err != nil {
			continue
		}
		norm.Comment, norm.Off = r.Comment, r.Off
		if r.Off {
			off = append(off, norm)
		} else {
			on = append(on, norm)
		}
	}
	ex.Match = find(on, in, addrs)
	if ex.Match.Rule.Value == "" {
		ex.OffMatch = find(off, in, addrs)
	}
	listed := ex.Match.Rule.Value != ""
	if listed == (o.SplitMode == model.SplitOnly) {
		ex.Verdict = VerdictTunnel
	} else {
		ex.Verdict = VerdictDirect
	}
	return ex, nil
}

// find ищет сначала доменное правило для имени (MatchDomain), потом самый длинный префикс правил IP
// и подсетей, содержащий один из адресов.
func find(rules []model.Rule, in model.Rule, addrs []netip.Addr) Match {
	if in.Kind == model.RuleDomain {
		var domains []string
		for _, r := range rules {
			if r.Kind == model.RuleDomain {
				domains = append(domains, r.Value)
			}
		}
		if d, ok := MatchDomain(domains, in.Value); ok {
			for _, r := range rules {
				if r.Kind == model.RuleDomain && r.Value == d {
					return Match{Rule: r}
				}
			}
		}
	}
	var best Match
	bestBits := -1
	for _, a := range addrs {
		a = a.Unmap()
		for _, r := range rules {
			if r.Kind == model.RuleDomain {
				continue
			}
			p, ok := toPrefix(r)
			if !ok || !p.Contains(a) || p.Bits() <= bestBits {
				continue
			}
			best, bestBits = Match{Rule: r, Addr: a}, p.Bits()
		}
	}
	return best
}
