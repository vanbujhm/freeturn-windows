package split

import "strings"

// MatchDomain ищет доменное правило для имени: правило совпадает с самим именем и со всеми его
// поддоменами. Из нескольких совпадений выбирается самое длинное правило. domains в
// нормализованном виде (Compiled.Domains), имя приводится к нему же: punycode, нижний
// регистр, без точки на конце. Неверное имя ни с чем не совпадает.
func MatchDomain(domains []string, name string) (rule string, ok bool) {
	n, valid := normalizeDomain(name)
	if !valid {
		return "", false
	}
	for _, d := range domains {
		if (n == d || strings.HasSuffix(n, "."+d)) && len(d) > len(rule) {
			rule, ok = d, true
		}
	}
	return rule, ok
}
