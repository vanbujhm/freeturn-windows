package model

import "testing"

func TestOptionsSplitModes(t *testing.T) {
	rules := []Rule{{Kind: RuleIP, Value: "203.0.113.1"}}
	cases := []struct {
		name               string
		o                  Options
		active, only, keep bool
	}{
		{"обход", Options{KillSwitch: true, Rules: rules}, true, false, true},
		{"только список", Options{KillSwitch: true, Rules: rules, SplitMode: SplitOnly}, true, true, false},
		{"выключено", Options{KillSwitch: true, Rules: rules, SplitOff: true, SplitMode: SplitOnly}, false, false, true},
		{"без защиты", Options{Rules: rules}, true, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := len(c.o.ActiveRules()) > 0; got != c.active {
				t.Errorf("ActiveRules непуст = %v", got)
			}
			if got := c.o.TunnelOnly(); got != c.only {
				t.Errorf("TunnelOnly = %v", got)
			}
			if got := c.o.Blocks(); got != c.keep {
				t.Errorf("Blocks = %v", got)
			}
		})
	}
}
