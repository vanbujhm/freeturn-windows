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

func TestActiveApps(t *testing.T) {
	o := Options{SplitOff: true, Apps: []AppRule{
		{Path: `C:\one.exe`}, {Path: `C:\two.exe`, Off: true}, {Path: `C:\three.exe`},
	}}
	if got := o.ActiveApps(); len(got) != 2 || got[0] != `C:\one.exe` || got[1] != `C:\three.exe` {
		t.Errorf("ActiveApps = %v", got)
	}
	if !o.AppsActive() {
		t.Error("AppsActive = false при включённых программах")
	}
	off := Options{Apps: []AppRule{{Path: `C:\two.exe`, Off: true}}}
	if off.AppsActive() || len(off.ActiveApps()) != 0 {
		t.Errorf("выключенная программа действует: %v", off.ActiveApps())
	}
	if (Options{}).AppsActive() || len(Options{}.ActiveApps()) != 0 {
		t.Error("пустой список действует")
	}
}
