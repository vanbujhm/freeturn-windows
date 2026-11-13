package dnsproxy

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

func entry(name string) model.QueryEntry { return model.QueryEntry{Name: name, Type: "A"} }

func TestLogSince(t *testing.T) {
	l := NewLog()
	for _, n := range []string{"a", "b", "c"} {
		l.Add(entry(n))
	}
	got, last := l.Since(0)
	if len(got) != 3 || last != 3 || got[0].Seq != 1 || got[2].Seq != 3 || got[2].Name != "c" {
		t.Fatalf("Since(0) = %+v, %d", got, last)
	}
	got, last = l.Since(2)
	if len(got) != 1 || got[0].Seq != 3 || last != 3 {
		t.Fatalf("Since(2) = %+v, %d", got, last)
	}
	got, last = l.Since(3)
	if len(got) != 0 || last != 3 {
		t.Fatalf("Since(3) = %+v, %d", got, last)
	}
}

func TestLogOverflow(t *testing.T) {
	l := NewLog()
	for i := range LogSize + 5 {
		l.Add(entry(fmt.Sprint(i)))
	}
	got, last := l.Since(0)
	if len(got) != LogSize || got[0].Seq != 6 || last != LogSize+5 || got[len(got)-1].Seq != LogSize+5 {
		t.Fatalf("после переполнения %d записей, первая %d, last %d", len(got), got[0].Seq, last)
	}
}

func TestLogClear(t *testing.T) {
	l := NewLog()
	l.Add(entry("a"))
	l.Add(entry("b"))
	l.Clear()
	if got, last := l.Since(0); len(got) != 0 || last != 2 {
		t.Fatalf("после Clear %+v, %d", got, last)
	}
	l.Add(entry("c"))
	if got, _ := l.Since(0); len(got) != 1 || got[0].Seq != 3 {
		t.Fatalf("после Clear и Add %+v", got)
	}
}

func TestLogTrimsAddrs(t *testing.T) {
	l := NewLog()
	e := entry("a")
	for i := range 10 {
		e.Addrs = append(e.Addrs, netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}))
	}
	l.Add(e)
	got, _ := l.Since(0)
	if len(got[0].Addrs) != MaxEntryAddrs || got[0].Addrs[7] != e.Addrs[7] {
		t.Fatalf("адресов %d", len(got[0].Addrs))
	}
}

func TestLogCopies(t *testing.T) {
	l := NewLog()
	e := entry("a")
	e.Addrs = []netip.Addr{netip.MustParseAddr("203.0.113.1")}
	l.Add(e)
	got, _ := l.Since(0)
	got[0].Addrs[0] = netip.MustParseAddr("203.0.113.99")
	e.Addrs[0] = netip.MustParseAddr("203.0.113.98")
	again, _ := l.Since(0)
	if again[0].Addrs[0] != netip.MustParseAddr("203.0.113.1") {
		t.Fatalf("буфер изменился через копию: %v", again[0].Addrs)
	}
}
