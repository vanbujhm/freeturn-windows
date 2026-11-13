// Package dnsproxy - DNS-сервер сеанса: пересылает запросы на сторону, куда пойдёт трафик
// имени, ждёт маршрута для имён под правилом и записывает запросы в журнал.
package dnsproxy

import (
	"slices"
	"sync"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

const (
	// LogSize - сколько записей держит журнал запросов.
	LogSize = 2000
	// MaxEntryAddrs - сколько адресов хранит одна запись.
	MaxEntryAddrs = 8
)

// Log - кольцевой журнал запросов в памяти службы. На диск не пишется. Номера записей растут
// и после Clear, поэтому окно может спрашивать с последнего виденного.
type Log struct {
	mu   sync.Mutex
	ring []model.QueryEntry
	next int // куда ляжет следующая запись
	full bool
	seq  uint64
}

func NewLog() *Log { return &Log{ring: make([]model.QueryEntry, LogSize)} }

// Add ставит записи номер и кладёт её копию, обрезав адреса до MaxEntryAddrs.
func (l *Log) Add(e model.QueryEntry) {
	if len(e.Addrs) > MaxEntryAddrs {
		e.Addrs = e.Addrs[:MaxEntryAddrs]
	}
	e.Addrs = slices.Clone(e.Addrs)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	e.Seq = l.seq
	l.ring[l.next] = e
	l.next = (l.next + 1) % len(l.ring)
	if l.next == 0 {
		l.full = true
	}
}

// Since возвращает копии записей с номером больше seq от старых к новым и последний номер.
func (l *Log) Since(seq uint64) (entries []model.QueryEntry, last uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	start, n := 0, l.next
	if l.full {
		start, n = l.next, len(l.ring)
	}
	for i := range n {
		e := l.ring[(start+i)%len(l.ring)]
		if e.Seq > seq {
			e.Addrs = slices.Clone(e.Addrs)
			entries = append(entries, e)
		}
	}
	return entries, l.seq
}

// Clear стирает записи, номер не сбрасывает.
func (l *Log) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	clear(l.ring)
	l.next, l.full = 0, false
}
