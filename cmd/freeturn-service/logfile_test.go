package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// logFilesIn возвращает имена файлов каталога журнала.
func logFilesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestRotateAtLimit(t *testing.T) {
	dir := t.TempDir()
	w := newRotatingFile(dir, logFileLimit)
	defer w.close()

	line := strings.Repeat("x", 1023) + "\n"
	// Хватает на пять полных файлов: лишние должны быть удалены.
	for range 5 * 1024 {
		if err := w.write(line); err != nil {
			t.Fatal(err)
		}
	}
	w.close()

	want := []string{"service.1.log", "service.2.log", "service.log"}
	if got := logFilesIn(t, dir); !slices.Equal(got, want) {
		t.Fatalf("файлы %v, ожидались %v", got, want)
	}
	for _, name := range want {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() == 0 || st.Size() > logFileLimit {
			t.Errorf("%s: размер %d", name, st.Size())
		}
	}
}

// Служба перезапускается часто, поэтому файл дописывается, а не начинается заново.
func TestRotatingFileKeepsExisting(t *testing.T) {
	dir := t.TempDir()
	w := newRotatingFile(dir, 16)
	if err := w.write("первая\n"); err != nil {
		t.Fatal(err)
	}
	w.close()

	w = newRotatingFile(dir, 16)
	defer w.close()
	if err := w.write("x\n"); err != nil {
		t.Fatal(err)
	}
	w.close()

	data, err := os.ReadFile(filepath.Join(dir, "service.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "первая\nx\n" {
		t.Fatalf("содержимое %q", data)
	}
}

func TestRingKeepsLast(t *testing.T) {
	r := newRing(ringLines)
	for i := range ringLines + 500 {
		r.add(strconv.Itoa(i))
	}
	got := r.last()
	if len(got) != ringLines {
		t.Fatalf("строк %d", len(got))
	}
	if got[0] != "500" || got[len(got)-1] != strconv.Itoa(ringLines+499) {
		t.Fatalf("первая %q, последняя %q", got[0], got[len(got)-1])
	}
}

func TestRingBeforeFull(t *testing.T) {
	r := newRing(ringLines)
	if got := r.last(); len(got) != 0 {
		t.Fatalf("пустое кольцо отдало %v", got)
	}
	r.add("a")
	r.add("b")
	if got := r.last(); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("строки %v", got)
	}
}

// recorder - приёмник строк для fileSink: может задерживать запись и отказывать.
type recorder struct {
	mu    sync.Mutex
	lines []string
	fail  bool
	gate  chan struct{} // nil: запись не ждёт
}

func (r *recorder) write(line string) error {
	if r.gate != nil {
		<-r.gate
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return errors.New("диск недоступен")
	}
	r.lines = append(r.lines, line)
	return nil
}

func (r *recorder) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.lines)
}

// Запись на диск не должна держать поток событий ядра: зависший диск только теряет строки,
// а потери считаются и попадают в журнал.
func TestFileSinkDropsInsteadOfBlocking(t *testing.T) {
	rec := &recorder{gate: make(chan struct{})}
	s := newFileSink(rec.write, 2)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 100 {
			s.put(fmt.Sprintf("строка %d", i))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("put заблокировался на занятом диске")
	}

	close(rec.gate)
	s.close()

	got := rec.got()
	notice := -1
	for i, line := range got {
		if strings.Contains(line, "потеряно") {
			notice = i
		}
	}
	if notice < 0 {
		t.Fatalf("нет записи о потерях: %q", got)
	}
	if len(got) >= 100 {
		t.Fatalf("при полной очереди ничего не потеряно: %d строк", len(got))
	}
}

func TestFileSinkDrainsOnClose(t *testing.T) {
	rec := &recorder{}
	s := newFileSink(rec.write, 16)
	for i := range 10 {
		s.put(strconv.Itoa(i))
	}
	s.close()
	if got := rec.got(); len(got) != 10 {
		t.Fatalf("записано %v", got)
	}
}

// Потери в самом конце работы некому записать следующей строкой, их пишет close.
func TestFileSinkReportsDropsOnClose(t *testing.T) {
	rec := &recorder{}
	s := newFileSink(rec.write, 16)
	s.dropped.Add(3)
	s.close()
	got := rec.got()
	if len(got) != 1 || !strings.Contains(got[0], "потеряно строк журнала: 3") {
		t.Fatalf("записано %q", got)
	}
}

// Ядро может дописать строку после завершения службы: это не должно ронять процесс.
func TestFileSinkPutAfterClose(t *testing.T) {
	rec := &recorder{}
	s := newFileSink(rec.write, 2)
	s.close()
	s.close()
	for range 10 {
		s.put("поздняя строка")
	}
}

func TestFileSinkCountsFailedWrites(t *testing.T) {
	rec := &recorder{fail: true}
	s := newFileSink(rec.write, 16)
	s.put("a")
	s.put("b")
	s.close()
	if n := s.dropped.Load(); n != 2 {
		t.Fatalf("потеряно %d", n)
	}
}

func TestServiceLogFansOut(t *testing.T) {
	rec := &recorder{}
	var sent []string
	l := &serviceLog{
		ring:      newRing(ringLines),
		file:      newFileSink(rec.write, 16),
		broadcast: func(line string) { sent = append(sent, line) },
		now:       func() time.Time { return time.Date(2026, 10, 31, 12, 30, 45, 0, time.UTC) },
	}
	l.write("warn", "сообщение")
	l.file.close()

	const want = "2026-10-31 12:30:45 [warn] сообщение"
	if got := l.ring.last(); !slices.Equal(got, []string{want}) {
		t.Errorf("кольцо %q", got)
	}
	if got := rec.got(); !slices.Equal(got, []string{want + "\n"}) {
		t.Errorf("файл %q", got)
	}
	if !slices.Equal(sent, []string{want}) {
		t.Errorf("рассылка %q", sent)
	}
}
