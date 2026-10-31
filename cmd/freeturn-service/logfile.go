package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// logFileLimit - предел одного файла журнала. Файлов не больше трёх: текущий и два старых.
	logFileLimit = 1 << 20
	// ringLines - сколько последних строк служба отдаёт окну.
	ringLines = 2000
	// logQueue - сколько строк ждёт записи на диск. Больше: строка теряется, а не ждёт.
	logQueue = 1024
)

var logNames = []string{"service.log", "service.1.log", "service.2.log"}

// ring хранит последние строки журнала. Строки не длиннее тех, что пришли, поэтому память
// ограничена числом строк.
type ring struct {
	mu    sync.Mutex
	lines []string
	next  int // куда лечь следующей строке
	full  bool
}

func newRing(n int) *ring {
	return &ring{lines: make([]string, n)}
}

func (r *ring) add(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines[r.next] = line
	r.next++
	if r.next == len(r.lines) {
		r.next, r.full = 0, true
	}
}

// last возвращает строки от старых к новым.
func (r *ring) last() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		out := make([]string, r.next)
		copy(out, r.lines)
		return out
	}
	out := make([]string, 0, len(r.lines))
	out = append(out, r.lines[r.next:]...)
	return append(out, r.lines[:r.next]...)
}

// rotatingFile пишет в service.log и при достижении предела сдвигает файлы: service.log
// становится service.1.log, тот service.2.log, а самый старый исчезает. Вызывается из одного
// потока. Файл открывается при первой записи: сбой диска не должен мешать запуску службы.
type rotatingFile struct {
	dir   string
	limit int64
	f     *os.File
	size  int64
}

func newRotatingFile(dir string, limit int64) *rotatingFile {
	return &rotatingFile{dir: dir, limit: limit}
}

func (r *rotatingFile) open() error {
	f, err := os.OpenFile(filepath.Join(r.dir, logNames[0]), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

func (r *rotatingFile) write(line string) error {
	if r.f == nil {
		if err := r.open(); err != nil {
			return err
		}
	}
	if r.size > 0 && r.size+int64(len(line)) > r.limit {
		if err := r.rotate(); err != nil {
			return err
		}
	}
	n, err := r.f.WriteString(line)
	r.size += int64(n)
	return err
}

// rotate сдвигает файлы. Если сдвинуть не вышло, например файл держит антивирус, запись
// продолжается в текущий файл, а следующая строка попробует снова.
func (r *rotatingFile) rotate() error {
	r.close()
	var shiftErr error
	for i := len(logNames) - 1; i > 0; i-- {
		err := os.Rename(filepath.Join(r.dir, logNames[i-1]), filepath.Join(r.dir, logNames[i]))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			shiftErr = err
		}
	}
	if err := r.open(); err != nil {
		return errors.Join(shiftErr, err)
	}
	return nil
}

func (r *rotatingFile) close() {
	if r.f != nil {
		r.f.Close()
		r.f = nil
	}
}

// fileSink пишет строки на диск в своём потоке. put не ждёт: его зовут из потока событий ядра
// и под замками движка. Строка, которой нет места в очереди или которую не удалось записать,
// теряется и считается, а счётчик попадает в журнал при следующей удачной записи.
type fileSink struct {
	lines    chan string
	write    func(string) error
	dropped  atomic.Uint64
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

func newFileSink(write func(string) error, queue int) *fileSink {
	s := &fileSink{
		lines: make(chan string, queue),
		write: write,
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go s.loop()
	return s
}

func (s *fileSink) put(line string) {
	select {
	case s.lines <- line:
	default:
		s.dropped.Add(1)
	}
}

func (s *fileSink) loop() {
	defer close(s.done)
	for {
		select {
		case line := <-s.lines:
			s.store(line)
		case <-s.stop:
			s.drain()
			s.reportDropped()
			return
		}
	}
}

func (s *fileSink) drain() {
	for {
		select {
		case line := <-s.lines:
			s.store(line)
		default:
			return
		}
	}
}

func (s *fileSink) store(line string) {
	s.reportDropped()
	if s.write(line) != nil {
		s.dropped.Add(1)
	}
}

// reportDropped пишет счётчик потерь. Если запись не удалась, счётчик остаётся на потом.
func (s *fileSink) reportDropped() {
	if n := s.dropped.Swap(0); n > 0 {
		if s.write(fmt.Sprintf("потеряно строк журнала: %d\n", n)) != nil {
			s.dropped.Add(n)
		}
	}
}

// close записывает очередь и останавливает поток. Поздний put ничего не ломает: строка
// остаётся в очереди или теряется.
func (s *fileSink) close() {
	s.stopOnce.Do(func() { close(s.stop) })
	<-s.done
}

// serviceLog - журнал службы: кольцо для окна, файл и рассылка клиентам. Текст приходит уже
// замаскированным, write ничего не ждёт.
type serviceLog struct {
	ring      *ring
	file      *fileSink
	disk      *rotatingFile
	broadcast func(line string)
	now       func() time.Time
}

// newServiceLog открывает журнал в dir. Если echo не nil, строки идут и туда, в потоке записи
// на диск: остановленная консоль задерживает только его.
func newServiceLog(dir string, echo io.Writer, broadcast func(string)) *serviceLog {
	disk := newRotatingFile(dir, logFileLimit)
	write := disk.write
	if echo != nil {
		write = func(line string) error {
			io.WriteString(echo, line)
			return disk.write(line)
		}
	}
	return &serviceLog{
		ring:      newRing(ringLines),
		file:      newFileSink(write, logQueue),
		disk:      disk,
		broadcast: broadcast,
		now:       time.Now,
	}
}

func (l *serviceLog) write(level, msg string) {
	line := l.now().Format(time.DateTime) + " [" + level + "] " + msg
	l.ring.add(line)
	l.file.put(line + "\n")
	l.broadcast(line)
}

// close дописывает очередь и закрывает файл.
func (l *serviceLog) close() {
	l.file.close()
	l.disk.close()
}
