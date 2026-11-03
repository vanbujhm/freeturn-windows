package update

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeTransport отвечает вместо GitHub и считает запросы.
type fakeTransport struct {
	status int
	body   string
	err    error
	calls  atomic.Int32
	last   *http.Request
	fn     func(*http.Request) *http.Response // если задана, отвечает вместо status и body
}

func (f *fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.calls.Add(1)
	f.last = r
	if f.err != nil {
		return nil, f.err
	}
	if f.fn != nil {
		return f.fn(r), nil
	}
	return &http.Response{
		StatusCode: f.status,
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Header:     http.Header{},
		Request:    r,
	}, nil
}

func client(f *fakeTransport) *http.Client { return &http.Client{Transport: f} }

func TestNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.2.0", "1.1.9", true},
		{"1.10.0", "1.9.0", true},
		{"v1.0.0", "1.0.0", false},
		{"1.0.0", "v1.0.0", false},
		{"1.0", "1.0.0", false},
		{"1.0.1", "1.0", true},
		{"1.0.0", "1.0.1", false},
		{"мусор", "1.0.0", false},
		{"1.0.0", "мусор", false},
		{"1.0.0", "dev", false},
		{"", "1.0.0", false},
		{"1..0", "1.0.0", false},
		{"2.0.0", "2.0.0-rc1", true},
		{"2.0.0-rc1", "2.0.0", false},
		{"2.0.1-rc1", "2.0.0", true},
		{"99999999999999999999.0.0", "1.0.0", false},
	}
	for _, c := range cases {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, ждали %v", c.a, c.b, got, c.want)
		}
	}
}

func TestCheckNewVersion(t *testing.T) {
	f := &fakeTransport{status: 200, body: `{"tag_name":"v1.1.0","html_url":"https://github.com/o/r/releases/tag/v1.1.0"}`}
	rel, ok, err := Check(context.Background(), client(f), "o/r", "1.0.0")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if rel.Version != "1.1.0" || rel.URL != "https://github.com/o/r/releases/tag/v1.1.0" {
		t.Fatalf("релиз %+v", rel)
	}
	if got := f.last.URL.String(); got != "https://api.github.com/repos/o/r/releases/latest" {
		t.Fatalf("адрес %q", got)
	}
	if got := f.last.Header.Get("User-Agent"); got != "FreeTurn/1.0.0" {
		t.Fatalf("User-Agent %q", got)
	}
}

func TestCheckIgnoresForeignURL(t *testing.T) {
	for _, u := range []string{"http://github.com/o/r", "https://evil.example/", "https://github.com.evil.example/x", "javascript:alert(1)", ""} {
		f := &fakeTransport{status: 200, body: `{"tag_name":"v2.0.0","html_url":"` + u + `"}`}
		rel, ok, err := Check(context.Background(), client(f), "o/r", "1.0.0")
		if err != nil || !ok || rel.Version != "2.0.0" || rel.URL != "" {
			t.Fatalf("%q: %+v ok=%v err=%v", u, rel, ok, err)
		}
	}
}

func TestCheckSameVersion(t *testing.T) {
	f := &fakeTransport{status: 200, body: `{"tag_name":"v1.0.0","html_url":"https://github.com/o/r"}`}
	if _, ok, err := Check(context.Background(), client(f), "o/r", "1.0.0"); ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestCheckEmptyRepo(t *testing.T) {
	f := &fakeTransport{status: 200}
	if _, ok, err := Check(context.Background(), client(f), "", "1.0.0"); ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if f.calls.Load() != 0 {
		t.Fatal("при пустом репозитории был запрос")
	}
}

func TestCheckBadRepo(t *testing.T) {
	f := &fakeTransport{status: 200}
	for _, repo := range []string{"o", "o/r/x", "../x", "o/r?x=1", "o /r"} {
		if _, ok, err := Check(context.Background(), client(f), repo, "1.0.0"); ok || err == nil {
			t.Fatalf("%q принят", repo)
		}
	}
	if f.calls.Load() != 0 {
		t.Fatal("с негодным репозиторием был запрос")
	}
}

func TestCheckNetworkError(t *testing.T) {
	f := &fakeTransport{err: errors.New("секрет-в-тексте-ошибки")}
	_, ok, err := Check(context.Background(), client(f), "o/r", "1.0.0")
	if ok || err == nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if strings.Contains(err.Error(), "секрет") {
		t.Fatalf("текст ошибки сети попал наружу: %v", err)
	}
}

func TestCheckRateLimit(t *testing.T) {
	f := &fakeTransport{status: 403, body: `{"message":"API rate limit exceeded"}`}
	_, ok, err := Check(context.Background(), client(f), "o/r", "1.0.0")
	if ok || err == nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("тело ответа попало в ошибку: %v", err)
	}
}

func TestCheckBadBody(t *testing.T) {
	for _, body := range []string{"не json", `{"tag_name":""}`, `{}`} {
		f := &fakeTransport{status: 200, body: body}
		if _, ok, err := Check(context.Background(), client(f), "o/r", "1.0.0"); ok || err == nil {
			t.Fatalf("%q: ok=%v err=%v", body, ok, err)
		}
	}
}

func TestCheckBodyCapped(t *testing.T) {
	// JSON, который становится верным только после 1 МиБ: усечённое тело разбору не поддаётся.
	body := `{"tag_name":"v9.0.0","pad":"` + strings.Repeat("a", maxBody) + `"}`
	f := &fakeTransport{status: 200, body: body}
	if _, ok, err := Check(context.Background(), client(f), "o/r", "1.0.0"); ok || err == nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestWatch(t *testing.T) {
	f := &fakeTransport{status: 200, body: `{"tag_name":"v2.0.0"}`}
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan Release, 4)
	done := make(chan struct{})
	go func() {
		Watch(ctx, client(f), "o/r", "1.0.0", time.Millisecond, 5*time.Millisecond, func(r Release) { got <- r }, func() {})
		close(done)
	}()
	for i := 0; i < 2; i++ {
		select {
		case r := <-got:
			if r.Version != "2.0.0" {
				t.Fatalf("релиз %+v", r)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("нет события")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watch не остановился")
	}
}

func TestWatchEmptyRepo(t *testing.T) {
	f := &fakeTransport{status: 200}
	Watch(context.Background(), client(f), "", "1.0.0", time.Millisecond, time.Millisecond, func(Release) { t.Fatal("событие") }, func() { t.Fatal("ошибка") })
	if f.calls.Load() != 0 {
		t.Fatal("при пустом репозитории был запрос")
	}
}

func TestWatchReportsErrors(t *testing.T) {
	f := &fakeTransport{status: 500}
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan struct{}, 1)
	go Watch(ctx, client(f), "o/r", "1.0.0", time.Millisecond, time.Hour, func(Release) {}, func() { errs <- struct{}{} })
	select {
	case <-errs:
	case <-time.After(2 * time.Second):
		t.Fatal("ошибка не передана")
	}
	cancel()
}
