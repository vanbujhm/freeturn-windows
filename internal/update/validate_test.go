package update

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
)

func okBody(r *http.Request, body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{}, Request: r, Body: io.NopCloser(strings.NewReader(body))}
}

func redirectTo(loc string) *http.Response {
	return &http.Response{StatusCode: 302, Header: http.Header{"Location": {loc}}, Body: io.NopCloser(strings.NewReader(""))}
}

func TestCheckVersionValidation(t *testing.T) {
	long := "v" + strings.Repeat("1", maxVersion+1)
	for _, tag := range []string{long, "v1.0<script>", "v1 .0", "v1.0\n", "v1.0/../x", "v1_0", "v1.0‮", "v1.0\"", "v1.0é"} {
		body, _ := json.Marshal(map[string]string{"tag_name": tag})
		f := &fakeTransport{status: 200, body: string(body)}
		if _, ok, err := Check(context.Background(), client(f), "o/r", "1.0.0"); ok || err == nil {
			t.Fatalf("тег %q принят", tag)
		}
	}
	// Ровно 64 знака проходят.
	f := &fakeTransport{status: 200, body: `{"tag_name":"v2` + strings.Repeat(".1", 31) + `1"}`}
	if rel, ok, err := Check(context.Background(), client(f), "o/r", "1.0.0"); err != nil || !ok || len(rel.Version) != maxVersion {
		t.Fatalf("предельная версия: ok=%v err=%v", ok, err)
	}
	f = &fakeTransport{status: 200, body: `{"tag_name":"v1.2.3-rc.1+build5"}`}
	if rel, _, err := Check(context.Background(), client(f), "o/r", "1.0.0"); err != nil || rel.Version != "1.2.3-rc.1+build5" {
		t.Fatalf("допустимые знаки: %+v %v", rel, err)
	}
}

func TestCheckURLValidation(t *testing.T) {
	bad := []string{
		"https://github.com@evil.example/x",
		"https://user@github.com/o/r",
		"https://user:pw@github.com/o/r",
		"https://github.com:8443/o/r",
		"https://github.com/o/r with space",
		"https://github.com/o/r\nx",
		"https://github.com/o/r\tx",
		"https://github.com/\\evil.example",
		"https://github.com/o/\x7fr",
		"https://github.com.evil.example/",
		"http://github.com/o/r",
		"HTTPS://github.com/o/r",
		"https://github.com/%zz",
	}
	for _, u := range bad {
		body, _ := json.Marshal(map[string]string{"tag_name": "v2.0.0", "html_url": u})
		f := &fakeTransport{status: 200, body: string(body)}
		rel, ok, err := Check(context.Background(), client(f), "o/r", "1.0.0")
		if err != nil || !ok || rel.URL != "" {
			t.Fatalf("%q: URL=%q ok=%v err=%v", u, rel.URL, ok, err)
		}
	}
	const good = "https://github.com/o/r/releases/tag/v2.0.0?x=1#y"
	f := &fakeTransport{status: 200, body: `{"tag_name":"v2.0.0","html_url":"` + good + `"}`}
	if rel, _, _ := Check(context.Background(), client(f), "o/r", "1.0.0"); rel.URL != good {
		t.Fatalf("законный адрес потерян: %q", rel.URL)
	}
}

func TestCheckRedirectPinned(t *testing.T) {
	// Переадресация на чужой хост отвергается, чужой хост не опрашивается.
	var hosts []string
	f := &fakeTransport{fn: func(r *http.Request) *http.Response {
		hosts = append(hosts, r.URL.Host)
		return redirectTo("https://evil.example/steal")
	}}
	if _, ok, err := Check(context.Background(), client(f), "o/r", "1.0.0"); ok || err == nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if slices.Contains(hosts, "evil.example") {
		t.Fatalf("запрос ушёл на чужой хост: %v", hosts)
	}

	// Переадресация на тот же API (переименованный репозиторий) работает.
	f2 := &fakeTransport{fn: func(r *http.Request) *http.Response {
		if r.URL.Path == "/repos/o/r/releases/latest" {
			return redirectTo("https://api.github.com/repositories/1/releases/latest")
		}
		return okBody(r, `{"tag_name":"v2.0.0"}`)
	}}
	if rel, ok, err := Check(context.Background(), client(f2), "o/r", "1.0.0"); err != nil || !ok || rel.Version != "2.0.0" {
		t.Fatalf("%+v ok=%v err=%v", rel, ok, err)
	}

	// Понижение до http, чужой порт и похожий хост тоже отвергаются.
	for _, loc := range []string{"http://api.github.com/x", "https://api.github.com:8443/x", "https://api.github.com.evil.example/x"} {
		f3 := &fakeTransport{fn: func(*http.Request) *http.Response { return redirectTo(loc) }}
		if _, ok, err := Check(context.Background(), client(f3), "o/r", "1.0.0"); ok || err == nil {
			t.Fatalf("%s принят", loc)
		}
	}

	// Бесконечная цепочка переадресаций обрывается.
	n := 0
	f4 := &fakeTransport{fn: func(*http.Request) *http.Response {
		n++
		return redirectTo("https://api.github.com/loop")
	}}
	if _, ok, err := Check(context.Background(), client(f4), "o/r", "1.0.0"); ok || err == nil || n > maxRedirects+2 {
		t.Fatalf("ok=%v err=%v запросов=%d", ok, err, n)
	}

	// Клиент вызывающего не меняется.
	c := client(f2)
	_, _, _ = Check(context.Background(), c, "o/r", "1.0.0")
	if c.CheckRedirect != nil {
		t.Fatal("Check изменил переданный клиент")
	}
}
