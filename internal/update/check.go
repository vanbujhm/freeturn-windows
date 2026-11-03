// Package update проверяет, вышла ли новая версия программы. Ничего не скачивает: только
// спрашивает GitHub о последнем релизе и отдаёт номер со ссылкой на страницу релиза.
package update

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// apiBase - адрес API. Репозиторий подставляется из переменной сборки.
	apiBase = "https://api.github.com/repos/"
	// pageHost - единственное начало адреса страницы релиза, которое принимается.
	pageHost = "https://github.com/"
	// requestTimeout - предел одного запроса.
	requestTimeout = 10 * time.Second
	// maxVersion - предел длины номера версии.
	maxVersion = 64
	// apiHost - единственный хост, на который разрешены переадресации.
	apiHost = "api.github.com"
	// maxRedirects - сколько переадресаций допускается.
	maxRedirects = 5
	// maxBody - сколько байт ответа читается. Остальное отбрасывается.
	maxBody = 1 << 20
)

// Ошибки заданы постоянным текстом: в них нет ни тела ответа, ни подробностей сети, так что
// их можно показывать в журнале как есть.
var (
	ErrRepo    = errors.New("некорректный репозиторий для проверки версии")
	ErrRequest = errors.New("не удалось связаться с GitHub")
	ErrStatus  = errors.New("GitHub не отдал сведения о релизе")
	ErrFormat  = errors.New("непонятный ответ GitHub")
)

// repoPattern - owner/name: буквы, цифры, точка, дефис, подчёркивание.
var repoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// repoOK проверяет вид owner/name и отсекает сегменты "." и "..", которые меняли бы путь запроса.
func repoOK(repo string) bool {
	if !repoPattern.MatchString(repo) {
		return false
	}
	for _, seg := range strings.Split(repo, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// Release - сведения о новом релизе. URL пуст, если GitHub прислал адрес не со своего сайта.
type Release struct{ Version, URL string }

// Check спрашивает последний релиз репозитория repo ("владелец/имя") и сообщает, новее ли он
// current. Пустой repo отключает проверку: запроса нет, ответ (Release{}, false, nil).
func Check(ctx context.Context, c *http.Client, repo, current string) (Release, bool, error) {
	if repo == "" {
		return Release{}, false, nil
	}
	if !repoOK(repo) {
		return Release{}, false, ErrRepo
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+repo+"/releases/latest", nil)
	if err != nil {
		return Release{}, false, ErrRequest
	}
	req.Header.Set("User-Agent", "FreeTurn/"+current)
	req.Header.Set("Accept", "application/vnd.github+json")
	// Переадресации разрешены только на тот же API: копия клиента, чужой клиент не меняется.
	pinned := *c
	pinned.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects || r.URL.Scheme != "https" || r.URL.Hostname() != apiHost || r.URL.Port() != "" {
			return ErrRequest
		}
		return nil
	}
	resp, err := pinned.Do(req)
	if err != nil {
		return Release{}, false, ErrRequest
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Release{}, false, ErrStatus
	}
	var body struct {
		Tag     string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&body); err != nil {
		return Release{}, false, ErrFormat
	}
	ver := strings.TrimPrefix(strings.TrimPrefix(body.Tag, "v"), "V")
	if !versionOK(ver) {
		return Release{}, false, ErrFormat
	}
	rel := Release{Version: ver}
	if pageURLOK(body.HTMLURL) {
		rel.URL = body.HTMLURL
	}
	return rel, Newer(ver, current), nil
}

// versionOK: непустой номер до 64 знаков из букв, цифр и . + -. Он попадает в интерфейс и в
// журнал, поэтому всё остальное отвергается.
func versionOK(v string) bool {
	if v == "" || len(v) > maxVersion {
		return false
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '.', r == '+', r == '-':
		default:
			return false
		}
	}
	return true
}

// pageURLOK: адрес страницы релиза это https://github.com/... без имени пользователя и порта,
// без пробелов, управляющих знаков и обратной косой черты. Иное игнорируется.
func pageURLOK(raw string) bool {
	if !strings.HasPrefix(raw, pageHost) {
		return false
	}
	for _, r := range raw {
		if r <= ' ' || r == 0x7f || r == '\\' {
			return false
		}
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host == "github.com" && u.User == nil && u.Opaque == ""
}

// Watch проверяет версию через delay после вызова, затем каждые every, пока жив ctx. Новый
// релиз отдаётся в onNew, ошибка проверки в onErr (без подробностей). Пустой repo: возврат
// сразу, ни одного запроса. Блокирует вызывающего, запускать в своей горутине.
func Watch(ctx context.Context, c *http.Client, repo, current string, delay, every time.Duration, onNew func(Release), onErr func()) {
	if repo == "" {
		return
	}
	wait := delay
	for {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		rel, ok, err := Check(ctx, c, repo, current)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			onErr()
		case ok:
			onNew(rel)
		}
		wait = every
	}
}

// Newer сообщает, что версия a новее b. Сравниваются числа через точку, ведущая v
// отбрасывается. Суффикс после дефиса (-rc1) делает версию старше такой же без суффикса.
// Версия не из чисел (в том числе "dev") никогда не новее и не считается старее: ответ false.
// Две версии с суффиксами не сравниваются: false.
func Newer(a, b string) bool {
	an, apre, ok := parse(a)
	if !ok {
		return false
	}
	bn, bpre, ok := parse(b)
	if !ok {
		return false
	}
	for i := 0; i < max(len(an), len(bn)); i++ {
		var x, y uint64
		if i < len(an) {
			x = an[i]
		}
		if i < len(bn) {
			y = bn[i]
		}
		if x != y {
			return x > y
		}
	}
	return !apre && bpre
}

// parse разбирает "1.2.3", "v1.2.3-rc1" и "1.2.3+сборка". pre говорит о суффиксе после дефиса.
func parse(v string) (nums []uint64, pre, ok bool) {
	v = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(v), "v"), "V")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v, pre = v[:i], true
	}
	if v == "" {
		return nil, false, false
	}
	for _, p := range strings.Split(v, ".") {
		for _, r := range p {
			if r < '0' || r > '9' {
				return nil, false, false
			}
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return nil, false, false
		}
		nums = append(nums, n)
	}
	return nums, pre, true
}
