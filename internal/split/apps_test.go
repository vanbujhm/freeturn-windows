package split

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

func paths(in []model.AppRule) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		out = append(out, a.Path)
	}
	return out
}

func TestCleanAppsPaths(t *testing.T) {
	cases := []struct{ in, want string }{
		{`C:\Program Files\App\app.exe`, `C:\Program Files\App\app.exe`},
		{"  c:/Program Files/App/./APP.EXE ", `c:\Program Files\App\APP.EXE`},
		{`\\server\share\app.exe`, `\\server\share\app.exe`},
	}
	for _, c := range cases {
		got, err := CleanApps([]model.AppRule{{Path: c.in}})
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if len(got) != 1 || got[0].Path != c.want {
			t.Errorf("%q -> %v, ожидалось %q", c.in, paths(got), c.want)
		}
	}
}

func TestCleanAppsDuplicateKeepsFirst(t *testing.T) {
	got, err := CleanApps([]model.AppRule{
		{Path: `C:\Apps\App.exe`, Comment: "первая", Off: true},
		{Path: "c:/apps/./APP.EXE ", Comment: "вторая"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := model.AppRule{Path: `C:\Apps\App.exe`, Comment: "первая", Off: true}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("получено %+v", got)
	}
}

func TestCleanAppsComment(t *testing.T) {
	got, err := CleanApps([]model.AppRule{
		{Path: `C:\a.exe`, Comment: "  дом\n "},
		{Path: `C:\b.exe`, Comment: strings.Repeat("я", 100)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Comment != "дом" {
		t.Errorf("комментарий %q", got[0].Comment)
	}
	if n := len([]rune(got[1].Comment)); n != 80 {
		t.Errorf("длина комментария %d рун", n)
	}
}

func TestCleanAppsRejectsBadPath(t *testing.T) {
	bad := []string{
		"app.exe", `.\app.exe`, `\app.exe`, `C:app.exe`, `C:\App\..\app.exe`,
		`C:\App\app.dll`, `C:\App\app`, "", "   ", "C:\\App\\a\x00b.exe",
		`C:\` + strings.Repeat("я", MaxAppPath-6) + ".exe",
	}
	for _, p := range bad {
		if _, err := CleanApps([]model.AppRule{{Path: p}}); !errors.Is(err, ErrAppPath) {
			t.Errorf("%.40q: ошибка %v, ожидалась ErrAppPath", p, err)
		}
	}
	// Путь ровно в MaxAppPath рун проходит.
	ok := `C:\` + strings.Repeat("я", MaxAppPath-7) + ".exe"
	if n := len([]rune(ok)); n != MaxAppPath {
		t.Fatalf("длина пути в тесте %d", n)
	}
	if _, err := CleanApps([]model.AppRule{{Path: ok}}); err != nil {
		t.Errorf("путь в %d рун отклонён: %v", MaxAppPath, err)
	}
}

func many(n int) []model.AppRule {
	out := make([]model.AppRule, 0, n)
	for i := range n {
		out = append(out, model.AppRule{Path: fmt.Sprintf(`C:\Apps\app%d.exe`, i)})
	}
	return out
}

func TestCleanAppsLimit(t *testing.T) {
	if got, err := CleanApps(many(MaxApps)); err != nil || len(got) != MaxApps {
		t.Errorf("%d программ: %d, %v", MaxApps, len(got), err)
	}
	if _, err := CleanApps(many(MaxApps + 1)); !errors.Is(err, ErrTooManyApps) {
		t.Errorf("%d программ: ошибка %v", MaxApps+1, err)
	}
	withDup := append(many(MaxApps), model.AppRule{Path: `c:\apps\APP0.exe`})
	if got, err := CleanApps(withDup); err != nil || len(got) != MaxApps {
		t.Errorf("повтор сверх предела: %d, %v", len(got), err)
	}
}

func TestCleanAppsNil(t *testing.T) {
	got, err := CleanApps(nil)
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("CleanApps(nil) = %#v, %v", got, err)
	}
}
