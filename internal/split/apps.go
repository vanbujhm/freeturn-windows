package split

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

const (
	// MaxApps - предел программ только через туннель.
	MaxApps = 50
	// MaxAppPath - предел длины пути к программе в рунах.
	MaxAppPath = 1024
)

var (
	ErrAppPath     = errors.New("нужен полный путь к файлу .exe")
	ErrTooManyApps = errors.New("слишком много программ: не больше 50")
)

// CleanApps проверяет и нормализует список программ: путь абсолютный, без «..», с
// расширением .exe, повторы без учёта регистра убираются, остаётся первая запись со своим
// комментарием и выключателем. Существование файла не проверяется: программу могут
// поставить позже.
func CleanApps(in []model.AppRule) ([]model.AppRule, error) {
	out := make([]model.AppRule, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, a := range in {
		p, err := cleanAppPath(a.Path)
		if err != nil {
			return nil, err
		}
		key := strings.ToLower(p)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, model.AppRule{Path: p, Comment: CleanComment(a.Comment), Off: a.Off})
	}
	if len(out) > MaxApps {
		return nil, ErrTooManyApps
	}
	return out, nil
}

// cleanAppPath проверяет один путь. «..» ищется до filepath.Clean: Clean его бы убрал, и
// путь указал бы на другой файл, чем написал человек.
func cleanAppPath(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	bad := func() (string, error) { return "", fmt.Errorf("%w: %s", ErrAppPath, p) }
	if p == "" || len([]rune(p)) > MaxAppPath || strings.ContainsFunc(p, unicode.IsControl) {
		return bad()
	}
	isSep := func(r rune) bool { return r == '/' || r == '\\' }
	for _, part := range strings.FieldsFunc(p, isSep) {
		if part == ".." {
			return bad()
		}
	}
	if !filepath.IsAbs(p) || !strings.EqualFold(filepath.Ext(p), ".exe") {
		return bad()
	}
	return filepath.Clean(p), nil
}
