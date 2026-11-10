package split

import (
	"strings"
	"unicode"
)

// MaxComment - предел длины комментария правила в рунах.
const MaxComment = 80

// CleanComment убирает управляющие символы и пробелы по краям и режет комментарий до
// MaxComment рун.
func CleanComment(s string) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s))
	if r := []rune(s); len(r) > MaxComment {
		s = strings.TrimSpace(string(r[:MaxComment]))
	}
	return s
}
