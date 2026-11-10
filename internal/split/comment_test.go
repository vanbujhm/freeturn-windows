package split

import (
	"strings"
	"testing"
)

func TestCleanComment(t *testing.T) {
	long := strings.Repeat("я", 90)
	cases := map[string]string{
		"  работа  ":   "работа",
		"a\tb\nc\x00d": "abcd",
		" \n\t ":       "",
		long:           strings.Repeat("я", 80),
	}
	for in, want := range cases {
		if got := CleanComment(in); got != want {
			t.Errorf("CleanComment(%q) = %q, want %q", in, got, want)
		}
	}
}
