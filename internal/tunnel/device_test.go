package tunnel

import (
	"errors"
	"testing"
	"time"
)

// Рядом с тестовым exe нет wintun.dll, поэтому это тот же случай, что и удалённая антивирусом
// библиотека: понятная ошибка, а не сбой где-то в глубине.
func TestRemoveStaleWithoutDLL(t *testing.T) {
	if CheckDLL() == nil {
		t.Skip("wintun.dll есть в System32")
	}
	if err := RemoveStale(); !errors.Is(err, ErrNoWintun) {
		t.Fatalf("ошибка %v", err)
	}
}

func TestParseStats(t *testing.T) {
	raw := "private_key=00\npublic_key=aa\nlast_handshake_time_sec=1700000000\n" +
		"last_handshake_time_nsec=5\ntx_bytes=100\nrx_bytes=250\n" +
		"public_key=bb\nlast_handshake_time_sec=1700000100\ntx_bytes=1\nrx_bytes=2\nbroken\nrx_bytes=x\n"
	st := parseStats(raw)
	if st.TxBytes != 101 || st.RxBytes != 252 {
		t.Errorf("TxBytes=%d RxBytes=%d, want 101 и 252", st.TxBytes, st.RxBytes)
	}
	if want := time.Unix(1700000100, 0); !st.LastHandshake.Equal(want) {
		t.Errorf("LastHandshake = %v, want %v", st.LastHandshake, want)
	}
}

func TestParseStatsNoHandshake(t *testing.T) {
	st := parseStats("tx_bytes=0\nlast_handshake_time_sec=0\n")
	if !st.LastHandshake.IsZero() {
		t.Errorf("LastHandshake = %v, want нулевое время", st.LastHandshake)
	}
}
