package corehost

import (
	"net"
	"testing"

	"github.com/vanbujhm/freeturn-windows/internal/model"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		msg  string
		want model.ErrorCode
	}{
		{"provider fatal: no streams: INVALID_JOIN_LINK", model.ErrInvalidCallLink},
		{"provider fatal: no streams: CALL_FULL", model.ErrCallFull},
		{"provider fatal: no streams: ANON_BLOCKED", model.ErrAnonBlocked},
		{"provider fatal: no streams: FATAL_CAPTCHA_FAILED_NO_STREAMS", model.ErrCaptchaFailed},
		{"что-то другое", model.ErrCore},
		{"", model.ErrCore},
	}
	for _, c := range cases {
		if got := Classify(c.msg); got != c.want {
			t.Errorf("Classify(%q) = %q, want %q", c.msg, got, c.want)
		}
	}
}

func TestFreePortIsLoopback(t *testing.T) {
	ap, err := FreePort()
	if err != nil {
		t.Fatalf("FreePort: %v", err)
	}
	if !ap.Addr().IsLoopback() || ap.Addr().String() != "127.0.0.1" {
		t.Errorf("адрес %v, want 127.0.0.1", ap.Addr())
	}
	if ap.Port() == 0 || ap.Port() == 9000 {
		t.Errorf("порт %d недопустим", ap.Port())
	}
	// Порт должен быть свободен после возврата.
	c, err := net.ListenPacket("udp", ap.String())
	if err != nil {
		t.Fatalf("порт занят: %v", err)
	}
	c.Close()
}
