package engine

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/vanbujhm/freeturn-windows/internal/model"
	"github.com/vanbujhm/freeturn-windows/internal/split"
)

var (
	ip1 = netip.MustParseAddr("1.1.1.1")
	ip2 = netip.MustParseAddr("2.2.2.2")
	ip3 = netip.MustParseAddr("3.3.3.3")
	ip4 = netip.MustParseAddr("4.4.4.4")
)

// connected поднимает сессию до фазы connected.
func connected(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	h.connect(testRequest())
	h.waitPhase(model.PhaseConnected)
	return h
}

func TestProbeNotConnected(t *testing.T) {
	h := newHarness(t)
	if _, err := h.e.Probe(context.Background(), "1.1.1.1"); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("без сессии err = %v", err)
	}
	h.core.silent = true
	h.connect(testRequest())
	h.waitCall("core.start")
	if _, err := h.e.Probe(context.Background(), "1.1.1.1"); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("во время подключения err = %v", err)
	}
}

func TestProbeIP(t *testing.T) {
	h := connected(t)
	h.net.setRoutes(map[netip.Addr]uint64{ip1: testLUID}, nil)
	got, err := h.e.Probe(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if want := []model.ProbeHop{{Addr: ip1, Via: model.ViaTunnel}}; !slices.Equal(got, want) {
		t.Fatalf("Probe = %+v", got)
	}
}

func TestProbeDomain(t *testing.T) {
	h := connected(t)
	h.res.answer("example.com", ip2, ip3)
	h.net.setRoutes(map[netip.Addr]uint64{ip2: 7, ip3: 99}, nil)
	got, err := h.e.Probe(context.Background(), "Example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []model.ProbeHop{{Addr: ip2, Via: model.ViaDirect}, {Addr: ip3, Via: model.ViaOther}}
	if !slices.Equal(got, want) {
		t.Fatalf("Probe = %+v", got)
	}
}

func TestProbeRouteError(t *testing.T) {
	h := connected(t)
	h.net.setRoutes(nil, map[netip.Addr]error{ip4: errors.New("x")})
	got, err := h.e.Probe(context.Background(), "4.4.4.4")
	if err != nil {
		t.Fatal(err)
	}
	if want := []model.ProbeHop{{Addr: ip4}}; !slices.Equal(got, want) {
		t.Fatalf("Probe = %+v", got)
	}
}

func TestProbeUnresolved(t *testing.T) {
	h := connected(t)
	got, err := h.e.Probe(context.Background(), "nowhere.example")
	if err != nil || len(got) != 0 {
		t.Fatalf("Probe = %+v, %v", got, err)
	}
}

func TestProbeBadInput(t *testing.T) {
	h := connected(t)
	if _, err := h.e.Probe(context.Background(), "10.0.0.0/8"); !errors.Is(err, split.ErrSubnetInput) {
		t.Fatalf("подсеть: err = %v", err)
	}
	if _, err := h.e.Probe(context.Background(), "*.a"); !errors.Is(err, split.ErrWildcard) {
		t.Fatalf("маска: err = %v", err)
	}
}

func TestProbeLocalAndOutside(t *testing.T) {
	h := newHarness(t)
	req := testRequest()
	req.Profile.WGConfig = strings.Replace(req.Profile.WGConfig, "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 10.0.0.0/8", 1)
	h.connect(req)
	h.waitPhase(model.PhaseConnected)
	lan, outside, inside := netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.1.1.1")
	h.net.setRoutes(map[netip.Addr]uint64{lan: 7, outside: 7, inside: testLUID}, nil)
	h.net.setOnLink(map[netip.Addr]bool{lan: true})
	for _, c := range []struct {
		addr            netip.Addr
		local, isOutside bool
	}{{lan, true, true}, {outside, false, true}, {inside, false, false}} {
		got, err := h.e.Probe(context.Background(), c.addr.String())
		if err != nil || len(got) != 1 {
			t.Fatalf("Probe(%s) = %+v, %v", c.addr, got, err)
		}
		if got[0].Local != c.local || got[0].Outside != c.isOutside {
			t.Errorf("Probe(%s) = %+v", c.addr, got[0])
		}
	}
}

func TestProbeOutsideIgnoredInTunnelOnly(t *testing.T) {
	h := newHarness(t)
	req := testRequest()
	req.Options.SplitMode = model.SplitOnly
	req.Profile.WGConfig = strings.Replace(req.Profile.WGConfig, "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 10.0.0.0/8", 1)
	h.connect(req)
	h.waitPhase(model.PhaseConnected)
	h.net.setRoutes(map[netip.Addr]uint64{ip1: 7}, nil)
	got, err := h.e.Probe(context.Background(), "1.1.1.1")
	if err != nil || len(got) != 1 || got[0].Outside {
		t.Fatalf("Probe = %+v, %v", got, err)
	}
}
