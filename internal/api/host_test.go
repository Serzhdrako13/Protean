package api

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"protean/internal/sshexec"
	"protean/internal/vpn"
)

type fakeHost struct {
	pingErr error
	pings   atomic.Int32
}

func (f *fakeHost) Ping(context.Context) error { f.pings.Add(1); return f.pingErr }
func (f *fakeHost) Stats() sshexec.Stats       { return sshexec.Stats{Commands: 3, Errors: 1} }

func hostsOf(m map[string]HostProbe) func() map[string]HostProbe {
	return func() map[string]HostProbe { return m }
}

func TestHostHealthyCaches(t *testing.T) {
	h := &fakeHost{}
	s := &Server{}
	s.SetHostsFunc(hostsOf(map[string]HostProbe{"default": h}))

	for i := 0; i < 5; i++ {
		if ok, _ := s.hostHealthy(context.Background()); !ok {
			t.Fatal("expected healthy")
		}
	}
	if got := h.pings.Load(); got != 1 {
		t.Fatalf("expected 1 cached ping, got %d", got)
	}
}

func TestHostHealthyReportsError(t *testing.T) {
	h := &fakeHost{pingErr: errors.New("dial refused")}
	s := &Server{}
	s.SetHostsFunc(hostsOf(map[string]HostProbe{"hq": h}))
	ok, msg := s.hostHealthy(context.Background())
	if ok || msg != "hq: dial refused" {
		t.Fatalf("expected unhealthy with server-scoped message, got ok=%v msg=%q", ok, msg)
	}
}

func TestHostMetricsPresentWhenWired(t *testing.T) {
	s := &Server{reg: vpn.NewRegistry()}
	s.SetHostsFunc(hostsOf(map[string]HostProbe{"default": &fakeHost{}}))
	names := map[string]bool{}
	for _, sm := range s.gatherMetrics(context.Background(), time.Unix(1000, 0)) {
		names[sm.name] = true
	}
	for _, want := range []string{"protean_host_up", "protean_ssh_commands_total", "protean_ssh_command_errors_total"} {
		if !names[want] {
			t.Errorf("missing host metric %q", want)
		}
	}
}
