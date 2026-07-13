package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"protean/internal/vpn"
)

func TestRenderMetricsFormat(t *testing.T) {
	samples := []metricSample{
		{name: "protean_up", value: 1},
		{name: "protean_interface_up", labels: map[string]string{"provider": "wireguard"}, value: 1},
		{name: "protean_peers_total", labels: map[string]string{"provider": "wireguard"}, value: 3},
		{name: "protean_peer_online", labels: map[string]string{"provider": "wireguard", "peer": `weird"name`}, value: 1},
	}
	out := renderMetrics(samples)

	for _, want := range []string{
		"# TYPE protean_up gauge",
		"protean_up 1",
		`protean_interface_up{provider="wireguard"} 1`,
		`protean_peers_total{provider="wireguard"} 3`,
		`protean_peer_online{peer="weird\"name",provider="wireguard"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q\n---\n%s", want, out)
		}
	}
}

func TestGatherMetricsFromProviders(t *testing.T) {
	reg := vpn.NewRegistry()
	reg.Register(&meshFakeProvider{name: "wireguard", address: "10.10.0.1/24"})
	s := &Server{reg: reg}

	samples := s.gatherMetrics(context.Background(), time.Unix(1000, 0))
	// meshFakeProvider reports Up with no peers; expect interface_up=1.
	found := false
	for _, sm := range samples {
		if sm.name == "protean_interface_up" && sm.labels["provider"] == "wireguard" && sm.value == 1 {
			found = true
		}
	}
	if !found {
		t.Error("expected protean_interface_up=1 for wireguard")
	}

	// HTTP and Go runtime metrics are always present (host is nil here, so
	// SSH metrics are correctly omitted).
	names := map[string]bool{}
	for _, sm := range samples {
		names[sm.name] = true
	}
	for _, want := range []string{"protean_http_requests_total", "protean_go_goroutines", "protean_go_heap_bytes"} {
		if !names[want] {
			t.Errorf("missing metric %q", want)
		}
	}
	if names["protean_host_up"] {
		t.Error("protean_host_up should be absent when no host probe is wired")
	}
}

func TestMetricsEndpointAuth(t *testing.T) {
	reg := vpn.NewRegistry()
	s := &Server{reg: reg, metricsToken: "sekret"}
	ts := httptest.NewServer(s.Routes())
	defer ts.Close()

	// No token -> 401.
	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: got %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Correct token -> 200.
	req, _ := http.NewRequest("GET", ts.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer sekret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("with token: got %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestMetricsEndpointDisabledWithoutToken(t *testing.T) {
	s := &Server{reg: vpn.NewRegistry()} // no metricsToken
	ts := httptest.NewServer(s.Routes())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("disabled endpoint: got %d, want 404", resp.StatusCode)
	}
}
