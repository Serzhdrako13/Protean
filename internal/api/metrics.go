package api

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"
)

// metricSample is one Prometheus time series line.
type metricSample struct {
	name   string
	labels map[string]string
	value  float64
}

// gatherMetrics collects panel/VPN state into Prometheus samples. Pure apart
// from the provider calls, so the formatting is unit-testable via renderMetrics.
func (s *Server) gatherMetrics(ctx context.Context, now time.Time) []metricSample {
	var out []metricSample
	out = append(out, metricSample{name: "protean_up", value: 1})

	for _, prov := range s.reg.List() {
		name := prov.Name()
		lbl := map[string]string{"provider": name}

		status, err := s.providerStatus(ctx, prov)
		up := 0.0
		if err == nil && status.Up {
			up = 1
		}
		out = append(out, metricSample{name: "protean_interface_up", labels: lbl, value: up})
		if up == 0 {
			continue
		}

		out = append(out,
			metricSample{name: "protean_listen_port", labels: lbl, value: float64(status.ListenPort)},
			metricSample{name: "protean_peers_total", labels: lbl, value: float64(status.PeerCount)},
			metricSample{name: "protean_peers_online", labels: lbl, value: float64(status.PeersOnline)},
			metricSample{name: "protean_rx_bytes_total", labels: lbl, value: float64(status.TotalRxBytes)},
			metricSample{name: "protean_tx_bytes_total", labels: lbl, value: float64(status.TotalTxBytes)},
		)

		peers, err := s.providerPeers(ctx, prov)
		if err != nil {
			continue
		}
		for _, p := range peers {
			id := p.Name
			if id == "" {
				id = p.PublicKey
			}
			pl := map[string]string{"provider": name, "peer": id}
			online := 0.0
			if p.Online {
				online = 1
			}
			hs := 0.0
			if !p.LastHandshake.IsZero() {
				hs = float64(now.Sub(p.LastHandshake).Seconds())
			}
			out = append(out,
				metricSample{name: "protean_peer_online", labels: pl, value: online},
				metricSample{name: "protean_peer_last_handshake_seconds", labels: pl, value: hs},
				metricSample{name: "protean_peer_rx_bytes", labels: pl, value: float64(p.RxBytes)},
				metricSample{name: "protean_peer_tx_bytes", labels: pl, value: float64(p.TxBytes)},
			)
		}
	}

	// Per-server SSH health + command stats.
	for id, h := range s.hostSet() {
		lbl := map[string]string{"server": id}
		up := 0.0
		if err := h.Ping(ctx); err == nil {
			up = 1
		}
		st := h.Stats()
		out = append(out,
			metricSample{name: "protean_host_up", labels: lbl, value: up},
			metricSample{name: "protean_ssh_commands_total", labels: lbl, value: float64(st.Commands)},
			metricSample{name: "protean_ssh_command_errors_total", labels: lbl, value: float64(st.Errors)},
			metricSample{name: "protean_ssh_last_command_seconds", labels: lbl, value: st.LastLatency.Seconds()},
		)
	}

	// HTTP request stats (from the metrics middleware).
	reqs, errs, lastLatency := s.httpStats()
	out = append(out,
		metricSample{name: "protean_http_requests_total", value: float64(reqs)},
		metricSample{name: "protean_http_request_errors_total", value: float64(errs)},
		metricSample{name: "protean_http_last_request_seconds", value: lastLatency.Seconds()},
	)

	// Go runtime.
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	out = append(out,
		metricSample{name: "protean_go_goroutines", value: float64(runtime.NumGoroutine())},
		metricSample{name: "protean_go_heap_bytes", value: float64(ms.HeapAlloc)},
	)
	return out
}

// metricHelp/metricType drive the # HELP/# TYPE header lines.
var metricMeta = []struct{ name, typ, help string }{
	{"protean_up", "gauge", "1 if the panel is running"},
	{"protean_interface_up", "gauge", "1 if the VPN interface is up"},
	{"protean_listen_port", "gauge", "UDP listen port of the interface"},
	{"protean_peers_total", "gauge", "Configured peers on the interface"},
	{"protean_peers_online", "gauge", "Peers with a recent handshake"},
	{"protean_rx_bytes_total", "counter", "Total bytes received on the interface"},
	{"protean_tx_bytes_total", "counter", "Total bytes sent on the interface"},
	{"protean_peer_online", "gauge", "1 if the peer has a recent handshake"},
	{"protean_peer_last_handshake_seconds", "gauge", "Seconds since the peer's last handshake (0 if never)"},
	{"protean_peer_rx_bytes", "counter", "Bytes received from the peer"},
	{"protean_peer_tx_bytes", "counter", "Bytes sent to the peer"},
	{"protean_host_up", "gauge", "1 if the managed host is reachable over SSH"},
	{"protean_ssh_commands_total", "counter", "SSH commands run against the host"},
	{"protean_ssh_command_errors_total", "counter", "SSH commands that returned an error"},
	{"protean_ssh_last_command_seconds", "gauge", "Duration of the most recent SSH command"},
	{"protean_http_requests_total", "counter", "HTTP requests served"},
	{"protean_http_request_errors_total", "counter", "HTTP responses with status >= 500"},
	{"protean_http_last_request_seconds", "gauge", "Duration of the most recent HTTP request"},
	{"protean_go_goroutines", "gauge", "Number of goroutines"},
	{"protean_go_heap_bytes", "gauge", "Heap bytes allocated and in use"},
}

// renderMetrics formats samples as Prometheus text exposition, grouped by
// metric name with HELP/TYPE headers.
func renderMetrics(samples []metricSample) string {
	byName := map[string][]metricSample{}
	for _, s := range samples {
		byName[s.name] = append(byName[s.name], s)
	}

	var b strings.Builder
	for _, m := range metricMeta {
		lines := byName[m.name]
		if len(lines) == 0 {
			continue
		}
		fmt.Fprintf(&b, "# HELP %s %s\n", m.name, m.help)
		fmt.Fprintf(&b, "# TYPE %s %s\n", m.name, m.typ)
		// Stable output order for readable diffs/tests.
		sort.Slice(lines, func(i, j int) bool {
			return lines[i].labels["provider"]+lines[i].labels["peer"] <
				lines[j].labels["provider"]+lines[j].labels["peer"]
		})
		for _, s := range lines {
			b.WriteString(m.name)
			b.WriteString(formatLabels(s.labels))
			fmt.Fprintf(&b, " %s\n", formatValue(s.value))
		}
	}
	return b.String()
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+`="`+escapeLabelValue(labels[k])+`"`)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func escapeLabelValue(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

func formatValue(f float64) string {
	// Integers render without a decimal point; keep it simple.
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%g", f)
}
