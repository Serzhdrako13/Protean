// Package openvpn implements the vpn.Provider interface for OpenVPN. Unlike
// wg-family it is certificate-based (see internal/vpn/pki), tracks connected
// clients via the daemon's status file, and ships each client a single
// inlined .ovpn bundle.
package openvpn

import (
	"strconv"
	"strings"
	"time"
)

// ConnectedClient is one entry from the OpenVPN status file's CLIENT_LIST.
type ConnectedClient struct {
	CommonName     string
	RealAddress    string // ip:port the client connects from
	VirtualAddress string // assigned tunnel IP
	BytesReceived  uint64
	BytesSent      uint64
	ConnectedSince time.Time
}

// ParseStatus parses an OpenVPN status file (status-version 2 or 3). v2 is
// comma-separated, v3 tab-separated; both use the same CLIENT_LIST layout:
//
//	CLIENT_LIST,<cn>,<real>,<virt>,<virt6>,<rx>,<tx>,<since-str>,<since-unix>,...
func ParseStatus(content string) []ConnectedClient {
	var clients []ConnectedClient
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "CLIENT_LIST") {
			continue
		}
		sep := ","
		if strings.Contains(line, "\t") {
			sep = "\t"
		}
		f := strings.Split(line, sep)
		if len(f) < 8 {
			continue
		}
		c := ConnectedClient{
			CommonName:     f[1],
			RealAddress:    f[2],
			VirtualAddress: f[3],
		}
		c.BytesReceived, _ = strconv.ParseUint(strings.TrimSpace(f[5]), 10, 64)
		c.BytesSent, _ = strconv.ParseUint(strings.TrimSpace(f[6]), 10, 64)
		// Prefer the unix timestamp field (f[8]) when present; fall back to
		// parsing the human string.
		if len(f) >= 9 {
			if ts, err := strconv.ParseInt(strings.TrimSpace(f[8]), 10, 64); err == nil && ts > 0 {
				c.ConnectedSince = time.Unix(ts, 0)
			}
		}
		clients = append(clients, c)
	}
	return clients
}
