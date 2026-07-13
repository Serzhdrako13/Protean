package wgfamily

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// DumpInterface is the first line of `wg show <iface> dump`.
type DumpInterface struct {
	PrivateKey string
	PublicKey  string
	ListenPort int
	FwMark     string
}

// DumpPeer is one peer line of `wg show <iface> dump`.
type DumpPeer struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          []string
	LatestHandshake     time.Time
	RxBytes             uint64
	TxBytes             uint64
	PersistentKeepalive int
}

// ParseDump parses the tab-separated output of `wg show <iface> dump` (also
// understood by `awg show <iface> dump`).
func ParseDump(output string) (DumpInterface, []DumpPeer, error) {
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return DumpInterface{}, nil, fmt.Errorf("empty dump output")
	}

	head := strings.Split(lines[0], "\t")
	if len(head) < 4 {
		return DumpInterface{}, nil, fmt.Errorf("malformed interface line: %q", lines[0])
	}
	port, err := strconv.Atoi(head[2])
	if err != nil {
		return DumpInterface{}, nil, fmt.Errorf("parse listen port: %w", err)
	}
	iface := DumpInterface{
		PrivateKey: noneEmpty(head[0]),
		PublicKey:  noneEmpty(head[1]),
		ListenPort: port,
		FwMark:     head[3],
	}

	var peers []DumpPeer
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 8 {
			return iface, nil, fmt.Errorf("malformed peer line: %q", line)
		}
		hsEpoch, err := strconv.ParseInt(f[4], 10, 64)
		if err != nil {
			return iface, nil, fmt.Errorf("parse latest handshake: %w", err)
		}
		rx, err := strconv.ParseUint(f[5], 10, 64)
		if err != nil {
			return iface, nil, fmt.Errorf("parse rx bytes: %w", err)
		}
		tx, err := strconv.ParseUint(f[6], 10, 64)
		if err != nil {
			return iface, nil, fmt.Errorf("parse tx bytes: %w", err)
		}
		keepalive := 0
		if f[7] != "off" {
			keepalive, err = strconv.Atoi(f[7])
			if err != nil {
				return iface, nil, fmt.Errorf("parse persistent keepalive: %w", err)
			}
		}

		var handshake time.Time
		if hsEpoch > 0 {
			handshake = time.Unix(hsEpoch, 0)
		}

		var allowedIPs []string
		if aip := noneEmpty(f[3]); aip != "" {
			allowedIPs = strings.Split(aip, ",")
		}

		peers = append(peers, DumpPeer{
			PublicKey:           f[0],
			PresharedKey:        noneEmpty(f[1]),
			Endpoint:            noneEmpty(f[2]),
			AllowedIPs:          allowedIPs,
			LatestHandshake:     handshake,
			RxBytes:             rx,
			TxBytes:             tx,
			PersistentKeepalive: keepalive,
		})
	}

	return iface, peers, nil
}

func noneEmpty(s string) string {
	if s == "(none)" {
		return ""
	}
	return s
}
