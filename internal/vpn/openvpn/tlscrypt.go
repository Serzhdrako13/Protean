package openvpn

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// GenTLSCrypt generates an OpenVPN tls-crypt/tls-auth static key (2048-bit,
// the "OpenVPN Static key V1" PEM-ish block) in Go, so no host openvpn binary
// is needed to bootstrap a server.
func GenTLSCrypt() (string, error) {
	buf := make([]byte, 256) // 2048 bits
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	h := hex.EncodeToString(buf) // 512 hex chars
	var body strings.Builder
	for i := 0; i < len(h); i += 32 {
		body.WriteString(h[i : i+32])
		body.WriteString("\n")
	}
	return "-----BEGIN OpenVPN Static key V1-----\n" +
		body.String() +
		"-----END OpenVPN Static key V1-----\n", nil
}
