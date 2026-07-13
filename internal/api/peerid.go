package api

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Peer IDs are a provider's Peer.PublicKey (see vpn.Peer), which is a real
// WireGuard public key for wg-family providers but just the plain client
// name (CN) for cert-based ones (OpenVPN/IKEv2) -- not remotely base64
// shaped. Both need to survive a round trip through a URL path segment.
//
// Two schemes, tagged by an explicit "b."/"s." prefix (never ambiguous with
// each other or with the old untagged format below: the URL-safe base64
// alphabet contains no ".", so its presence/position always identifies
// which case applies):
//   - "b." (binary): the WG-pubkey case -- publicKey is itself standard
//     base64 (contains '+'/'/'/'='), decoded to raw bytes and re-encoded
//     URL-safe, matching the ORIGINAL (pre-fix) scheme's output exactly so
//     old links keep resolving.
//   - "s." (string): anything else (cert-based CNs, or any future
//     provider whose identifier isn't a WG pubkey) -- the raw UTF-8 bytes
//     of publicKey are URL-safe base64 encoded directly, no assumption
//     that the input is itself base64. This is what a plain name like
//     "sidorov" needed all along: the old code tried to base64-DECODE it
//     first (since publicKey was assumed to always be a WG pubkey), which
//     fails whenever the name's length isn't a multiple of 4 -- a
//     genuinely broken case, not a "server not configured" edge case.
//
// decodePeerID also accepts old links with NO prefix at all (issued before
// this fix existed) via the same "b."-equivalent logic, so no DB migration
// of already-granted peer_owner.peer_key rows is needed.
func encodePeerID(publicKey string) (string, error) {
	if raw, err := base64.StdEncoding.DecodeString(publicKey); err == nil {
		return "b." + base64.RawURLEncoding.EncodeToString(raw), nil
	}
	return "s." + base64.RawURLEncoding.EncodeToString([]byte(publicKey)), nil
}

func decodePeerID(urlID string) (string, error) {
	scheme, rest, tagged := strings.Cut(urlID, ".")
	if !tagged {
		// No "." at all -- an old link issued before schemes existed;
		// rest wasn't split out, so use the whole string and fall through
		// to the "b" (binary/WG-pubkey) decode path, matching the
		// original behavior exactly.
		rest = urlID
		scheme = "b"
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return "", fmt.Errorf("decode peer id: %w", err)
	}
	switch scheme {
	case "b":
		return base64.StdEncoding.EncodeToString(raw), nil
	case "s":
		return string(raw), nil
	default:
		return "", fmt.Errorf("decode peer id: unknown scheme %q", scheme)
	}
}
