// Package vpnsetup serves the self-service portal's per-protocol "how to
// connect" instructions (app name/link + per-OS steps) from a plain
// directory of JSON files instead of baking them into the frontend build --
// the whole point being that app names, download links, and setup steps
// drift over time (new OS versions, renamed apps, changed install flows),
// and an admin should be able to fix a stale instruction by editing a file
// on the host, not by rebuilding and redeploying the panel.
//
// Each file is named <lang>.json (e.g. ru.json, en.json) and holds an
// object keyed by provider type (wireguard/amneziawg/openvpn/ikev2), each
// with `app`, `appUrl`, `appNote`, and one string-array per OS key (windows/
// macos/linux_nm/linux_cli/ios/android) -- see defaults/ru.json for the
// exact shape (also the seed content copied out on first boot).
package vpnsetup

import (
	"embed"
	"os"
	"path/filepath"
)

//go:embed defaults/*.json
var defaultsFS embed.FS

// EnsureSeeded copies every embedded default language file into dir, but
// only if that file doesn't already exist there -- never overwrites an
// admin's edits. Safe to call on every startup. Non-fatal by design: a
// failure here (e.g. read-only volume) degrades to "always serve the
// built-in defaults" via Load's own fallback, not a crash.
func EnsureSeeded(dir string) error {
	entries, err := defaultsFS.ReadDir("defaults")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, e := range entries {
		dst := filepath.Join(dir, e.Name())
		if _, err := os.Stat(dst); err == nil {
			continue // admin's file (or a previous seed) already there
		}
		b, err := defaultsFS.ReadFile("defaults/" + e.Name())
		if err != nil {
			return err
		}
		// 0666 (not 0644): the panel container runs as root, so a file it
		// creates on a bind-mounted host directory is root-owned there --
		// world-writable is what actually lets a non-root host user edit it
		// without sudo, which is the entire point of this directory
		// existing. Not a meaningful security concern: this is non-secret
		// help text, not credentials.
		if err := os.WriteFile(dst, b, 0o666); err != nil {
			return err
		}
	}
	return nil
}

// Load returns the raw JSON bytes for lang, preferring dir/<lang>.json (so
// admin edits always win) and falling back to the embedded default for that
// language, then to the embedded English default if the language itself is
// unrecognized -- Load never errors on a merely-missing/uncustomized file.
func Load(dir, lang string) ([]byte, error) {
	if b, err := os.ReadFile(filepath.Join(dir, lang+".json")); err == nil {
		return b, nil
	}
	if b, err := defaultsFS.ReadFile("defaults/" + lang + ".json"); err == nil {
		return b, nil
	}
	return defaultsFS.ReadFile("defaults/en.json")
}
