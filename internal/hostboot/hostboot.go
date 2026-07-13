// Package hostboot carries the root-owned on-host installer script embedded in
// the panel binary, so a server can be bootstrapped straight from the UI (via
// the one-time SSH password) without copying files by hand.
//
// installer.sh is a copy of scripts/protean-installer.sh (source of truth);
// keep the two in sync. setup-host.sh installs the same script for the manual
// hardened path.
package hostboot

import _ "embed"

//go:embed installer.sh
var installerScript []byte

// InstallerScript returns the on-host installer contents.
func InstallerScript() []byte { return installerScript }

// InstallerPath is where the script is placed on the host (matches
// vpn.InstallerPath and the sudoers rule).
const InstallerPath = "/usr/local/lib/protean/protean-installer.sh"
