// Package e2elab is a real systemd-container integration lab: it
// bootstraps and provisions OpenVPN/IKEv2/Xray on an actual systemd host
// exactly the way the panel would a real VPS, over real SSH, and asserts
// real outcomes (a revoked cert is actually rejected by a real CRL, a
// service is actually restarted). See README.md for how to run it --
// gated behind the "e2elab" build tag and PROTEAN_E2ELAB=1, not part of
// the normal fast test suite (needs Docker with --privileged container
// support). This file carries no build tag so the package always has at
// least one buildable file: `go build ./...`/`go vet ./...`/a plain
// `go test ./...` must never notice this directory exists.
package e2elab
