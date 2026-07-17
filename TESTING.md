# Testing

**Shortest path from a fresh clone**: `make test` (unit tests, stubs the
frontend if needed), `make build` (real frontend + static binary), `make
dev` (self-contained standalone stack). See the Makefile for what each
target actually runs -- everything below also works directly if you want
more control.

## Unit + in-process integration (no external services)

```sh
go test -race ./...
```

Covers pure logic, parsers/builders, PKI, notify webhooks (httptest), the API
layer, and the **SSH client end-to-end** against an in-process SSH server
(`internal/sshexec` — real dial/handshake/exec, ctx cancellation, per-command
timeout, host-key pinning).

`internal/web/web.go` embeds the built frontend (`//go:embed dist`) at
**compile time** — on a fresh clone, before `cd frontend && npm run build`
has ever run, `internal/web/dist` doesn't exist and the whole thing fails to
compile (not just fail a test), since `internal/api` imports `internal/web`.
Go has no pre-test hooks, so this doesn't happen automatically — **run
this first** if you haven't built the real frontend yet:

```sh
./scripts/ensure-frontend-dist.sh   # no-op if a real build already exists
go test -race ./...
```

It drops in a trivial stub (plain HTML, empty asset/font dirs) just enough
to compile and pass the two SPA-shell smoke tests
(`internal/api/routes_smoke_test.go`) — never overwrites a real
`npm run build` output.

## WireGuard integration (real interface, root)

```sh
sudo PROTEAN_INTEGRATION=1 go test -tags integration ./internal/vpn/wgfamily/ -run Integration -v
```

Runs against a throwaway network namespace; needs `wg`/`ip` and root.

## Store integration (real Postgres, `dbtest` tag)

Bring up a throwaway Postgres (port 5433, ephemeral tmpfs — fresh each run):

```sh
docker compose -f docker-compose.test.yml up -d
PROTEAN_TEST_DB='postgres://protean:protean@localhost:5433/protean?sslmode=disable' \
  go test -tags dbtest ./internal/store/
docker compose -f docker-compose.test.yml down -v
```

The schema is dropped and re-migrated at the start of each run, so tests are
repeatable. Tests skip (not fail) when `PROTEAN_TEST_DB` is unset.

## Full integration/E2E lab (real systemd containers, `e2elab` tag)

```sh
docker build -t protean-e2elab:test test/e2elab
PROTEAN_E2ELAB=1 go test -tags e2elab ./test/e2elab/... -v -timeout 15m
```

The one suite that runs the real thing: a real systemd container boots
OpenVPN + strongSwan (IKEv2) + Xray, the panel's own
`sshexec.BootstrapHost`/`openvpn`/`ikev2`/`xray`/`vpn.Installer` code
provisions it over real SSH exactly like a real "Add server" would, and the
tests assert real outcomes — a revoked cert is actually rejected by a real
CRL (parsed with `pki.ParseCRL`), `ip_forward` actually flips, a stopped
host produces a clean error instead of a hang. See `test/e2elab/README.md`
for what's covered (and what deliberately isn't — WireGuard already has its
own real, non-mock test above).

Needs Docker with `--privileged` container support; takes a few minutes
(booting systemd + real daemons). Not part of the fast suite — gated behind
both the `e2elab` build tag and `PROTEAN_E2ELAB=1`; in CI it only runs as a
nightly scheduled job or manual `workflow_dispatch`, never on a normal
push/PR (`.github/workflows/ci.yml`'s `e2e-lab` job).

## Whole app smoke (container build + boot)

```sh
cp .env.standalone.example .env.standalone && edit the 4 required values
docker compose -f docker-compose.standalone.yml --env-file .env.standalone up --build -d   # panel + its own Postgres
curl -fsSk https://localhost:8080/healthz   # "ok" (or "ok (host degraded: …)" without a reachable SSH host)
docker compose -f docker-compose.standalone.yml down -v
```
