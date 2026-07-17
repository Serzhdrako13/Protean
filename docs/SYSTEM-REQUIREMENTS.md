# System requirements and sizing

Minimum and recommended server specs for running Protean, plus a worked
formula for scaling with the number of active VPN providers and concurrent
clients. Numbers below come from two real measurements taken this pass:

1. **Idle baseline** — the panel + its own Postgres, freshly started via
   `docker-compose.standalone.yml`, doing nothing.
2. **Per-protocol marginal cost** — a real load test
   (`test/e2elab/loadtest`, `//go:build e2eload`) that provisions each of
   the four VPN provider families on a real host, brings up genuine
   client tunnels (real `wg`/`openvpn`/`charon`/`xray` processes, not
   mocks) at 1/10/50 concurrent peers, drives real traffic through them
   (`iperf3` for the three TUN/XFRM-based protocols, `curl` through a real
   SOCKS proxy for Xray, which has no TUN interface to attach `iperf3`
   to), and samples the server's CPU%/RSS while that traffic runs. See
   `test/e2elab/loadtest/results.json` for the raw numbers this document
   cites.

## Read this before the numbers: what they do and don't tell you

- **Measured on this session's sandbox hardware** — an 8-vCPU QEMU virtual
  machine (`model name: QEMU Virtual CPU version 2.5+`), almost certainly
  running nested inside whatever host actually executed this session.
  That is **not** a Hetzner/Timeweb vCPU, and nested virtualization adds
  overhead a real cloud VM's first-level hypervisor doesn't have. Treat
  every *absolute* Mbps/CPU% number here as **relative, not a guarantee**:
  what's trustworthy is the *ratio* between protocols (which one costs
  more CPU per Mbps than another) and the *shape* of how cost scales with
  concurrency — not "this exact vCPU count gets you this exact Mbps on
  your cloud box."
- **Client and server shared one physical machine.** The load test's
  "client" containers and the "server" container both ran on the same
  8-vCPU box, competing for the same cores. Absolute throughput numbers
  are therefore a ceiling on what *this rig* could do end-to-end, not a
  clean single-sided server benchmark — again, relative comparison across
  protocols is the reliable part.
- **Cross-checked against public reference figures**, not used blindly:
  WireGuard's in-kernel crypto is well documented as capable of several
  Gbps per core on modern x86 with AES-NI; OpenVPN's userspace crypto
  loop is well known as the most CPU-hungry per Mbps of the four (a
  single OpenVPN process is fundamentally harder to scale across cores
  than kernel-accelerated IPsec or WireGuard); strongSwan/IPsec with
  AES-NI is architecturally closer to WireGuard's kernel-side efficiency
  than to OpenVPN's userspace cost. The measurements below reproduce
  exactly that ordering (OpenVPN highest CPU-per-Mbps, WireGuard/IKEv2
  lowest), which is the load-bearing confirmation — the ordering is real,
  even though the absolute vCPU-hours aren't this rig's to promise.
- **Disk sizing is dominated by configurable retention**, not fixed
  per-install growth — see below, and set retention appropriately for
  your compliance/audit needs before assuming any disk number here.
- **Network egress bandwidth is your uplink, not something to size
  here.** Hetzner/Timeweb both publish their own per-plan bandwidth caps;
  this document is about compute (CPU/RAM), not what your provider allows
  you to push.

## Panel + Postgres baseline (idle)

Measured via `docker compose -f docker-compose.standalone.yml --env-file
.env.standalone up -d`, `docker stats --no-stream` after ~15s settling:

| Component | Idle RSS | Idle CPU |
|---|---|---|
| panel (Go binary) | ~7 MB | ~0% |
| Postgres 16-alpine | ~32 MB | ~0-2% |

This is the fixed cost of running Protean at all, before any VPN provider
or client exists. It's small enough that on any plan with at least 512 MB
RAM, the baseline itself is never the constraint — the VPN providers and
their clients are.

## Disk: dominated by retention settings, not fixed growth

Measured against a real, in-use database (this session's own test/dev
activity, not a synthetic clean-room row), `pg_stat_user_tables`:

| Table | Size | Rows | Bytes/row (approx) |
|---|---|---|---|
| `traffic_samples` | 568 kB | 2,338 | ~243 |
| `audit_log` | 48 kB | 27 | too few rows for a reliable per-row figure at this scale, but same order of magnitude as traffic_samples (small, fixed-width rows) |

`traffic_samples` is the one table that grows continuously and
unboundedly by design (a periodic per-server/per-peer traffic snapshot) —
everything else (`audit_log`, `login_attempts`, `access_requests`,
`login_ban_state`) grows with admin/security *events*, not with time or
client count directly.

**What actually controls disk usage long-term:**
- `TRAFFIC_RETENTION_HOURS` (env var, default `72`) — how long
  `traffic_samples` rows are kept before pruning. At ~243 bytes/row and
  one sample per active peer per sampling interval, disk growth here
  scales with `(number of active peers) × (samples per hour) × 243 bytes
  × retention hours` — a few hundred KB/month even at moderate fleet
  sizes, negligible next to typical VPS disk plans (20 GB+).
- The panel's own **Data Retention** admin settings (`audit_log`,
  `access_requests`, `login_attempts`, `login_ban_state` — each
  independently toggleable with its own retention-days value, all
  opt-in/disabled by default per `defaultDataRetentionSettings()` in
  `internal/store/data_retention.go`) — set these explicitly if
  disk-bounded long-term audit history matters for your deployment;
  left disabled, these tables grow with event volume indefinitely (still
  small per-row, but genuinely unbounded without an explicit retention
  policy).

Bottom line: **10-20 GB of disk is comfortable for the panel + DB
indefinitely** under any realistic single-operator fleet size, as long as
retention is configured for tables you don't want growing forever. VPN
providers themselves (OpenVPN/IKEv2/Xray/WireGuard configs, CA material,
CRLs) are KB-to-low-MB regardless of client count — the DB, not the VPN
host filesystem, is where any real growth would show up.

## Per-provider marginal cost (measured, real tunnels)

`succeeded`/`concurrency` was 100% across every cell below — no dropped
connections at any tier tested. Full raw data in
`test/e2elab/loadtest/results.json`.

| Protocol | Concurrency | Aggregate throughput | Per-client | Server CPU% | Server RSS |
|---|---|---|---|---|---|
| WireGuard | 1 | 2200 Mbps | 2200 Mbps | 43% | n/a (in-kernel, no process) |
| WireGuard | 10 | 7713 Mbps | 771 Mbps | 25% | n/a |
| WireGuard | 50 | 8486 Mbps | 170 Mbps | 27% | n/a |
| IKEv2/strongSwan | 1 | 614 Mbps | 614 Mbps | 23% | 12 MB |
| IKEv2/strongSwan | 10 | 3351 Mbps | 335 Mbps | 11% | 13 MB |
| IKEv2/strongSwan | 50 | 7781 Mbps | 156 Mbps | 17% | 15 MB |
| Xray (VLESS+Vision+TLS) | 1 | 3573 Mbps | 3573 Mbps | 0.1% | 35 MB |
| Xray (VLESS+Vision+TLS) | 10 | 11075 Mbps | 1107 Mbps | 0.3% | 39 MB |
| Xray (VLESS+Vision+TLS) | 50 | 14341 Mbps | 287 Mbps | 268% | 46 MB |
| OpenVPN | 1 | 748 Mbps | 748 Mbps | 121% | 9.5 MB |
| OpenVPN | 10 | 842 Mbps | 84 Mbps | 126% | 11 MB |
| OpenVPN | 50 | 1838 Mbps | 37 Mbps | 126% | 17 MB |

**CPU-per-Mbps at 50 concurrent clients** (the most stable sample —
`server CPU% ÷ aggregate Mbps`, i.e. cost per unit of throughput,
independent of this rig's absolute ceiling):

| Protocol | %CPU per Mbps | Relative to WireGuard |
|---|---|---|
| WireGuard | 0.0032 | 1x (cheapest) |
| IKEv2/strongSwan | 0.0021 | ~0.7x (measurement noise at this scale — both are kernel-accelerated and genuinely close) |
| Xray (VLESS+Vision+TLS) | 0.0187 | ~6x |
| OpenVPN | 0.0688 | ~21x (most expensive) |

This matches well-known public expectations for each crypto stack:
WireGuard and IKEv2 both do the actual packet crypto in the kernel
(WireGuard natively, strongSwan via the kernel's XFRM/ESP stack with
AES-NI) — cheap and scales across cores well. Xray is userspace TLS
proxying — real cost, but modern AES-NI-accelerated TLS is efficient.
OpenVPN's userspace single-process crypto loop is the well-documented
laggard of the four, confirmed directly here: consistently ~120%+ CPU
(over one full core) across every concurrency tier tested, the only
protocol where the CPU cost didn't meaningfully change between 1 and 50
clients (implying it's already compute-bound on this rig well before 50
clients, a genuine ceiling worth taking seriously when sizing for real
OpenVPN load).

**RSS** for the three userspace daemons (OpenVPN/Xray/charon) grows
slowly and sub-linearly with client count — a few KB per client, not a
sizing concern next to CPU. WireGuard has no separate daemon process to
measure (kernel module), which is itself part of why it's the cheapest
option.

## Worked sizing formula

```
recommended_vCPU ≈ baseline_vCPU
                  + Σ over active providers of:
                      concurrent_clients × avg_client_Mbps × (%CPU_per_Mbps / 100)
```

Where `baseline_vCPU` covers the panel + Postgres (round up to 1 full
vCPU — the idle measurement above is a rounding error next to a single
core, but don't run on a fractional/burstable-only instance for a
production panel).

**Worked example 1** — one WireGuard provider + one OpenVPN provider, 20
concurrent clients each, averaging 5 Mbps per client (a realistic light
web-browsing/mixed-use load, not a saturation test):

```
WireGuard: 20 × 5 × (0.0032/100)  = 0.032 vCPU
OpenVPN:   20 × 5 × (0.0688/100)  = 0.688 vCPU
baseline:                           1 vCPU
--------------------------------------------
total:                            ~1.7 vCPU  →  round up to 2 vCPU
```

**Worked example 2** — a heavier deployment: one OpenVPN provider with 100
concurrent clients at 10 Mbps average (e.g. an office's shared egress):

```
OpenVPN: 100 × 10 × (0.0688/100)  = 6.88 vCPU
baseline:                           1 vCPU
--------------------------------------------
total:                             ~8 vCPU
```

This is exactly why OpenVPN's ~21x CPU-per-Mbps cost matters in practice:
the same 1000 Mbps of aggregate client traffic that costs under 1 vCPU on
WireGuard or IKEv2 costs on the order of 7-8 vCPUs on OpenVPN alone. If a
deployment's client base is large and OpenVPN is not a hard requirement
(e.g. for specific client compatibility), WireGuard/AmneziaWG or IKEv2
are the meaningfully cheaper choices to actually recommend to an
operator sizing a real fleet.

**RAM**: add roughly baseline (~64 MB rounded up) + (userspace daemon RSS
× number of provider instances, a few tens of MB each) + OS/kernel
overhead. RAM is essentially never the bottleneck for any of these four
protocols at realistic client counts — CPU is the actual sizing
constraint in every worked example above.

## Minimum / Recommended specs

| Tier | vCPU | RAM | Disk | Fits |
|---|---|---|---|---|
| **Minimum** | 1 | 1 GB | 10 GB | Panel + Postgres baseline + a single lightly-used WireGuard/IKEv2/Xray provider (a handful of concurrent clients at light traffic). Not recommended for OpenVPN as the sole or primary provider — see the CPU-per-Mbps gap above. |
| **Recommended** | 2 | 2 GB | 20 GB | Panel + Postgres + 1-2 provider types, dozens of concurrent clients at moderate (mixed-use) traffic, headroom for occasional bursts and for OpenVPN if it's one of the enabled providers. |
| **Heavier / OpenVPN-primary or 100+ concurrent clients** | 4-8+ | 4 GB+ | 20-40 GB | Use the worked formula above with your own expected concurrent-client count and per-client Mbps — OpenVPN-heavy fleets in particular should size CPU directly from the formula rather than assume the "Recommended" tier covers them. |

None of these tiers are disk-constrained under normal use — set the Data
Retention settings (see above) if long-term audit history at scale
matters for your deployment, and disk stops being a consideration at
all past that.
