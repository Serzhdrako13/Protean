# Network topologies

The panel supports two ways to connect sites. They're not exclusive — choose
per provider. Mesh membership is a per-provider toggle (default **off**), so
you decide, for each VPN, whether it merges into one network or stays an
independent tunnel.

## A. Panel-managed cross-provider mesh (optional)

Turn `mesh` on (provider → Network page) for the VPNs you want merged. The hub
(this VPS) then:

- adds each mesh interface's tunnel CIDR to every mesh client's AllowedIPs /
  pushed routes, so clients of different VPNs (e.g. a WireGuard site and an
  AmneziaWG site) can reach each other;
- forwards between the interfaces (managed FORWARD rules, no NAT — addresses
  are preserved, true site-to-site);
- rejects overlapping subnets so routing stays unambiguous.

Use this when you want a single flat L3 network centrally managed here.

## B. Router-side merge / parallel tunnels (also fully supported)

Leave `mesh` **off** (the default). Each VPN is then an independent tunnel the
panel manages on its own (clients, keys/certs, status, egress, service). You
merge the site networks **on the site routers** instead — e.g. bring up 2–3
tunnels in parallel on each router and route between the site LANs there.

In this model the panel is a per-tunnel control plane; the L3 merge lives on
your routers. Nothing extra to configure in the panel — standalone is the
default behavior.

## Decision (recorded)

Both are first-class. The panel keeps mesh **optional and per-provider**, so
the operator can:

- mix: some VPNs in the panel mesh, others standalone for router-side merge;
- start standalone and adopt mesh later (or vice-versa) without rebuilding.

No further investment in cross-provider mesh is required for the router-side
approach — it works today via standalone mode. Revisit only if the router-side
plan is dropped in favor of centralizing the merge on the hub.

See also: internet egress (per provider) and the FORWARD/NAT rule model in
`ARCHITECTURE-openvpn-ikev2.md`.
