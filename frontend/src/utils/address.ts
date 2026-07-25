// Splits a peer's AllowedIPs into its own tunnel address (the narrowest
// host route, mask stripped for display) and its routed site subnets
// (kept as-is, mask included). This is the same distinction the backend's
// vpn.ClassifyPeerRoutes makes authoritatively for structural decisions
// (Node/Subnet creation) -- this frontend version is display-only and
// simpler (mask-width based, no tunnel-network awareness), since the raw
// AllowedIPs list here has no tunnel CIDR to classify against. Joining a
// peer's own address together with its site subnets into one string was a
// real, previously-fixed bug: an admin can't tell which part is the
// client's actual identity versus a network it merely routes traffic for.
export interface SplitAddress {
  ownAddress: string | null; // mask stripped, e.g. "10.10.0.5"
  subnets: string[]; // mask kept, e.g. ["192.168.50.0/24"]
}

export function stripHostMask(cidr: string): string {
  return cidr.replace(/\/(32|128)$/, '');
}

export function splitAllowedIPs(allowedIPs: string[] | null | undefined): SplitAddress {
  const subnets: string[] = [];
  let ownAddress: string | null = null;
  for (const raw of allowedIPs ?? []) {
    const entry = raw.trim();
    if (!entry || entry === '0.0.0.0/0' || entry === '::/0') continue;
    const isHost = /\/(32|128)$/.test(entry);
    if (isHost && ownAddress === null) {
      ownAddress = stripHostMask(entry);
    } else {
      subnets.push(entry);
    }
  }
  return { ownAddress, subnets };
}
