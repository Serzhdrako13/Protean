package api

import (
	"context"
	"strings"
	"time"
)

// knownProviderTypes are the installable backend TYPES (Install page + install
// validation + detect). Distinct from provider INSTANCES (from the registry),
// of which there can be several per type.
var knownProviderTypes = []struct{ Name, Label string }{
	{"wireguard", "WireGuard"},
	{"amneziawg", "AmneziaWG"},
	{"openvpn", "OpenVPN"},
	{"ikev2", "IKEv2"},
	{"xray", "Xray"},
}

func isKnownProviderType(t string) bool {
	for _, p := range knownProviderTypes {
		if p.Name == t {
			return true
		}
	}
	return false
}

func typeLabel(t string) string {
	for _, p := range knownProviderTypes {
		if p.Name == t {
			return p.Label
		}
	}
	return t
}

// instanceExists reports whether an instance id is registered.
func (s *Server) instanceExists(id string) bool {
	_, ok := s.reg.Get(id)
	return ok
}

// localName returns the instance part of a "server:instance" key (or the whole
// key if unscoped). serverPart returns the server part (empty if unscoped).
func localName(id string) string {
	if i := strings.IndexByte(id, ':'); i >= 0 {
		return id[i+1:]
	}
	return id
}
func serverPart(id string) string {
	if i := strings.IndexByte(id, ':'); i >= 0 {
		return id[:i]
	}
	return ""
}

// technicalLabel is the "<Type> <instance>" construction (e.g. "WireGuard
// wg0"), or the id alone if not found in the registry -- this is the
// identifier an admin actually needs for SSH/troubleshooting (systemctl unit
// names, config file paths etc. are all keyed by the technical instance
// name, never the friendly one). No "@ server" suffix -- every page that
// shows this is already scoped to (or clearly labels) one specific server,
// so it'd just be redundant noise.
func (s *Server) technicalLabel(id string) string {
	prov, ok := s.reg.Get(id)
	if !ok {
		return id
	}
	local := localName(id)
	label := typeLabel(prov.Type())
	if local != prov.Type() {
		label += " " + local
	}
	return label
}

// providerLabel returns the FRIENDLY-ONLY label for an instance id -- for
// the self-service portal, where hiding "wg0"/"awg1" from a non-technical
// end user is the entire point. If labels has a non-empty admin-set
// friendly name for this id (see store.ListAllServerInstanceLabels, keyed
// the same way as registry ids), that's returned as-is; labels may be nil
// (e.g. s.store unavailable in tests), in which case this falls back to
// technicalLabel. Do NOT use this for admin-facing views -- see
// adminProviderLabel.
func (s *Server) providerLabel(id string, labels map[string]string) string {
	if l := labels[id]; l != "" {
		return l
	}
	return s.technicalLabel(id)
}

// adminProviderLabel is providerLabel's admin-facing twin: an admin always
// needs the technical instance identifier visible (for SSH/troubleshooting,
// matching systemd unit names, config paths, the "Провайдеры" table row
// they're about to click into) regardless of whatever friendly name a
// portal user sees, so a friendly name is shown ALONGSIDE it, never instead
// of it -- "Германия (WireGuard wg0 @ hq)", not just "Германия".
func (s *Server) adminProviderLabel(id string, labels map[string]string) string {
	tech := s.technicalLabel(id)
	if l := labels[id]; l != "" {
		return l + " (" + tech + ")"
	}
	return tech
}

// instanceLabels fetches every admin-set friendly instance label in one
// query, for passing into providerLabel -- call once per request/loop, not
// once per instance. Returns nil (not an error) if s.store is unavailable,
// so providerLabel's fallback kicks in uniformly.
func (s *Server) instanceLabels(ctx context.Context) map[string]string {
	if s.store == nil {
		return nil
	}
	labels, err := s.store.ListAllServerInstanceLabels(ctx)
	if err != nil {
		return nil
	}
	return labels
}

// instancePortalVisibility fetches the set of instances an admin has opted
// into the self-service portal, in one query -- call once per request, not
// once per instance. Returns nil (not an error) if s.store is unavailable.
func (s *Server) instancePortalVisibility(ctx context.Context) map[string]bool {
	if s.store == nil {
		return nil
	}
	visible, err := s.store.ListAllServerInstancePortalVisibility(ctx)
	if err != nil {
		return nil
	}
	return visible
}

// instanceDescriptions fetches every admin-set instance note in one query --
// call once per request, not once per instance. Returns nil (not an error)
// if s.store is unavailable.
func (s *Server) instanceDescriptions(ctx context.Context) map[string]string {
	if s.store == nil {
		return nil
	}
	descriptions, err := s.store.ListAllServerInstanceDescriptions(ctx)
	if err != nil {
		return nil
	}
	return descriptions
}

// instanceConfigChangedAt fetches every instance's config_changed_at in one
// query, for apiPortalMe's per-instance staleness check. Returns nil (not
// an error) if s.store is unavailable -- a nil/missing map entry compares
// as a zero time, which never reports stale.
func (s *Server) instanceConfigChangedAt(ctx context.Context) map[string]time.Time {
	if s.store == nil {
		return nil
	}
	changed, err := s.store.ListAllServerInstanceConfigChangedAt(ctx)
	if err != nil {
		return nil
	}
	return changed
}

// meshCapableTypes are provider types that expose a tunnel CIDR and can join
// the cross-provider mesh.
var meshCapableTypes = map[string]bool{
	"wireguard": true, "amneziawg": true, "openvpn": true, "ikev2": true,
}

// meshCapableInstances returns mesh-capable instance ids on one server (mesh is
// per-server for now; cross-host mesh is a separate future feature). An empty
// serverID returns matches across all servers (used for global overlap checks,
// since site subnets are shared mesh-wide).
func (s *Server) meshCapableInstances(serverID string) []string {
	var ids []string
	for _, p := range s.reg.List() {
		if !meshCapableTypes[p.Type()] {
			continue
		}
		if serverID != "" && serverPart(p.Name()) != serverID {
			continue
		}
		ids = append(ids, p.Name())
	}
	return ids
}
