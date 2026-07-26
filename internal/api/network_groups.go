package api

import "context"

// ensureProviderGroup returns providerName's current group id, creating a
// new auto-named "Сеть {N}" group and assigning it if the instance has
// none yet. Idempotent -- an instance that already has a group (e.g. from
// an earlier detection apply run) silently keeps it; the same instance is
// always the same reachability boundary, so there's never a reason to
// prompt for this.
func (s *Server) ensureProviderGroup(ctx context.Context, providerName string) (int64, error) {
	ps, err := s.store.GetProviderSettings(ctx, providerName)
	if err != nil {
		return 0, err
	}
	if ps.GroupID != nil {
		return *ps.GroupID, nil
	}
	grp, err := s.store.CreateNextAutoNamedGroup(ctx)
	if err != nil {
		return 0, err
	}
	if _, err := s.store.SetProviderGroup(ctx, providerName, &grp.ID); err != nil {
		return 0, err
	}
	s.audit(ctx, "network_group.create", grp.Name+" (auto, "+providerName+")")
	return grp.ID, nil
}

// reconcileMeshGroups applies group bookkeeping when two instances become
// mesh-linked:
//   - neither has a group: create ONE new auto-named group, assign to both.
//   - exactly one has a group: the other silently adopts it -- they're now
//     the same reachability boundary.
//   - both already have DIFFERENT groups: left untouched. Auto-merging two
//     independently-named groups without confirmation would be exactly the
//     kind of surprising bulk rename this feature must never do silently;
//     the admin can manually repoint one side's group if they want real
//     unification (apiMeshGet's Warnings flags this case instead).
func (s *Server) reconcileMeshGroups(ctx context.Context, a, b string) error {
	psA, err := s.store.GetProviderSettings(ctx, a)
	if err != nil {
		return err
	}
	psB, err := s.store.GetProviderSettings(ctx, b)
	if err != nil {
		return err
	}
	switch {
	case psA.GroupID == nil && psB.GroupID == nil:
		grp, err := s.store.CreateNextAutoNamedGroup(ctx)
		if err != nil {
			return err
		}
		if _, err := s.store.SetProviderGroup(ctx, a, &grp.ID); err != nil {
			return err
		}
		if _, err := s.store.SetProviderGroup(ctx, b, &grp.ID); err != nil {
			return err
		}
		s.audit(ctx, "network_group.create", grp.Name+" (auto, mesh link "+a+"+"+b+")")
	case psA.GroupID == nil:
		_, err := s.store.SetProviderGroup(ctx, a, psB.GroupID)
		return err
	case psB.GroupID == nil:
		_, err := s.store.SetProviderGroup(ctx, b, psA.GroupID)
		return err
	}
	return nil // both already grouped differently -- case (c), untouched by design
}
