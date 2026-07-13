package openvpn

import (
	"context"

	"protean/internal/store"
)

// StoreAdapter adapts *store.Store to the flat openvpn.Store interface, so the
// provider stays decoupled from the concrete store type (and testable with a
// fake).
type StoreAdapter struct{ S *store.Store }

func (a StoreAdapter) GetCAMaterial(ctx context.Context, provider string) (string, []byte, string, error) {
	m, err := a.S.GetCAMaterial(ctx, provider)
	if err != nil {
		return "", nil, "", err
	}
	return m.CertPEM, m.EncKeyPEM, m.Source, nil
}

func (a StoreAdapter) SaveCAMaterial(ctx context.Context, provider, certPEM string, encKeyPEM []byte, source string) error {
	return a.S.SaveCAMaterial(ctx, store.CAMaterial{Provider: provider, CertPEM: certPEM, EncKeyPEM: encKeyPEM, Source: source})
}

func (a StoreAdapter) SaveOpenVPNClient(ctx context.Context, provider, cn, certPEM string, encKeyPEM []byte, address, subnets string) error {
	return a.S.SaveOpenVPNClient(ctx, store.OpenVPNClient{Provider: provider, CN: cn, CertPEM: certPEM, EncKeyPEM: encKeyPEM, Address: address, Subnets: subnets})
}

func (a StoreAdapter) GetOpenVPNClient(ctx context.Context, provider, cn string) (string, []byte, string, string, error) {
	c, err := a.S.GetOpenVPNClient(ctx, provider, cn)
	if err != nil {
		return "", nil, "", "", err
	}
	return c.CertPEM, c.EncKeyPEM, c.Address, c.Subnets, nil
}

func (a StoreAdapter) ListOpenVPNClients(ctx context.Context, provider string) ([]string, []string, []string, error) {
	cs, err := a.S.ListOpenVPNClients(ctx, provider)
	if err != nil {
		return nil, nil, nil, err
	}
	cns := make([]string, len(cs))
	addrs := make([]string, len(cs))
	subs := make([]string, len(cs))
	for i, c := range cs {
		cns[i], addrs[i], subs[i] = c.CN, c.Address, c.Subnets
	}
	return cns, addrs, subs, nil
}

func (a StoreAdapter) DeleteOpenVPNClient(ctx context.Context, provider, cn string) error {
	return a.S.DeleteOpenVPNClient(ctx, provider, cn)
}

func (a StoreAdapter) AddRevokedCert(ctx context.Context, provider, serial, cn string) error {
	return a.S.AddRevokedCert(ctx, provider, serial, cn)
}

func (a StoreAdapter) ListRevokedCerts(ctx context.Context, provider string) ([]RevokedCert, error) {
	rows, err := a.S.ListRevokedCerts(ctx, provider)
	if err != nil {
		return nil, err
	}
	out := make([]RevokedCert, len(rows))
	for i, r := range rows {
		out[i] = RevokedCert{Serial: r.Serial, RevokedAt: r.RevokedAt}
	}
	return out, nil
}

func (a StoreAdapter) NextCRLNumber(ctx context.Context, provider string) (int64, error) {
	return a.S.NextCRLNumber(ctx, provider)
}
