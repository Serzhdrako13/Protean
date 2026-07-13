package ikev2

import (
	"context"

	"protean/internal/store"
)

// StoreAdapter adapts *store.Store to the flat ikev2.Store interface.
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

func (a StoreAdapter) SaveClient(ctx context.Context, provider, cn, certPEM string, encKeyPEM []byte, p12pass, address, subnets string) error {
	return a.S.SaveIKEv2Client(ctx, store.IKEv2Client{
		Provider: provider, CN: cn, CertPEM: certPEM, EncKeyPEM: encKeyPEM, P12Password: p12pass, Address: address, Subnets: subnets,
	})
}

func (a StoreAdapter) GetClient(ctx context.Context, provider, cn string) (string, []byte, string, string, string, error) {
	c, err := a.S.GetIKEv2Client(ctx, provider, cn)
	if err != nil {
		return "", nil, "", "", "", err
	}
	return c.CertPEM, c.EncKeyPEM, c.P12Password, c.Address, c.Subnets, nil
}

func (a StoreAdapter) ListClients(ctx context.Context, provider string) ([]string, []string, []string, []string, error) {
	cs, err := a.S.ListIKEv2Clients(ctx, provider)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cns := make([]string, len(cs))
	addrs := make([]string, len(cs))
	subs := make([]string, len(cs))
	pass := make([]string, len(cs))
	for i, c := range cs {
		cns[i], addrs[i], subs[i], pass[i] = c.CN, c.Address, c.Subnets, c.P12Password
	}
	return cns, addrs, subs, pass, nil
}

func (a StoreAdapter) DeleteClient(ctx context.Context, provider, cn string) error {
	return a.S.DeleteIKEv2Client(ctx, provider, cn)
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

func (a StoreAdapter) SaveServerRoutes(ctx context.Context, provider string, pushRoutes []string, egress bool) error {
	return a.S.SaveCertServerRoutes(ctx, provider, pushRoutes, egress)
}

func (a StoreAdapter) GetServerRoutes(ctx context.Context, provider string) ([]string, bool, bool, error) {
	return a.S.GetCertServerRoutes(ctx, provider)
}
