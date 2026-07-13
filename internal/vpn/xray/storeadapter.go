package xray

import (
	"context"

	"protean/internal/store"
)

// StoreAdapter adapts *store.Store to the flat xray.Store interface.
type StoreAdapter struct{ S *store.Store }

func (a StoreAdapter) SaveInstance(ctx context.Context, provider, strategy string, encParams, encRelay []byte) error {
	return a.S.SaveXrayInstance(ctx, store.XrayInstance{
		Provider: provider, Strategy: strategy, EncParams: encParams, EncRelay: encRelay,
	})
}

func (a StoreAdapter) GetInstance(ctx context.Context, provider string) (string, []byte, []byte, error) {
	x, err := a.S.GetXrayInstance(ctx, provider)
	if err != nil {
		return "", nil, nil, err
	}
	return x.Strategy, x.EncParams, x.EncRelay, nil
}

func (a StoreAdapter) SaveXrayClient(ctx context.Context, provider, name string, encCred []byte) error {
	return a.S.SaveXrayClient(ctx, provider, name, encCred)
}

func (a StoreAdapter) ListXrayClients(ctx context.Context, provider string) ([]ClientRow, error) {
	cs, err := a.S.ListXrayClients(ctx, provider)
	if err != nil {
		return nil, err
	}
	out := make([]ClientRow, len(cs))
	for i, c := range cs {
		out[i] = ClientRow{Name: c.Name, EncCred: c.EncCred}
	}
	return out, nil
}

func (a StoreAdapter) DeleteXrayClient(ctx context.Context, provider, name string) error {
	return a.S.DeleteXrayClient(ctx, provider, name)
}
