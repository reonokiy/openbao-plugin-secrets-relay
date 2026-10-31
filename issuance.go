package relay

import (
	"context"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/reonokiy/openbao-plugin-secrets-relay/provider"
)

func (b *backend) issue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if resp := rejectUnknown(data); resp != nil {
		return resp, nil
	}
	if req.EntityID == "" {
		return logical.ErrorResponse("issuance requires an authenticated OpenBao entity"), nil
	}
	var config mountConfig
	ok, err := load(ctx, req.Storage, "config", &config)
	if err != nil {
		return nil, err
	}
	if !ok {
		return logical.ErrorResponse("mount is not configured"), nil
	}
	var value role
	name := data.Get("name").(string)
	ok, err = load(ctx, req.Storage, "roles/"+name, &value)
	if err != nil {
		return nil, err
	}
	if !ok {
		return logical.ErrorResponse("role does not exist"), nil
	}
	ttl := value.TTL
	if raw, specified := data.GetOk("ttl"); specified {
		seconds := raw.(int)
		if seconds <= 0 || seconds > int(value.MaxTTL/time.Second) {
			return logical.ErrorResponse("requested ttl is outside role limits"), nil
		}
		ttl = time.Duration(seconds) * time.Second
	} else if _, specified := data.Raw["ttl"]; specified {
		return logical.ErrorResponse("requested ttl must be positive"), nil
	}
	if limit := b.System().MaxLeaseTTL(); limit > 0 && ttl > limit {
		ttl = limit
	}
	if ttl <= 0 || ttl > maxTTL {
		return logical.ErrorResponse("invalid effective ttl"), nil
	}
	adapter, ok := b.adapters[config.Provider]
	if !ok {
		return nil, errProvider
	}
	caps := adapter.Capabilities()
	if !caps.IndependentCredentials || !caps.RecoveryByRequestID {
		return nil, errProvider
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	record := issuance{
		Version: 1, ID: id, EntityID: req.EntityID, Role: name,
		Config: config, ExpiresAt: b.now().Add(ttl),
	}
	key := "issuances/" + id
	// Persist the recovery ID BEFORE making any upstream side effect.
	if err := store(ctx, req.Storage, key, record); err != nil {
		return nil, err
	}
	callCtx, cancel := context.WithTimeout(ctx, callBudget)
	credential, issueErr := adapter.Issue(callCtx, config.Options, provider.IssueRequest{
		RequestID: id, EntityID: req.EntityID, TTL: ttl, Options: value.Options,
	})
	cancel()
	if issueErr != nil || credential == nil {
		b.compensate(ctx, req.Storage, record)
		return nil, errProvider
	}
	record.Revocation = credential.Revocation
	if caps.NativeExpiry {
		if credential.ExpiresAt.IsZero() {
			b.compensate(ctx, req.Storage, record)
			return nil, errProvider
		}
		if deadline := credential.ExpiresAt.Add(-safetySkew); deadline.Before(record.ExpiresAt) {
			record.ExpiresAt = deadline
		}
	}
	remaining := record.ExpiresAt.Sub(b.now()).Truncate(time.Second)
	if len(credential.Data) == 0 || remaining < time.Second {
		b.compensate(ctx, req.Storage, record)
		return nil, errProvider
	}
	if err := store(ctx, req.Storage, key, record); err != nil {
		b.compensate(ctx, req.Storage, record)
		return nil, err
	}
	resp := b.Secret(secretType).Response(credential.Data, map[string]any{"issuance_id": id})
	resp.Secret.TTL = remaining
	resp.Secret.MaxTTL = remaining
	resp.Secret.Renewable = false
	if !caps.NativeExpiry {
		resp.AddWarning("Expiry depends on successful upstream revocation; outages can delay invalidation.")
	}
	return resp, nil
}

func (b *backend) compensate(parent context.Context, storage logical.Storage, record issuance) {
	// Client cancellation must not prevent an immediate cleanup attempt.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), callBudget)
	defer cancel()
	// Keep the durable record if either remote revocation or deletion fails.
	_ = b.revokeRecord(ctx, storage, record)
}

func (b *backend) revokeRecord(ctx context.Context, storage logical.Storage, record issuance) error {
	if record.Version != 1 || !validID.MatchString(record.ID) || record.EntityID == "" {
		return errRecord
	}
	adapter, ok := b.adapters[record.Config.Provider]
	if !ok {
		return errProvider
	}
	callCtx, cancel := context.WithTimeout(ctx, callBudget)
	defer cancel()
	if adapter.Revoke(callCtx, record.Config.Options, provider.Revocation{
		RequestID: record.ID, EntityID: record.EntityID, Material: record.Revocation,
	}) != nil {
		return errProvider
	}
	return remove(ctx, storage, "issuances/"+record.ID)
}

func (b *backend) revoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if req.Secret == nil {
		return nil, errRecord
	}
	id, ok := req.Secret.InternalData["issuance_id"].(string)
	if !ok || !validID.MatchString(id) {
		return nil, errRecord
	}
	var record issuance
	found, err := load(ctx, req.Storage, "issuances/"+id, &record)
	if err != nil || !found {
		return nil, err
	}
	if record.ID != id {
		return nil, errRecord
	}
	return nil, b.revokeRecord(ctx, req.Storage, record)
}

func (b *backend) cleanup(ctx context.Context, req *logical.Request) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	keys, err := req.Storage.List(ctx, "issuances/")
	if err != nil {
		return errStorage
	}
	var firstErr error
	for _, id := range keys {
		var record issuance
		found, err := load(ctx, req.Storage, "issuances/"+id, &record)
		if err == nil && found {
			if record.ID != id || !validID.MatchString(id) {
				err = errRecord
			} else if !b.now().Before(record.ExpiresAt) {
				err = b.revokeRecord(ctx, req.Storage, record)
			}
		}
		if firstErr == nil && err != nil {
			firstErr = err
		}
	}
	return firstErr
}
