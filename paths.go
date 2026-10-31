package relay

import (
	"context"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) paths() []*framework.Path {
	name := &framework.FieldSchema{Type: framework.TypeString, Description: "Role name."}
	options := &framework.FieldSchema{Type: framework.TypeMap, Description: "Adapter-validated JSON object."}
	return []*framework.Path{
		{
			Pattern:      "providers/?",
			HelpSynopsis: "List compiled-in adapters.",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: func(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
					return logical.ListResponse(b.providerNames()), nil
				},
			},
		},
		{
			Pattern:      "config",
			HelpSynopsis: "Configure one immutable provider; reads return metadata only.",
			Fields: map[string]*framework.FieldSchema{
				"provider": {Type: framework.TypeString, Required: true, Description: "Compiled-in adapter name."},
				"options":  options,
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.readConfig, logical.UpdateOperation: b.writeConfig,
			},
		},
		{
			Pattern:      "roles/?",
			HelpSynopsis: "List issuance roles.",
			Callbacks:    map[logical.Operation]framework.OperationFunc{logical.ListOperation: b.listRoles},
		},
		{
			Pattern:      "roles/" + framework.GenericNameRegex("name"),
			HelpSynopsis: "Manage an issuance role; writes replace all fields.",
			Fields: map[string]*framework.FieldSchema{
				"name":    name,
				"ttl":     {Type: framework.TypeDurationSecond, Default: 900, Description: "Default duration, at most 15m."},
				"max_ttl": {Type: framework.TypeDurationSecond, Default: 900, Description: "Maximum duration, at most 15m."},
				"options": options,
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.readRole, logical.UpdateOperation: b.writeRole, logical.DeleteOperation: b.deleteRole,
			},
		},
		{
			Pattern:      "issue/" + framework.GenericNameRegex("name"),
			HelpSynopsis: "Issue an independent credential for the authenticated entity.",
			Fields: map[string]*framework.FieldSchema{
				"name": name,
				"ttl":  {Type: framework.TypeDurationSecond, Description: "Requested duration within role limits."},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{logical.UpdateOperation: b.issue},
		},
	}
}

func (b *backend) readConfig(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var config mountConfig
	ok, err := load(ctx, req.Storage, "config", &config)
	if err != nil || !ok {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{
		"provider": config.Provider, "revision": config.Revision,
	}}, nil
}

func (b *backend) writeConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if resp := rejectUnknown(data); resp != nil {
		return resp, nil
	}
	name := data.Get("provider").(string)
	adapter, ok := b.adapters[name]
	if !ok {
		return logical.ErrorResponse("provider is not compiled into this plugin"), nil
	}
	caps := adapter.Capabilities()
	if !caps.IndependentCredentials || !caps.RecoveryByRequestID {
		return logical.ErrorResponse("provider does not support independent credentials and recovery"), nil
	}
	var old mountConfig
	found, err := load(ctx, req.Storage, "config", &old)
	if err != nil {
		return nil, err
	}
	if found && old.Provider != name {
		return logical.ErrorResponse("provider is immutable; use another mount"), nil
	}
	options, err := object(data.Get("options"))
	if err != nil {
		return logical.ErrorResponse("options must be a JSON object of at most 64 KiB"), nil
	}
	callCtx, cancel := context.WithTimeout(ctx, callBudget)
	defer cancel()
	if adapter.ValidateConfig(callCtx, options) != nil {
		return logical.ErrorResponse("provider configuration rejected; details withheld"), nil
	}
	config := mountConfig{Provider: name, Revision: old.Revision + 1, Options: options}
	return nil, store(ctx, req.Storage, "config", config)
}

func (b *backend) listRoles(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, errStorage
	}
	return logical.ListResponse(keys), nil
}

func (b *backend) writeRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if resp := rejectUnknown(data); resp != nil {
		return resp, nil
	}
	name := data.Get("name").(string)
	if !validName.MatchString(name) {
		return logical.ErrorResponse("invalid role name"), nil
	}
	var config mountConfig
	ok, err := load(ctx, req.Storage, "config", &config)
	if err != nil {
		return nil, err
	}
	if !ok {
		return logical.ErrorResponse("configure the mount first"), nil
	}
	ttlSeconds := data.Get("ttl").(int)
	maxSeconds := data.Get("max_ttl").(int)
	// Validate before converting to Duration to prevent integer overflow.
	if ttlSeconds <= 0 || maxSeconds <= 0 || ttlSeconds > maxSeconds || maxSeconds > int(maxTTL/time.Second) {
		return logical.ErrorResponse("require 0 < ttl <= max_ttl <= 15m"), nil
	}
	options, err := object(data.Get("options"))
	if err != nil {
		return logical.ErrorResponse("options must be a JSON object of at most 64 KiB"), nil
	}
	adapter, ok := b.adapters[config.Provider]
	if !ok {
		return nil, errProvider
	}
	callCtx, cancel := context.WithTimeout(ctx, callBudget)
	defer cancel()
	if adapter.ValidateRole(callCtx, options) != nil {
		return logical.ErrorResponse("provider role rejected; details withheld"), nil
	}
	value := role{TTL: time.Duration(ttlSeconds) * time.Second, MaxTTL: time.Duration(maxSeconds) * time.Second, Options: options}
	return nil, store(ctx, req.Storage, "roles/"+name, value)
}

func (b *backend) readRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var value role
	ok, err := load(ctx, req.Storage, "roles/"+data.Get("name").(string), &value)
	if err != nil || !ok {
		return nil, err
	}
	// Vendor options can contain sensitive identifiers; do not reflect them.
	return &logical.Response{Data: map[string]any{
		"ttl": int64(value.TTL / time.Second), "max_ttl": int64(value.MaxTTL / time.Second),
	}}, nil
}

func (b *backend) deleteRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return nil, remove(ctx, req.Storage, "roles/"+data.Get("name").(string))
}
