// Package relay implements the Relay OpenBao secrets engine.
package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/reonokiy/openbao-plugin-secrets-relay/provider"
)

const (
	Version    = "v0.1.0-dev"
	maxTTL     = 15 * time.Minute
	callBudget = 30 * time.Second
	safetySkew = 5 * time.Second
	secretType = "relay_credential"
)

var (
	errStorage  = errors.New("Relay storage operation failed; details withheld")
	errProvider = errors.New("Relay provider operation failed; details withheld")
	errRecord   = errors.New("Relay issuance record is invalid")
	validName   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	validID     = regexp.MustCompile(`^[a-f0-9]{32}$`)
)

type backend struct {
	*framework.Backend
	// Serialize mutations within one mount; there is no cross-mount state.
	mu       sync.Mutex
	adapters map[string]provider.Adapter
	now      func() time.Time
}

// Factory is the production entry point. No vendor adapters ship yet.
func Factory(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
	return FactoryWithAdapters(nil)(ctx, config)
}

// FactoryWithAdapters composes a fixed registry at process startup. It cannot
// load arbitrary code, endpoints, or adapters from operator configuration.
func FactoryWithAdapters(adapters map[string]provider.Adapter) logical.Factory {
	return func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
		b := &backend{adapters: make(map[string]provider.Adapter), now: time.Now}
		for name, adapter := range adapters {
			if !validName.MatchString(name) || adapter == nil {
				return nil, errors.New("invalid Relay adapter registry")
			}
			b.adapters[name] = adapter
		}
		b.Backend = &framework.Backend{
			Help:           "Relay brokers independent, short-lived vendor credentials.",
			BackendType:    logical.TypeLogical,
			RunningVersion: Version,
			PathsSpecial: &logical.Paths{
				SealWrapStorage: []string{"config", "issuances/"},
			},
		}
		b.Paths = b.paths()
		b.Secrets = []*framework.Secret{{Type: secretType, Revoke: b.revoke}}
		b.PeriodicFunc = b.cleanup
		if err := b.Setup(ctx, config); err != nil {
			return nil, err
		}
		return b, nil
	}
}

type mountConfig struct {
	Provider string          `json:"provider"`
	Revision uint64          `json:"revision"`
	Options  json.RawMessage `json:"options"`
}

type role struct {
	TTL     time.Duration   `json:"ttl"`
	MaxTTL  time.Duration   `json:"max_ttl"`
	Options json.RawMessage `json:"options"`
}

type issuance struct {
	Version    int             `json:"version"`
	ID         string          `json:"id"`
	EntityID   string          `json:"entity_id"`
	Role       string          `json:"role"`
	Config     mountConfig     `json:"config"`
	ExpiresAt  time.Time       `json:"expires_at"`
	Revocation json.RawMessage `json:"revocation,omitempty"`
}

func store(ctx context.Context, storage logical.Storage, key string, value any) error {
	entry, err := logical.StorageEntryJSON(key, value)
	if err != nil {
		return errStorage
	}
	entry.SealWrap = true
	if storage.Put(ctx, entry) != nil {
		return errStorage
	}
	return nil
}

func load(ctx context.Context, storage logical.Storage, key string, value any) (bool, error) {
	entry, err := storage.Get(ctx, key)
	if err != nil {
		return false, errStorage
	}
	if entry == nil {
		return false, nil
	}
	if entry.DecodeJSON(value) != nil {
		return false, errStorage
	}
	return true, nil
}

func remove(ctx context.Context, storage logical.Storage, key string) error {
	if storage.Delete(ctx, key) != nil {
		return errStorage
	}
	return nil
}

func object(raw any) (json.RawMessage, error) {
	if raw == nil {
		return json.RawMessage(`{}`), nil
	}
	value, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("options must be a JSON object")
	}
	data, err := json.Marshal(value)
	if err != nil || len(data) > 65536 {
		return nil, errors.New("options exceed the supported size or encoding")
	}
	return data, nil
}

func rejectUnknown(data *framework.FieldData) *logical.Response {
	for key := range data.Raw {
		if _, ok := data.Schema[key]; !ok {
			return logical.ErrorResponse("unknown request field")
		}
	}
	return nil
}

func (b *backend) providerNames() []string {
	names := make([]string, 0, len(b.adapters))
	for name := range b.adapters {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func newID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", errors.New("Relay request ID generation failed")
	}
	return hex.EncodeToString(id[:]), nil
}
