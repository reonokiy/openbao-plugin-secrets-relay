package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/reonokiy/openbao-plugin-secrets-relay/provider"
)

type fakeAdapter struct {
	mu         sync.Mutex
	caps       provider.Capabilities
	issued     map[string]provider.IssueRequest
	revoked    map[string]provider.Revocation
	configs    map[string]json.RawMessage
	issueErr   error
	revokeErr  error
	expiry     time.Time
	lastConfig json.RawMessage
}

func newFake() *fakeAdapter {
	return &fakeAdapter{
		caps:   provider.Capabilities{IndependentCredentials: true, RecoveryByRequestID: true},
		issued: make(map[string]provider.IssueRequest), revoked: make(map[string]provider.Revocation),
		configs: make(map[string]json.RawMessage),
	}
}

func (f *fakeAdapter) Capabilities() provider.Capabilities { return f.caps }
func (f *fakeAdapter) ValidateConfig(_ context.Context, raw json.RawMessage) error {
	return requireEmptyObjectOrField(raw, "account")
}
func (f *fakeAdapter) ValidateRole(_ context.Context, raw json.RawMessage) error {
	return requireEmptyObjectOrField(raw, "scope")
}
func requireEmptyObjectOrField(raw json.RawMessage, field string) error {
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		return errors.New("invalid JSON")
	}
	for key := range value {
		if key != field {
			return errors.New("unknown option")
		}
	}
	return nil
}
func (f *fakeAdapter) Issue(_ context.Context, config json.RawMessage, req provider.IssueRequest) (*provider.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued[req.RequestID] = req
	f.configs[req.RequestID] = append(json.RawMessage(nil), config...)
	if f.issueErr != nil {
		return nil, f.issueErr
	}
	// Generate disposable values in memory; assertions never print credentials.
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, err
	}
	material, _ := json.Marshal(map[string]string{"key": hex.EncodeToString(secret[:])})
	return &provider.Credential{
		Data:       map[string]any{"token": hex.EncodeToString(secret[:])},
		Revocation: material, ExpiresAt: f.expiry,
	}, nil
}
func (f *fakeAdapter) Revoke(_ context.Context, config json.RawMessage, req provider.Revocation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revokeErr != nil {
		return f.revokeErr
	}
	f.revoked[req.RequestID] = req
	f.lastConfig = append(json.RawMessage(nil), config...)
	return nil
}

func newTestBackend(t *testing.T, adapter *fakeAdapter, storage logical.Storage) *backend {
	t.Helper()
	config := logical.TestBackendConfig()
	if storage == nil {
		storage = &logical.InmemStorage{}
	}
	config.StorageView = storage
	value, err := FactoryWithAdapters(map[string]provider.Adapter{"alpha": adapter, "beta": newFake()})(context.Background(), config)
	if err != nil {
		t.Fatal("backend setup failed")
	}
	b := value.(*backend)
	t.Cleanup(func() { b.Cleanup(context.Background()) })
	return b
}

func call(t *testing.T, b *backend, storage logical.Storage, op logical.Operation, path string, data map[string]any) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: op, Path: path, Storage: storage, Data: data, EntityID: "entity-one",
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal("logical request failed; diagnostics suppressed")
	}
	return resp
}

func configured(t *testing.T) (*backend, *fakeAdapter, logical.Storage) {
	t.Helper()
	adapter := newFake()
	storage := &logical.InmemStorage{}
	b := newTestBackend(t, adapter, storage)
	call(t, b, storage, logical.UpdateOperation, "config", map[string]any{
		"provider": "alpha", "options": map[string]any{"account": "first"},
	})
	call(t, b, storage, logical.UpdateOperation, "roles/dev", map[string]any{"ttl": "10m", "max_ttl": "15m"})
	return b, adapter, storage
}

func requireRejected(t *testing.T, b *backend, storage logical.Storage, path string, data map[string]any) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: path, Storage: storage, Data: data, EntityID: "entity-one",
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("request unexpectedly accepted")
	}
}

func TestFactoryHasNoProductionProviders(t *testing.T) {
	conf := logical.TestBackendConfig()
	b, err := Factory(context.Background(), conf)
	if err != nil {
		t.Fatal("factory failed")
	}
	defer b.Cleanup(context.Background())
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation, Path: "providers", Storage: conf.StorageView,
	})
	if err != nil || resp == nil {
		t.Fatal("provider listing failed")
	}
	if keys, ok := resp.Data["keys"].([]string); ok && len(keys) != 0 {
		t.Fatal("production registry must be empty")
	}
}

func TestConfigAndRoleValidation(t *testing.T) {
	b, _, storage := configured(t)
	for _, test := range []struct {
		path string
		data map[string]any
	}{
		{"config", map[string]any{"provider": "beta"}},
		{"config", map[string]any{"provider": "missing"}},
		{"config", map[string]any{"provider": "alpha", "unknown": true}},
		{"config", map[string]any{"provider": "alpha", "options": map[string]any{"unknown": true}}},
		{"roles/dev", map[string]any{"ttl": "16m", "max_ttl": "16m"}},
		{"roles/dev", map[string]any{"ttl": "15m", "max_ttl": "10m"}},
		{"roles/dev", map[string]any{"ttl": "-1s"}},
		{"roles/dev", map[string]any{"options": map[string]any{"unknown": true}}},
		{"issue/dev", map[string]any{"ttl": 0}},
		{"issue/dev", map[string]any{"ttl": "16m"}},
		{"issue/dev", map[string]any{"entity_id": "another-entity"}},
	} {
		t.Run(test.path, func(t *testing.T) { requireRejected(t, b, storage, test.path, test.data) })
	}
	resp := call(t, b, storage, logical.ReadOperation, "config", nil)
	if len(resp.Data) != 2 || resp.Data["provider"] != "alpha" {
		t.Fatal("configuration read leaked options or lost metadata")
	}
}

func TestEntityRequired(t *testing.T) {
	b, adapter, storage := configured(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "issue/dev", Storage: storage,
	})
	if err != nil || resp == nil || !resp.IsError() || len(adapter.issued) != 0 {
		t.Fatal("entity-less request must fail before upstream side effects")
	}
}

func TestIndependentIssuanceAndRevocation(t *testing.T) {
	b, adapter, storage := configured(t)
	first := call(t, b, storage, logical.UpdateOperation, "issue/dev", nil)
	second := call(t, b, storage, logical.UpdateOperation, "issue/dev", map[string]any{"ttl": "5m"})
	firstID := first.Secret.InternalData["issuance_id"].(string)
	secondID := second.Secret.InternalData["issuance_id"].(string)
	if firstID == secondID || first.Secret.Renewable || len(first.Secret.InternalData) != 2 {
		t.Fatal("credentials must have independent non-renewable leases without secret material in internal data")
	}
	if first.Secret.TTL > 10*time.Minute || second.Secret.TTL > 5*time.Minute || len(first.Warnings) != 1 {
		t.Fatal("invalid TTL or missing revocation-only warning")
	}
	if adapter.issued[firstID].EntityID != "entity-one" {
		t.Fatal("adapter did not receive authenticated identity")
	}
	for range 2 {
		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.RevokeOperation, Storage: storage, Secret: first.Secret,
		})
		if err != nil {
			t.Fatal("revocation was not idempotent")
		}
	}
	if len(adapter.revoked) != 1 || adapter.revoked[firstID].RequestID == "" {
		t.Fatal("revocation affected the wrong number of credentials")
	}
	var record issuance
	found, err := load(context.Background(), storage, "issuances/"+secondID, &record)
	if err != nil || !found {
		t.Fatal("independent credential was removed")
	}
	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation, Storage: storage, Secret: second.Secret,
	})
	if err == nil {
		t.Fatal("renewal unexpectedly supported")
	}
}

func TestOldConfigurationSurvivesRotationAndRoleDeletion(t *testing.T) {
	b, adapter, storage := configured(t)
	resp := call(t, b, storage, logical.UpdateOperation, "issue/dev", nil)
	call(t, b, storage, logical.UpdateOperation, "config", map[string]any{
		"provider": "alpha", "options": map[string]any{"account": "second"},
	})
	call(t, b, storage, logical.DeleteOperation, "roles/dev", nil)
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation, Storage: storage, Secret: resp.Secret,
	})
	if err != nil {
		t.Fatal("old credential revocation failed")
	}
	var value map[string]string
	if json.Unmarshal(adapter.lastConfig, &value) != nil || value["account"] != "first" {
		t.Fatal("revocation did not use the original configuration")
	}
}

func TestNativeExpiryAndMountTTL(t *testing.T) {
	b, adapter, storage := configured(t)
	now := time.Now().UTC()
	b.now = func() time.Time { return now }
	adapter.caps.NativeExpiry = true
	adapter.expiry = now.Add(time.Minute)
	resp := call(t, b, storage, logical.UpdateOperation, "issue/dev", nil)
	if resp.Secret.TTL != 55*time.Second || len(resp.Warnings) != 0 {
		t.Fatal("native expiry was not bounded with safety margin")
	}
	b.System().(*logical.StaticSystemView).MaxLeaseTTLVal = 20 * time.Second
	resp = call(t, b, storage, logical.UpdateOperation, "issue/dev", nil)
	if resp.Secret.TTL != 20*time.Second {
		t.Fatal("mount maximum TTL ignored")
	}
	adapter.expiry = time.Time{}
	requireRejected(t, b, storage, "issue/dev", nil)
}

func TestAmbiguousIssueRecoveredAfterRestart(t *testing.T) {
	b, adapter, storage := configured(t)
	adapter.issueErr = errors.New("simulated upstream failure")
	adapter.revokeErr = errors.New("simulated revocation outage")
	requireRejected(t, b, storage, "issue/dev", nil)
	keys, _ := storage.List(context.Background(), "issuances/")
	if len(keys) != 1 {
		t.Fatal("ambiguous issue lost its durable recovery record")
	}
	adapter.revokeErr = nil
	restarted := newTestBackend(t, adapter, storage)
	restarted.now = func() time.Time { return time.Now().Add(time.Hour) }
	if restarted.cleanup(context.Background(), &logical.Request{Storage: storage}) != nil {
		t.Fatal("restart recovery failed")
	}
	keys, _ = storage.List(context.Background(), "issuances/")
	if len(keys) != 0 || len(adapter.revoked) != 1 {
		t.Fatal("recovery did not reconcile the orphan")
	}
	for _, revocation := range adapter.revoked {
		if len(revocation.Material) != 0 {
			t.Fatal("ambiguous recovery should use request ID without returned material")
		}
	}
}

type failingStorage struct {
	logical.Storage
	puts   int
	failAt int
}

func (s *failingStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	s.puts++
	if s.puts == s.failAt {
		return errors.New("simulated storage failure")
	}
	return s.Storage.Put(ctx, entry)
}

func TestStorageFailureBeforeAndAfterCreation(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			b, adapter, storage := configured(t)
			failing := &failingStorage{Storage: storage, failAt: failAt}
			requireRejected(t, b, failing, "issue/dev", nil)
			if failAt == 1 && len(adapter.issued) != 0 {
				t.Fatal("upstream called without durable recovery record")
			}
			if failAt == 2 && (len(adapter.issued) != 1 || len(adapter.revoked) != 1) {
				t.Fatal("credential not compensated after final storage failure")
			}
		})
	}
}

func TestConcurrentIssuanceAndMountIsolation(t *testing.T) {
	b, adapter, storage := configured(t)
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation, Path: "issue/dev", Storage: storage, EntityID: "entity-one",
			})
			if err != nil || resp == nil || resp.IsError() {
				t.Error("concurrent issuance failed")
			}
		}()
	}
	wg.Wait()
	if len(adapter.issued) != 12 {
		t.Fatal("concurrent issuance lost requests")
	}
	otherStorage := &logical.InmemStorage{}
	other := newTestBackend(t, newFake(), otherStorage)
	resp := call(t, other, otherStorage, logical.ReadOperation, "config", nil)
	if resp != nil {
		t.Fatal("configuration crossed mount boundary")
	}
}

func TestUnsafeProviderRejected(t *testing.T) {
	adapter := newFake()
	adapter.caps.RecoveryByRequestID = false
	storage := &logical.InmemStorage{}
	b := newTestBackend(t, adapter, storage)
	requireRejected(t, b, storage, "config", map[string]any{"provider": "alpha"})
}

func TestFailedRevocationRetainsRecordForRetry(t *testing.T) {
	b, adapter, storage := configured(t)
	resp := call(t, b, storage, logical.UpdateOperation, "issue/dev", nil)
	req := &logical.Request{Operation: logical.RevokeOperation, Storage: storage, Secret: resp.Secret}
	adapter.revokeErr = errors.New("simulated upstream outage")
	if _, err := b.HandleRequest(context.Background(), req); err == nil {
		t.Fatal("revocation failure was hidden")
	}
	keys, _ := storage.List(context.Background(), "issuances/")
	if len(keys) != 1 {
		t.Fatal("failed revocation lost its retry record")
	}
	adapter.revokeErr = nil
	if _, err := b.HandleRequest(context.Background(), req); err != nil {
		t.Fatal("revocation retry failed")
	}
	keys, _ = storage.List(context.Background(), "issuances/")
	if len(keys) != 0 {
		t.Fatal("successful retry did not remove its record")
	}
}

func TestCleanupDoesNotRevokeUnexpiredCredential(t *testing.T) {
	b, adapter, storage := configured(t)
	now := time.Now().UTC()
	b.now = func() time.Time { return now }
	call(t, b, storage, logical.UpdateOperation, "issue/dev", nil)
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RollbackOperation, Storage: storage,
	})
	if err != nil || len(adapter.revoked) != 0 {
		t.Fatal("periodic callback revoked an unexpired credential")
	}
	b.now = func() time.Time { return now.Add(time.Hour) }
	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RollbackOperation, Storage: storage,
	})
	if err != nil || len(adapter.revoked) != 1 {
		t.Fatal("periodic callback did not revoke an expired credential")
	}
}
