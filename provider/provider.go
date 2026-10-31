// Package provider defines the contract between Relay and vendor adapters.
package provider

import (
	"context"
	"encoding/json"
	"time"
)

// Capabilities are guarantees implemented by an adapter, not operator settings.
type Capabilities struct {
	IndependentCredentials bool `json:"independent_credentials"`
	NativeExpiry           bool `json:"native_expiry"`
	// RecoveryByRequestID includes creation that succeeded upstream but timed out.
	RecoveryByRequestID bool `json:"recovery_by_request_id"`
}

type IssueRequest struct {
	RequestID string
	EntityID  string
	TTL       time.Duration
	Options   json.RawMessage
}

type Credential struct {
	// Data is disclosed only in the successful issuance response.
	Data map[string]any
	// Revocation may contain secrets; it must never be returned by a read API.
	Revocation json.RawMessage
	// ExpiresAt is mandatory when NativeExpiry is advertised.
	ExpiresAt time.Time
}

type Revocation struct {
	RequestID string
	EntityID  string
	Material  json.RawMessage
}

// Adapter implementations must be concurrency-safe, bound all network calls,
// verify TLS, and avoid logging credentials or upstream response bodies.
type Adapter interface {
	Capabilities() Capabilities
	ValidateConfig(context.Context, json.RawMessage) error
	ValidateRole(context.Context, json.RawMessage) error
	Issue(context.Context, json.RawMessage, IssueRequest) (*Credential, error)
	// Revoke is idempotent. Empty Material means reconcile by RequestID, including
	// an ambiguous Issue result. Never revoke unrelated credentials to recover.
	Revoke(context.Context, json.RawMessage, Revocation) error
}
