package githubuat

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/reonokiy/openbao-plugin-secrets-relay/provider"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type fixture struct {
	adapter                    *Adapter
	config                     config
	raw                        json.RawMessage
	role                       json.RawMessage
	now                        time.Time
	tokens                     map[string]authorization
	issued                     []string
	calls, scopeCalls, deletes int
	fault                      string
	forbidden, invalidRequest  bool
}

func disposable(t *testing.T) string {
	t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal("test randomness failed")
	}
	return hex.EncodeToString(raw[:])
}

func jsonValue(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("test encoding failed")
	}
	return raw
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		adapter: New(), now: time.Now().UTC(), tokens: make(map[string]authorization),
		config: config{ClientID: "test-client", ClientSecret: disposable(t), BaseToken: disposable(t), EntityID: "entity-one"},
	}
	f.raw = jsonValue(t, f.config)
	f.role = jsonValue(t, role{
		TargetID: 77, RepositoryIDs: []int64{101}, Permissions: map[string]string{"contents": "read"},
	})
	f.tokens[f.config.BaseToken] = f.authorization(f.config.BaseToken)
	f.adapter.now = func() time.Time { return f.now }
	f.adapter.client.Transport = roundTrip(func(req *http.Request) (*http.Response, error) { return f.serve(t, req) })
	return f
}

func (f *fixture) authorization(token string) authorization {
	expiry := f.now.Add(4 * time.Hour)
	value := authorization{Token: token, ExpiresAt: &expiry}
	value.App.ClientID = f.config.ClientID
	value.User.ID = 88
	return value
}

func (f *fixture) reply(t *testing.T, status int, value any) (*http.Response, error) {
	t.Helper()
	return &http.Response{
		StatusCode: status, Header: make(http.Header),
		Body: io.NopCloser(bytes.NewReader(jsonValue(t, value))),
	}, nil
}

func (f *fixture) serve(t *testing.T, req *http.Request) (*http.Response, error) {
	t.Helper()
	f.calls++
	if req.URL.Scheme != "https" || req.URL.Host != "api.github.com" || req.URL.RawQuery != "" ||
		req.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
		f.invalidRequest = true
		return f.reply(t, 400, f.config.ClientSecret)
	}
	if strings.HasSuffix(req.URL.Path, "/grant") || req.Method == http.MethodPatch {
		f.forbidden = true
		return f.reply(t, 500, f.config.ClientSecret)
	}
	if req.Method == http.MethodGet {
		token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		if _, ok := f.tokens[token]; !ok {
			return f.reply(t, 401, f.config.ClientSecret)
		}
		switch req.URL.Path {
		case "/user":
			return f.reply(t, 200, map[string]any{"id": 88})
		case "/repositories/101", "/repositories/202":
			id := int64(101)
			if req.URL.Path == "/repositories/202" {
				id = 202
				if token != f.config.BaseToken && f.fault != "repository-bypass" {
					return f.reply(t, 404, f.config.ClientSecret)
				}
			}
			return f.reply(t, 200, map[string]any{
				"id": id, "private": true, "name": "test-repo",
				"owner": map[string]any{"id": 77, "login": "test-owner"},
			})
		case "/repos/test-owner/test-repo/contents":
			return f.reply(t, 200, nil)
		case "/repos/test-owner/test-repo/actions/workflows":
			if token != f.config.BaseToken && f.fault != "permission-bypass" {
				return f.reply(t, 403, f.config.ClientSecret)
			}
			return f.reply(t, 200, nil)
		}
		return f.reply(t, 404, f.config.ClientSecret)
	}
	clientID, secret, ok := req.BasicAuth()
	if !ok || clientID != f.config.ClientID || secret != f.config.ClientSecret {
		f.invalidRequest = true
		return f.reply(t, 401, f.config.ClientSecret)
	}
	var body map[string]json.RawMessage
	if json.NewDecoder(req.Body).Decode(&body) != nil {
		f.invalidRequest = true
		return f.reply(t, 400, f.config.ClientSecret)
	}
	var token string
	if json.Unmarshal(body["access_token"], &token) != nil {
		f.invalidRequest = true
		return f.reply(t, 400, f.config.ClientSecret)
	}
	path := "/applications/" + f.config.ClientID + "/token"
	switch {
	case req.URL.Path == path+"/scoped" && req.Method == http.MethodPost:
		var target int64
		var ids []int64
		var permissions map[string]string
		_ = json.Unmarshal(body["target_id"], &target)
		_ = json.Unmarshal(body["repository_ids"], &ids)
		_ = json.Unmarshal(body["permissions"], &permissions)
		if len(body) != 4 || token != f.config.BaseToken || target != 77 ||
			len(ids) != 1 || ids[0] != 101 || len(permissions) != 1 || permissions["contents"] != "read" {
			f.invalidRequest = true
			return f.reply(t, 400, f.config.ClientSecret)
		}
		f.scopeCalls++
		child := disposable(t)
		if f.fault == "duplicate" && len(f.issued) > 0 {
			child = f.issued[0]
		}
		if f.fault == "base-response" {
			child = f.config.BaseToken
		}
		value := f.authorization(child)
		if f.fault == "no-expiry" {
			value.ExpiresAt = nil
		}
		if f.fault == "wrong-user" {
			value.User.ID++
		}
		f.tokens[child] = value
		f.issued = append(f.issued, child)
		if f.fault == "timeout" || f.fault == "second-timeout" && f.scopeCalls == 2 {
			return nil, errors.New(f.config.ClientSecret)
		}
		if f.fault == "malformed" {
			return &http.Response{StatusCode: 200, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader("{"))}, nil
		}
		if f.fault == "trailing-json" {
			return &http.Response{StatusCode: 200, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(string(jsonValue(t, value)) + "{}"))}, nil
		}
		return f.reply(t, 200, value)
	case req.URL.Path == path && req.Method == http.MethodPost:
		if f.fault == "bad-app" {
			return f.reply(t, 404, f.config.ClientSecret)
		}
		if f.fault == "bad-auth" && token == f.config.BaseToken {
			return f.reply(t, 401, f.config.ClientSecret)
		}
		value, found := f.tokens[token]
		if !found {
			return f.reply(t, 404, f.config.ClientSecret)
		}
		return f.reply(t, 200, value)
	case req.URL.Path == path && req.Method == http.MethodDelete:
		if token == f.config.BaseToken {
			f.forbidden = true
			return f.reply(t, 500, f.config.ClientSecret)
		}
		if f.fault == "delete-failed" {
			return f.reply(t, 500, f.config.ClientSecret)
		}
		f.deletes++
		delete(f.tokens, token)
		if f.fault == "delete-race" {
			return f.reply(t, 422, f.config.ClientSecret)
		}
		return f.reply(t, 204, nil)
	default:
		f.invalidRequest = true
		return f.reply(t, 404, f.config.ClientSecret)
	}
}

func (f *fixture) issue(t *testing.T) (*provider.Credential, error) {
	t.Helper()
	return f.adapter.Issue(context.Background(), f.raw, provider.IssueRequest{
		RequestID: disposable(t)[:32], EntityID: f.config.EntityID, TTL: time.Minute, Options: f.role,
	})
}

func (f *fixture) revoke(t *testing.T, credential *provider.Credential) error {
	t.Helper()
	return f.adapter.Revoke(context.Background(), f.raw, provider.Revocation{
		RequestID: disposable(t)[:32], EntityID: f.config.EntityID, Material: credential.Revocation,
	})
}

func (f *fixture) requireSanitized(t *testing.T, text string) {
	t.Helper()
	for _, value := range append([]string{f.config.ClientSecret, f.config.BaseToken}, f.issued...) {
		if strings.Contains(text, value) {
			t.Fatal("credential reflected in diagnostics")
		}
	}
}

func TestCandidateCapabilitiesAndStrictValidation(t *testing.T) {
	f := newFixture(t)
	caps := f.adapter.Capabilities()
	if caps.IndependentCredentials || caps.RecoveryByRequestID || caps.NativeExpiry {
		t.Fatal("candidate must not advertise unverified guarantees")
	}
	ctx := context.Background()
	if f.adapter.ValidateConfig(ctx, f.raw) != nil || f.adapter.ValidateRole(ctx, f.role) != nil || f.calls != 0 {
		t.Fatal("local validation failed or performed an external operation")
	}
	for _, field := range []string{"api_url", "access_token", "refresh_token", "username"} {
		var options map[string]any
		_ = json.Unmarshal(f.raw, &options)
		options[field] = "unsupported"
		if f.adapter.ValidateConfig(ctx, jsonValue(t, options)) == nil {
			t.Fatal("unknown configuration field accepted")
		}
	}
	for _, change := range []func(*role){
		func(value *role) { value.TargetID = 0 },
		func(value *role) { value.RepositoryIDs = nil },
		func(value *role) { value.RepositoryIDs = []int64{101, 101} },
		func(value *role) { value.Permissions = nil },
		func(value *role) { value.Permissions["contents"] = "admin" },
		func(value *role) { value.Permissions["unknown"] = "read" },
	} {
		var value role
		_ = json.Unmarshal(f.role, &value)
		change(&value)
		if f.adapter.ValidateRole(ctx, jsonValue(t, value)) == nil {
			t.Fatal("unsafe role accepted")
		}
	}
	for _, raw := range []json.RawMessage{nil, []byte("null"), []byte("{} {}")} {
		if f.adapter.ValidateConfig(ctx, raw) == nil || f.adapter.ValidateRole(ctx, raw) == nil {
			t.Fatal("invalid encoding accepted")
		}
	}
}

func TestScopedIssuanceAndIndividualIdempotentRevocation(t *testing.T) {
	f := newFixture(t)
	first, err := f.issue(t)
	if err != nil || first == nil || first.ExpiresAt.IsZero() {
		t.Fatal("scoped request failed")
	}
	second, err := f.issue(t)
	if err != nil || second == nil || first.Data["token"] == second.Data["token"] {
		t.Fatal("mock returned unexpected scoped credentials")
	}
	if f.revoke(t, first) != nil || f.revoke(t, first) != nil {
		t.Fatal("individual or repeated revocation failed")
	}
	if len(f.tokens) != 2 || f.tokens[f.config.BaseToken].Token == "" {
		t.Fatal("revocation affected another credential")
	}
	if f.revoke(t, second) != nil || len(f.tokens) != 1 || f.deletes != 2 || f.forbidden || f.invalidRequest {
		t.Fatal("revocation or request boundary failed")
	}
}

func TestEntityAndRequestValidationPrecedeNetwork(t *testing.T) {
	f := newFixture(t)
	for _, change := range []func(*provider.IssueRequest){
		func(req *provider.IssueRequest) { req.EntityID = "other-entity" },
		func(req *provider.IssueRequest) { req.RequestID = "" },
		func(req *provider.IssueRequest) { req.TTL = 0 },
		func(req *provider.IssueRequest) { req.TTL = time.Hour },
	} {
		req := provider.IssueRequest{
			RequestID: disposable(t)[:32], EntityID: f.config.EntityID, TTL: time.Minute, Options: f.role,
		}
		change(&req)
		if _, err := f.adapter.Issue(context.Background(), f.raw, req); err == nil {
			t.Fatal("invalid caller accepted")
		}
	}
	if f.calls != 0 {
		t.Fatal("rejected caller reached GitHub")
	}
}

func TestNonExpiringParentRejectedBeforeCreation(t *testing.T) {
	f := newFixture(t)
	parent := f.tokens[f.config.BaseToken]
	parent.ExpiresAt = nil
	f.tokens[f.config.BaseToken] = parent
	if _, err := f.issue(t); !errors.Is(err, ErrResponse) || f.scopeCalls != 0 {
		t.Fatal("non-expiring parent accepted")
	}
}

func TestLostAndMalformedCreationResponsesAreNotRetriedOrDeclaredRecovered(t *testing.T) {
	for _, fault := range []string{"timeout", "malformed", "base-response"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			f.fault = fault
			credential, err := f.issue(t)
			if !errors.Is(err, ErrAmbiguous) || credential != nil || f.scopeCalls != 1 {
				t.Fatal("ambiguous creation was not preserved")
			}
			f.requireSanitized(t, err.Error())
			before := f.calls
			err = f.adapter.Revoke(context.Background(), f.raw, provider.Revocation{
				RequestID: disposable(t)[:32], EntityID: f.config.EntityID,
			})
			if !errors.Is(err, ErrRecovery) || f.calls != before || f.deletes != 0 {
				t.Fatal("missing material must remain unrecoverable")
			}
		})
	}
}

func TestRejectedCredentialPreservesKnownCleanupMaterial(t *testing.T) {
	for _, mode := range []string{"no-expiry", "trailing-json"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.fault = mode
			credential, err := f.issue(t)
			if !errors.Is(err, ErrResponse) || credential == nil || len(credential.Revocation) == 0 {
				t.Fatal("rejected child lost known revocation material")
			}
			if f.revoke(t, credential) != nil || len(f.tokens) != 1 {
				t.Fatal("known rejected child cleanup failed")
			}
		})
	}
}

func TestAmbiguousNotFoundOrAuthenticationFailureDoesNotClearRevocation(t *testing.T) {
	for _, fault := range []string{"bad-app", "bad-auth", "delete-failed"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			credential, err := f.issue(t)
			if err != nil {
				t.Fatal("test issuance failed")
			}
			f.fault = fault
			err = f.revoke(t, credential)
			if err == nil || len(f.tokens) != 2 || f.deletes != 0 {
				t.Fatal("uncertain revocation was incorrectly accepted")
			}
			f.requireSanitized(t, err.Error())
		})
	}
}

func TestBaseTokenAndWrongEntityCannotBeRevoked(t *testing.T) {
	f := newFixture(t)
	for _, req := range []provider.Revocation{
		{RequestID: disposable(t)[:32], EntityID: f.config.EntityID,
			Material: jsonValue(t, material{Token: f.config.BaseToken, UserID: 88})},
		{RequestID: disposable(t)[:32], EntityID: "other-entity",
			Material: jsonValue(t, material{Token: disposable(t), UserID: 88})},
	} {
		if f.adapter.Revoke(context.Background(), f.raw, req) == nil {
			t.Fatal("unsafe revocation accepted")
		}
	}
	if f.calls != 0 {
		t.Fatal("unsafe revocation reached GitHub")
	}
}

func TestConcurrentDeleteRaceRequiresConfirmedAbsence(t *testing.T) {
	f := newFixture(t)
	credential, err := f.issue(t)
	if err != nil {
		t.Fatal("test issuance failed")
	}
	f.fault = "delete-race"
	if f.revoke(t, credential) != nil || len(f.tokens) != 1 {
		t.Fatal("confirmed absence was not reconciled")
	}
}

func TestRedirectsAndOversizedResponsesAreRejected(t *testing.T) {
	for _, mode := range []string{"redirect", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			count := 0
			f.adapter.client.Transport = roundTrip(func(req *http.Request) (*http.Response, error) {
				count++
				if req.URL.Host != "api.github.com" {
					t.Fatal("credential-bearing redirect followed")
				}
				if mode == "redirect" {
					return &http.Response{StatusCode: 302,
						Header: http.Header{"Location": []string{"https://example.invalid/"}},
						Body:   io.NopCloser(strings.NewReader(f.config.ClientSecret))}, nil
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader(strings.Repeat(" ", 1048577)))}, nil
			})
			_, err := f.issue(t)
			if err == nil || count != 1 {
				t.Fatal("unsafe response accepted or retried")
			}
			f.requireSanitized(t, err.Error())
		})
	}
}

func TestVerifierIsolationAndCleanup(t *testing.T) {
	for _, mode := range []string{"success", "duplicate", "second-timeout", "repository-bypass", "permission-bypass", "delete-failed"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.fault = mode
			report := f.adapter.Verify(context.Background(), VerifyInput{
				Config: f.raw, Role: f.role, OutsideRepositoryID: 202,
			})
			f.requireSanitized(t, string(jsonValue(t, report)))
			if report.ProductionEligible || f.forbidden || f.invalidRequest {
				t.Fatal("verifier exceeded its boundary")
			}
			if mode == "success" {
				if !report.Passed || !report.CleanupComplete || len(f.tokens) != 1 || len(report.Checks) != 6 {
					t.Fatal("mock verification or cleanup failed")
				}
			} else if report.Passed || report.FailedStep == "" {
				t.Fatal("failed verification reported success")
			}
			if mode == "second-timeout" {
				if !report.AmbiguousCreation || report.CleanupComplete || len(f.tokens) != 2 {
					t.Fatal("lost response was incorrectly reported as cleaned up")
				}
			} else if mode == "delete-failed" {
				if report.CleanupComplete {
					t.Fatal("failed cleanup reported success")
				}
			} else if !report.CleanupComplete || len(f.tokens) != 1 {
				t.Fatal("known test children were not cleaned up")
			}
		})
	}
}
