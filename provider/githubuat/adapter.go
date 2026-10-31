// Package githubuat implements an experimental GitHub scoped-UAT adapter.
// It is not registered in Relay: independent issuance is unverified and GitHub
// provides no supported recovery of a lost creation response by request ID.
package githubuat

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/reonokiy/openbao-plugin-secrets-relay/provider"
)

var (
	ErrOptions   = errors.New("GitHub UAT options rejected")
	ErrRequest   = errors.New("GitHub UAT request failed; details withheld")
	ErrResponse  = errors.New("GitHub UAT response rejected; details withheld")
	ErrAmbiguous = errors.New("GitHub UAT creation outcome is uncertain; request-ID recovery is unavailable")
	ErrRecovery  = errors.New("GitHub UAT revocation requires the known token; request-ID recovery is unavailable")
	clientIDRE   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	requestIDRE  = regexp.MustCompile(`^[a-f0-9]{32}$`)
)

// HTTPError exposes only the status, never the upstream response or credentials.
type HTTPError struct{ Status int }

func (e *HTTPError) Error() string {
	return fmt.Sprintf("GitHub UAT returned HTTP %d; details withheld", e.Status)
}

type config struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	BaseToken    string `json:"base_token"`
	EntityID     string `json:"entity_id"`
}

type role struct {
	TargetID      int64             `json:"target_id"`
	RepositoryIDs []int64           `json:"repository_ids"`
	Permissions   map[string]string `json:"permissions"`
}

type authorization struct {
	Token     string     `json:"token"`
	ExpiresAt *time.Time `json:"expires_at"`
	App       struct {
		ClientID string `json:"client_id"`
	} `json:"app"`
	User struct {
		ID int64 `json:"id"`
	} `json:"user"`
}

type material struct {
	Token  string `json:"token"`
	UserID int64  `json:"user_id"`
}

// Adapter has a fixed GitHub.com origin and no credential-bearing global state.
// A prototype mount is bound to one explicitly configured OpenBao entity.
type Adapter struct {
	client *http.Client
	now    func() time.Time
}

var _ provider.Adapter = (*Adapter)(nil)

func New() *Adapter {
	return &Adapter{
		client: &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
				TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
				IdleConnTimeout:       60 * time.Second,
				MaxIdleConnsPerHost:   4,
			},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
		now: time.Now,
	}
}

func (*Adapter) Capabilities() provider.Capabilities {
	// Do not advertise guarantees inferred from mocked HTTP responses.
	return provider.Capabilities{}
}

func decode(raw json.RawMessage, out any) error {
	if len(raw) == 0 || len(raw) > 65536 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return ErrOptions
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrOptions
	}
	return nil
}

func readConfig(raw json.RawMessage) (config, error) {
	var value config
	if decode(raw, &value) != nil || !clientIDRE.MatchString(value.ClientID) || value.ClientID == "." || value.ClientID == ".." ||
		!validSecret(value.ClientSecret) || !validSecret(value.BaseToken) ||
		strings.TrimSpace(value.EntityID) != value.EntityID || value.EntityID == "" || len(value.EntityID) > 256 {
		return config{}, ErrOptions
	}
	return value, nil
}

func validSecret(value string) bool {
	if len(value) == 0 || len(value) > 8192 {
		return false
	}
	for _, char := range value {
		if char < 33 || char > 126 {
			return false
		}
	}
	return true
}

func readRole(raw json.RawMessage) (role, error) {
	var value role
	if decode(raw, &value) != nil || value.TargetID <= 0 ||
		len(value.RepositoryIDs) == 0 || len(value.RepositoryIDs) > 100 || len(value.Permissions) == 0 {
		return role{}, ErrOptions
	}
	seen := make(map[int64]bool)
	for _, id := range value.RepositoryIDs {
		if id <= 0 || seen[id] {
			return role{}, ErrOptions
		}
		seen[id] = true
	}
	for name, level := range value.Permissions {
		switch name {
		case "contents", "pull_requests", "issues", "actions", "checks":
			if level != "read" && level != "write" {
				return role{}, ErrOptions
			}
		case "metadata":
			if level != "read" {
				return role{}, ErrOptions
			}
		default:
			return role{}, ErrOptions
		}
	}
	return value, nil
}

func (*Adapter) ValidateConfig(_ context.Context, raw json.RawMessage) error {
	_, err := readConfig(raw)
	return err
}

func (*Adapter) ValidateRole(_ context.Context, raw json.RawMessage) error {
	_, err := readRole(raw)
	return err
}

func (a *Adapter) call(ctx context.Context, method, path string, cfg config, bearer string, input, output any) error {
	var body []byte
	if input != nil {
		var err error
		body, err = json.Marshal(input)
		if err != nil {
			return ErrRequest
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://api.github.com"+path, bytes.NewReader(body))
	if err != nil {
		return ErrRequest
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "openbao-plugin-secrets-relay-experimental")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	} else {
		req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return ErrRequest
	}
	defer resp.Body.Close()
	expected := http.StatusOK
	if method == http.MethodDelete {
		expected = http.StatusNoContent
	}
	if resp.StatusCode != expected {
		return &HTTPError{Status: resp.StatusCode}
	}
	if output == nil {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1048577))
	if err != nil || len(raw) > 1048576 {
		return ErrResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if decoder.Decode(output) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrResponse
	}
	return nil
}

func (a *Adapter) check(ctx context.Context, cfg config, token string) (authorization, error) {
	var result authorization
	err := a.call(ctx, http.MethodPost, "/applications/"+cfg.ClientID+"/token", cfg, "",
		map[string]string{"access_token": token}, &result)
	if err != nil {
		return authorization{}, err
	}
	if result.Token != token || result.App.ClientID != cfg.ClientID || result.User.ID <= 0 {
		return authorization{}, ErrResponse
	}
	return result, nil
}

func (a *Adapter) Issue(ctx context.Context, raw json.RawMessage, req provider.IssueRequest) (*provider.Credential, error) {
	cfg, err := readConfig(raw)
	if err != nil {
		return nil, err
	}
	options, err := readRole(req.Options)
	if err != nil || req.EntityID != cfg.EntityID || !requestIDRE.MatchString(req.RequestID) ||
		req.TTL <= 0 || req.TTL > 15*time.Minute {
		return nil, ErrOptions
	}
	parent, err := a.check(ctx, cfg, cfg.BaseToken)
	if err != nil {
		return nil, err
	}
	if parent.ExpiresAt == nil || !parent.ExpiresAt.After(a.now().Add(req.TTL+5*time.Second)) {
		return nil, ErrResponse
	}
	var child authorization
	err = a.call(ctx, http.MethodPost, "/applications/"+cfg.ClientID+"/token/scoped", cfg, "", map[string]any{
		"access_token": cfg.BaseToken, "target_id": options.TargetID,
		"repository_ids": options.RepositoryIDs, "permissions": options.Permissions,
	}, &child)
	var credential *provider.Credential
	if validSecret(child.Token) && child.Token != cfg.BaseToken {
		revocation, _ := json.Marshal(material{Token: child.Token, UserID: parent.User.ID})
		credential = &provider.Credential{
			Data:       map[string]any{"token": child.Token, "token_type": "github_uat"},
			Revocation: revocation,
		}
		if child.ExpiresAt != nil {
			credential.ExpiresAt = *child.ExpiresAt
			credential.Data["expires_at"] = child.ExpiresAt.UTC().Format(time.RFC3339)
		}
	}
	if err != nil {
		// There is deliberately no retry or invented idempotency header.
		// Preserve an already decoded token even when trailing JSON is invalid.
		return credential, errors.Join(ErrAmbiguous, err)
	}
	if credential == nil {
		return nil, ErrAmbiguous
	}
	if child.User.ID != parent.User.ID || child.App.ClientID != cfg.ClientID ||
		child.ExpiresAt == nil || !child.ExpiresAt.After(a.now().Add(req.TTL+5*time.Second)) ||
		child.ExpiresAt.After(parent.ExpiresAt.Add(5*time.Second)) {
		// Preserve known material on rejection so the verifier can attempt cleanup.
		return credential, ErrResponse
	}
	return credential, nil
}

func isStatus(err error, status int) bool {
	var response *HTTPError
	return errors.As(err, &response) && response.Status == status
}

func (a *Adapter) Revoke(ctx context.Context, raw json.RawMessage, req provider.Revocation) error {
	cfg, err := readConfig(raw)
	if err != nil {
		return err
	}
	if req.EntityID != cfg.EntityID || !requestIDRE.MatchString(req.RequestID) {
		return ErrOptions
	}
	var value material
	if len(req.Material) == 0 {
		return ErrRecovery
	}
	if decode(req.Material, &value) != nil || !validSecret(value.Token) || value.UserID <= 0 ||
		value.Token == cfg.BaseToken {
		return ErrOptions
	}
	// Prove this app configuration still works before interpreting a child 404.
	parent, err := a.check(ctx, cfg, cfg.BaseToken)
	if err != nil {
		return err
	}
	if parent.User.ID != value.UserID {
		return ErrResponse
	}
	child, err := a.check(ctx, cfg, value.Token)
	if isStatus(err, http.StatusNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if child.User.ID != value.UserID {
		return ErrResponse
	}
	err = a.call(ctx, http.MethodDelete, "/applications/"+cfg.ClientID+"/token", cfg, "",
		map[string]string{"access_token": value.Token}, nil)
	if isStatus(err, http.StatusUnprocessableEntity) {
		_, checkErr := a.check(ctx, cfg, value.Token)
		if isStatus(checkErr, http.StatusNotFound) {
			return nil
		}
	}
	return err
}
