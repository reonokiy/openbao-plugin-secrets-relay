package githubuat

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/reonokiy/openbao-plugin-secrets-relay/provider"
)

// VerifyInput is supplied in memory by the human-operated verifier.
// Config contains secrets and must never be printed or saved.
type VerifyInput struct {
	Config              json.RawMessage `json:"config"`
	Role                json.RawMessage `json:"role"`
	OutsideRepositoryID int64           `json:"outside_repository_id"`
}

// Report contains only fixed check names, booleans, and HTTP statuses.
// It is evidence for this one live run, not permission to enable the adapter.
type Report struct {
	Passed             bool            `json:"passed"`
	Checks             map[string]bool `json:"checks"`
	DenialStatuses     map[string]int  `json:"denial_statuses"`
	FailedStep         string          `json:"failed_step,omitempty"`
	CleanupComplete    bool            `json:"cleanup_complete"`
	AmbiguousCreation  bool            `json:"ambiguous_creation"`
	ProductionEligible bool            `json:"production_eligible"`
}

type repository struct {
	ID      int64  `json:"id"`
	Private bool   `json:"private"`
	Name    string `json:"name"`
	Owner   struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
	} `json:"owner"`
}

var repositoryPart = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)

func (a *Adapter) repository(ctx context.Context, cfg config, id int64, token string) (repository, error) {
	var repo repository
	err := a.call(ctx, http.MethodGet, fmt.Sprintf("/repositories/%d", id), cfg, token, nil, &repo)
	return repo, err
}

func denied(err error) (int, bool) {
	var response *HTTPError
	if errors.As(err, &response) && (response.Status == 403 || response.Status == 404) {
		return response.Status, true
	}
	return 0, false
}

// Verify creates two identically scoped UATs, checks isolation, and revokes
// only the known child tokens. It never refreshes a token or deletes a grant.
// Only a human may run this with an isolated real GitHub authorization.
func (a *Adapter) Verify(ctx context.Context, input VerifyInput) (report Report) {
	report.Checks = make(map[string]bool)
	report.DenialStatuses = make(map[string]int)
	report.CleanupComplete = true
	cfg, err := readConfig(input.Config)
	if err != nil {
		report.FailedStep = "config"
		return
	}
	options, err := readRole(input.Role)
	if err != nil || len(options.RepositoryIDs) != 1 || input.OutsideRepositoryID <= 0 ||
		input.OutsideRepositoryID == options.RepositoryIDs[0] || options.Permissions["contents"] != "read" {
		report.FailedStep = "role"
		return
	}
	for key := range options.Permissions {
		if key != "contents" && key != "metadata" {
			report.FailedStep = "role"
			return
		}
	}
	var issued []provider.Revocation
	defer func() {
		seen := make(map[string]bool)
		for _, value := range issued {
			if seen[string(value.Material)] {
				continue
			}
			seen[string(value.Material)] = true
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			cleanupErr := a.Revoke(cleanupCtx, input.Config, value)
			cancel()
			if cleanupErr != nil {
				report.CleanupComplete = false
			}
		}
		if report.AmbiguousCreation {
			report.CleanupComplete = false
		}
		if !report.CleanupComplete {
			report.Passed = false
			if report.FailedStep == "" {
				report.FailedStep = "cleanup"
			}
		}
	}()

	parent, err := a.check(ctx, cfg, cfg.BaseToken)
	if err != nil || parent.ExpiresAt == nil || !parent.ExpiresAt.After(a.now().Add(5*time.Minute)) {
		report.FailedStep = "parent_preflight"
		return
	}
	allowed, err := a.repository(ctx, cfg, options.RepositoryIDs[0], cfg.BaseToken)
	if err != nil || !allowed.Private || allowed.ID != options.RepositoryIDs[0] ||
		allowed.Owner.ID != options.TargetID || !repositoryPart.MatchString(allowed.Owner.Login) ||
		!repositoryPart.MatchString(allowed.Name) {
		report.FailedStep = "allowed_private_repository_preflight"
		return
	}
	outside, err := a.repository(ctx, cfg, input.OutsideRepositoryID, cfg.BaseToken)
	if err != nil || !outside.Private || outside.ID != input.OutsideRepositoryID || outside.Owner.ID != options.TargetID {
		report.FailedStep = "outside_private_repository_preflight"
		return
	}
	basePath := "/repos/" + allowed.Owner.Login + "/" + allowed.Name
	for _, suffix := range []string{"/contents", "/actions/workflows"} {
		if a.call(ctx, http.MethodGet, basePath+suffix, cfg, cfg.BaseToken, nil, nil) != nil {
			report.FailedStep = "base_permission_preflight"
			return
		}
	}
	report.Checks["base_can_access_both_private_repositories_and_workflows"] = true

	var children []*provider.Credential
	for range 2 {
		var id [16]byte
		if _, err = rand.Read(id[:]); err != nil {
			report.FailedStep = "request_id"
			return
		}
		requestID := hex.EncodeToString(id[:])
		credential, issueErr := a.Issue(ctx, input.Config, provider.IssueRequest{
			RequestID: requestID, EntityID: cfg.EntityID, TTL: time.Minute, Options: input.Role,
		})
		if credential != nil && len(credential.Revocation) > 0 {
			issued = append(issued, provider.Revocation{
				RequestID: requestID, EntityID: cfg.EntityID, Material: credential.Revocation,
			})
		}
		if issueErr != nil {
			report.AmbiguousCreation = errors.Is(issueErr, ErrAmbiguous)
			report.FailedStep = "scoped_issuance"
			return
		}
		children = append(children, credential)
	}
	first := children[0].Data["token"].(string)
	second := children[1].Data["token"].(string)
	if first == second || first == cfg.BaseToken || second == cfg.BaseToken {
		report.FailedStep = "distinct_tokens"
		return
	}
	report.Checks["distinct_tokens"] = true
	for _, token := range []string{first, second} {
		checked, checkErr := a.check(ctx, cfg, token)
		var user struct {
			ID int64 `json:"id"`
		}
		if checkErr != nil || checked.User.ID != parent.User.ID ||
			a.call(ctx, http.MethodGet, "/user", cfg, token, nil, &user) != nil || user.ID != parent.User.ID {
			report.FailedStep = "concurrent_user_authentication"
			return
		}
		repo, readErr := a.repository(ctx, cfg, allowed.ID, token)
		if readErr != nil || repo.ID != allowed.ID ||
			a.call(ctx, http.MethodGet, basePath+"/contents", cfg, token, nil, nil) != nil {
			report.FailedStep = "allowed_repository_access"
			return
		}
		_, deniedErr := a.repository(ctx, cfg, outside.ID, token)
		if status, ok := denied(deniedErr); ok {
			report.DenialStatuses["outside_repository"] = status
		} else {
			report.FailedStep = "outside_repository_denial"
			return
		}
		deniedErr = a.call(ctx, http.MethodGet, basePath+"/actions/workflows", cfg, token, nil, nil)
		if status, ok := denied(deniedErr); ok {
			report.DenialStatuses["workflow_permission"] = status
		} else {
			report.FailedStep = "workflow_permission_denial"
			return
		}
	}
	report.Checks["concurrent_user_authentication"] = true
	report.Checks["repository_and_permission_restrictions"] = true
	if a.Revoke(ctx, input.Config, issued[0]) != nil {
		report.FailedStep = "first_revocation"
		return
	}
	if _, err = a.check(ctx, cfg, first); !isStatus(err, 404) {
		report.FailedStep = "first_invalid_after_revocation"
		return
	}
	if _, err = a.check(ctx, cfg, second); err != nil {
		report.FailedStep = "second_preserved"
		return
	}
	if _, err = a.check(ctx, cfg, cfg.BaseToken); err != nil {
		report.FailedStep = "base_preserved"
		return
	}
	report.Checks["first_revoked_second_and_base_preserved"] = true
	if a.Revoke(ctx, input.Config, issued[0]) != nil || a.Revoke(ctx, input.Config, issued[1]) != nil {
		report.FailedStep = "repeated_and_second_revocation"
		return
	}
	if _, err = a.check(ctx, cfg, second); !isStatus(err, 404) {
		report.FailedStep = "second_invalid_after_revocation"
		return
	}
	if _, err = a.check(ctx, cfg, cfg.BaseToken); err != nil {
		report.FailedStep = "base_preserved_after_cleanup"
		return
	}
	report.Checks["repeated_revocation_and_second_cleanup"] = true
	report.Passed = true
	return
}
