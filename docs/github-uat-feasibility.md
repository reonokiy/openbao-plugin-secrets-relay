# GitHub user access token feasibility

Assessment date: 2026-10-31.

Decision: **hold the GitHub UAT adapter under Relay's current contract**.
GitHub publishes scoped-UAT creation and individual-token revocation APIs.
That establishes an integration path, but does not establish every lifecycle
guarantee required to enable a Relay adapter. No real credentials, user
onboarding, or authenticated token issuance were used for this assessment.

## Evidence

The primary API evidence is GitHub's official OpenAPI description, pinned to
commit `f9ed74230d54847b5ca00a1343e8e349e858b8fb`:

- [Pinned OpenAPI source](https://github.com/github/rest-api-description/blob/f9ed74230d54847b5ca00a1343e8e349e858b8fb/descriptions/api.github.com/api.github.com.json).
- [Field-only snapshot](github-uat-api-evidence.json), containing selected
  operation IDs, request field names, response statuses, and expiry schema.
  Examples, tokens, response bodies, and credentials are not included.
- [Official API reference](https://docs.github.com/en/rest/apps/oauth-applications).
- [User access token generation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app).
- [Refresh semantics](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens).

The API reference page inspected during this assessment did not list scoped
creation, whereas the pinned schema contains `apps/scope-token`. A missing
rendered section is not evidence that the operation does not exist.

## Findings

| Requirement | Published API evidence | Result |
| --- | --- | --- |
| Create a reduced-access UAT from an existing user authorization | `POST /applications/{client_id}/token/scoped` accepts a non-scoped UAT and repository/permission restrictions | Supported by the documented API |
| Revoke one specified token | `DELETE /applications/{client_id}/token` accepts the complete `access_token` | Supported by the documented API |
| Check a known token | `POST /applications/{client_id}/token` accepts the complete `access_token` | Supported; it is not lookup by Relay request ID |
| Repeated identical issuance produces distinct, concurrently valid tokens | No explicit uniqueness or repeat-request semantics in the inspected operation contract | Requires isolated live verification |
| Revoking one scoped token preserves another and the base authorization | Single-token revocation is documented; the full scoped-token relationship was not tested | Requires isolated live verification |
| Native expiry matches a requested 15-minute lease | Scoped creation has no TTL or expiry input; response `expires_at` is nullable | Cannot claim a requested native short expiry |
| Recover an issuance response lost after remote creation | No request-ID, idempotency, or request-ID lookup contract is documented for scoped issuance | Does not meet the current recovery contract |

These conclusions distinguish documented support from behavior verified in a
live installation. Absence from the published contract is not a claim that
an undocumented behavior is impossible or that the endpoint rejects unknown
headers; it means Relay has no supported guarantee on which to rely.

## Why this does not enable an adapter yet

Relay requires both `IndependentCredentials` and `RecoveryByRequestID`.
The first must not be advertised merely because an endpoint returns a token.
The second covers this concrete failure:

1. Relay persists request ID R.
2. GitHub creates scoped token T.
3. The connection fails before Relay receives or persists T.
4. The revocation API needs T; R is insufficient.

Writing the request ID before creation protects local bookkeeping, but cannot
make an unsupported upstream recovery operation exist. Retrying the creation
request could create another unknown token or reuse one; neither behavior was
established by this assessment.

Do not implement `RecoveryByRequestID=true` with a no-op when revocation
material is missing. Do not use whole-authorization deletion as compensation:
`DELETE /applications/{client_id}/grant` also removes the user's other tokens
for that application.

A native-expiry recovery strategy might eventually be acceptable, but it
would be a new, explicitly weaker contract. Before implementing it, establish
a hard upper bound for scoped-token expiry, reject non-expiring parents, keep
unresolved issuance records, and specify the difference between the OpenBao
lease deadline and the possible upstream validity window. A nullable
`expires_at` response alone is not that guarantee.

Refreshing or resetting the base UAT is not an independent issuance strategy.
GitHub's refresh documentation states that refreshing invalidates the old
access token and refresh token; reset changes the existing token immediately.
Neither should be substituted for creating parallel child credentials.

## Human-only acceptance before integration

An authorized human must use an isolated GitHub App and a disposable test
repository. Agents must not obtain the App secret, base UAT, refresh token,
authorization code, or issued test tokens, and must not run real onboarding.
All credential handling must remain in the human-operated verifier's memory;
do not paste values or credential-bearing diagnostics into chat or files.

The acceptance result should contain booleans and sanitized HTTP statuses:

1. Establish a user authorization with expiration enabled. Record identity and
   expiry metadata without disclosing the token.
2. Perform two scoped requests using identical approved restrictions. Verify
   that neither result equals the base token, the two results differ, and both
   work concurrently for the expected user.
3. Verify permitted repository operations and denial outside the requested
   repository/permission boundary.
4. Revoke the first token with the single-token API. Check that it no longer
   authenticates while the second and base authorization still do.
5. Revoke the second token, verify its invalidity, and clean up the test
   authorization. Confirm cleanup without printing any token values.
6. Separately establish parent-refresh, parent-revocation, child-expiry, and
   repeated-delete behavior. Do not infer them from an HTTP mock.

Passing the independence checks would not resolve the lost-response recovery
gap. Both that policy decision and the integration behavior must be settled
before wiring a GitHub adapter into the production factory.

## Current implementation boundary

The production adapter registry remains empty. No OAuth flow, GitHub request
path, or unsupported capability flag was added. Existing offline framework
tests exercise local lifecycle behavior; they cannot validate GitHub's
token-issuance semantics.
