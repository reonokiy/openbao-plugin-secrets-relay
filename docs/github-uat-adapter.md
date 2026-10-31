# GitHub UAT candidate adapter

The candidate in `provider/githubuat` implements GitHub's scoped-user-token
protocol. It is deliberately not registered by the plugin factory. The
production registry remains empty, including in the local Docker instance.
This is not a usable `provider=github` mount or a PAT generator.

## Implemented behavior

- Check the base UAT with the App's client ID and client secret.
- Create a scoped UAT with `POST /applications/{client_id}/token/scoped`.
- Require a repository owner ID, explicit repository IDs, and explicit
  permissions. The prototype supports at most 100 repositories and the
  `contents`, `pull_requests`, `issues`, `actions`, `checks`, and `metadata`
  permissions. Levels are `read` or `write`, with metadata limited to `read`.
- Bind the configured base authorization to exactly one OpenBao entity.
  Issuance rejects another entity before any HTTP call.
- Return the child token and expiry metadata only from successful issuance.
  Preserve known revocation material when rejecting an unusable child response.
- Revoke only the specified child with
  `DELETE /applications/{client_id}/token`. Never delete the user's grant,
  reset the base token, or refresh the base authorization.
- Reject absent cleanup material with an explicit recovery error. A request ID
  alone cannot identify an unknown GitHub token.

The transport uses only `https://api.github.com`, verified TLS, bounded calls
and response bodies, no redirects, no proxy from the environment, no creation
retry, and no raw error bodies. GitHub Enterprise and custom endpoints are not
supported.

The prototype configuration contains `client_id`, `client_secret`, `base_token`,
and `entity_id`. Role options contain `target_id`, `repository_ids`, and
`permissions`. Unknown fields are rejected. Validation does not make network
calls. These are candidate-library inputs, not an enabled OpenBao API.

The single-entity mount is an explicit prototype limit. Supporting multiple
users on one GitHub mount still requires entity-indexed grants, human OAuth
authorization, and a separately designed refresh/rotation flow. A shared base
UAT must not represent several OpenBao users.

## What prevents enabling it

All three capability flags remain false. This is enforced by tests at the
adapter and framework boundaries; there is no operator override.

1. Independent issuance is still unverified against a real GitHub authorization.
   Mocked responses establish our request/cleanup behavior only.
2. Scoped creation has no documented request ID, idempotency contract, or lookup
   by Relay request ID. After a lost response, single-token deletion requires
   the token that Relay may never have received. The candidate reports that
   uncertainty and never declares it recovered.
3. Scoped creation has no requested expiry parameter. The candidate requires
   expiring parents and valid child expiry metadata, but that does not establish
   a guaranteed upper bound for an unknown child's lifetime. In particular,
   expiry metadata must not be described as native 15-minute enforcement.

The protocol cannot repair item 2 by writing another local journal or retrying
creation. To enable this provider, either GitHub must supply a supported recovery
mechanism, or Relay needs a reviewed weaker recovery contract backed by an
established hard native-expiry bound. Such a contract must preserve unresolved
records and explicitly describe delayed invalidation beyond a Bao lease. It
cannot silently set `RecoveryByRequestID=true`.

Cleanup of a known token also requires working App credentials and a valid
base token in this conservative candidate. It checks the base before accepting
a child-check 404 as absence. A broken App configuration or expired/revoked
base leaves cleanup uncertain rather than pretending the child is gone.

## Human-operated acceptance

Agents must not run real onboarding, obtain real App credentials or UATs, or
execute authenticated acceptance. Offline tests generate disposable values in
memory and make no network calls.

An authorized human can run:

```sh
make github-verify
```

This builds a separate verifier, then prompts in your terminal. The App secret
and base UAT use hidden input. They travel to the verifier only through an
anonymous process pipe and remain in process memory, not arguments, environment
variables, files, or output. The wrapper refuses noninteractive or unmasked
input. It does not implement or run OAuth; obtain the base UAT yourself.

Prepare an isolated GitHub App with expiring UATs, the matching client secret,
and a non-scoped UAT with at least five minutes remaining. Use two private,
disposable repositories belonging to the same owner, both accessible by the
base UAT. Initialize the allowed repository with content. The base App/user
authorization must allow reading contents and Actions workflows. The verifier
restricts the children to contents-read on only the allowed repository.

The verifier checks:

1. The base can read both private repositories, allowed contents, and workflows.
2. Two identical scope requests produce distinct tokens, distinct from the base.
3. Both children authenticate as the expected user concurrently, read the
   allowed contents, and cannot read the excluded repository or workflows.
4. Revoking the first invalidates it while preserving the second and base.
5. Repeated revocation succeeds, the second is revoked, and the base survives.
6. Every known child is cleaned up on success or failure when possible.

Output contains fixed check names, booleans, and denial HTTP statuses only.
`production_eligible` is always false. A successful report covers that one run;
it does not prove parent-refresh behavior, parent-revocation behavior, native
expiry timing, API idempotency, or recovery of a lost response.

Cleanup is best effort for known tokens. An unknown creation result sets
`ambiguous_creation=true` and `cleanup_complete=false`. Network/authentication
failures or interruption can also prevent cleanup. The tool never revokes the
entire grant automatically: the human must retire the isolated authorization
through GitHub settings when cleanup is uncertain. Do not use an everyday App
authorization for this experiment and do not paste credentials into chat.

## Offline validation

`make check` runs protocol and verifier tests with an in-memory HTTP transport,
including response loss after simulated creation, duplicate child responses,
single-token and repeated revocation, permission/repository scope failures,
redirects, response limits, invalid App authentication, missing revocation
material, cleanup failure, and credential-output suppression.

`make github-verifier` builds the verifier without making GitHub requests.
The normal plugin binary still has no production vendor adapter.
