# Architecture

## Trust and ownership

OpenBao authenticates callers, enforces path ACLs, stores plugin state behind
its barrier, and schedules dynamic lease revocation. Relay validates mount and
role configuration, binds issuance to `Request.EntityID`, persists recovery
state, and invokes vendor adapters. Adapters implement vendor protocol and
permission semantics.

The registry is copied when constructing each backend. The production factory
starts with an empty registry. There is no test provider, arbitrary HTTP
template, runtime code loading, or operator-controlled capability toggle.
Adapters must not retain mount credentials or users in process-global state.

API writes are serialized within a mount, including upstream calls. This is
deliberately conservative and suitable only for initial low-throughput use.
Before scaling, introduce narrower locking with a documented active-node
ownership model. An in-process mutex is not a distributed lock.

## Adapter contract

`ValidateConfig` and `ValidateRole` must strictly decode vendor options and
reject unknown fields. Validation must not create credentials.

`Issue` receives a durable random request ID, authenticated entity ID, bounded
TTL, and administrator-defined role options. It must create an independent
credential and return its disclosure data, private revocation material, and
actual expiry when the provider supports one.

`Revoke` must be idempotent and able to reconcile an empty revocation material
using the original request ID. This handles an upstream timeout or process
crash after successful creation but before Relay persisted the response.
Confirmed absence is success. Ambiguous 404s, authorization failures, and
network errors are not proof of absence.

This first contract is intentionally restrictive. Providers that cannot look
up or revoke by request ID need a separately designed strategy, such as a
provably bounded native expiry with explicitly weaker early-revocation
guarantees. Do not silently weaken `RecoveryByRequestID`.

Network adapters must use verified HTTPS, a bounded HTTP transport, no
cross-origin credential forwarding, and fixed or reviewed allowlisted
endpoints. Do not accept arbitrary request URLs or authentication headers in
issuance requests. Provider SDK errors must not cross Relay's error boundary.

## Durable issuance

1. Load the current config and role under the mount lock.
2. Allocate an opaque recovery ID.
3. Save a versioned issuance record with original configuration and deadline.
4. Call the vendor with the recovery ID.
5. Save revocation material and the bounded actual expiry.
6. Return a framework Secret response with a non-renewable lease.

There is no atomic transaction across vendor creation, plugin storage, and
OpenBao lease registration. An immediate bounded compensation attempt follows
creation failures and final storage failures. Failed compensation leaves the
original durable record for cleanup. A process crash or lease-registration
failure can leave an undisclosed credential until its recorded deadline.

The framework periodic callback scans records, reconciles expired credentials,
and removes records only after successful upstream revocation. Individual
failures do not prevent trying other records. It uses persistent state, not an
in-process expiry timer.

The initial scan is linear and holds the mount lock. Metrics, paging, rate
limits, retry backoff, issuance quotas, and faster orphan detection are future
work. No production scale or outage-recovery SLA is claimed.

## Configuration rotation

Provider type is immutable. Configuration writes increment a revision; each
issuance retains the original configuration snapshot needed for revocation.
Deleting or replacing a role does not affect existing revocation records.

Snapshots retain historical management credentials until associated issuance
records are removed. Reads never reveal those snapshots. Rotation procedures
must retain upstream authority for cleanup or explicitly migrate outstanding
revocations before invalidating the old management credential.

Config deletion is not exposed. Unmounting deletes plugin storage and is not
a safe cleanup mechanism for unresolved records. Drain issuance, ensure all
leases and recovery records have been reconciled, then retire a mount.
An operator recovery/status API is still needed before production use.

## Personal OAuth: planned, not implemented

Future authorization records must be indexed by the immutable authenticated
OpenBao entity ID, not a supplied username. Implement OAuth as an optional
adapter extension rather than requiring it from API-key providers.

An authorization flow must bind state to the initiating entity and mount,
verify callback state, implement PKCE where supported, have a short transaction
TTL, and avoid credentials in redirects, logs, or local files.

Rotating refresh tokens require serialized refresh per grant and durable
updates. A successful upstream refresh followed by a local write failure may
require human reauthorization. Do not promise exactly-once refresh.

GitHub UATs must not be presented as PATs. Before implementing GitHub, verify
independent token creation, expiry, permission narrowing, and revocation scope
against current official documentation and an isolated test installation.
Refresh is not independent child-token issuance. Never distribute one shared
base token under several leases and call it isolated revocation.

## Validation boundary

Offline tests use OpenBao 2.7.1 SDK logical requests and generated disposable
credentials. They verify framework state transitions and failures. They do
not verify the real server's catalog registration, RPC transport, ACL engine,
lease scheduler, failover, seal-wrapping availability, or any vendor API.
Those are explicit prerequisites for a production release.

## GitHub assessment

See the [2026-10-31 UAT assessment](github-uat-feasibility.md) and its pinned,
field-only API evidence. Scoped creation exists; this does not establish
independent issuance or recovery of a lost creation response. The current
provider contract and empty production registry remain unchanged.

An experimental [candidate adapter and human-only verifier](github-uat-adapter.md)
implement the protocol under `provider/githubuat`. The adapter advertises no
verified capabilities and cannot be configured through the current framework,
even if injected into a registry. It uses a single entity-bound base grant;
multi-user OAuth storage and refresh are not implemented. The verifier is a
separate executable and its offline simulations are not live acceptance.

## Local server validation

The optional [Docker environment](local-openbao.md) registers and mounts Relay
on an actual OpenBao server, then verifies userpass entity authentication,
plugin RPC, and rejection of the unimplemented GitHub provider. Bootstrap
credentials stay in the supervisor process memory. The instance is loopback-only
and ephemeral. This is not vendor, lease-scheduler, or failover acceptance.
