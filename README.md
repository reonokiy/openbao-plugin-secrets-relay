# Relay

Relay is an OpenBao secrets engine for short-lived vendor credentials.
One plugin binary can contain multiple vendor adapters; each mount is
permanently bound to one provider.

**Status: framework scaffold. No production vendor adapter is included.**
The executable builds and speaks the OpenBao plugin protocol. The test suite
exercises the lifecycle with an adapter compiled into tests only. There is no
GitHub PAT generator, OAuth onboarding, or functional GitHub UAT issuance yet.

The [GitHub UAT assessment](docs/github-uat-feasibility.md) confirms that scoped
creation and single-token revocation are documented, but leaves the adapter on
hold pending independent-token verification and a supported recovery strategy.

## Development

Requires Go 1.27.1. OpenBao API and SDK are pinned to 2.7.1.

```sh
make check
make build
```

The binary is written to `dist/openbao-plugin-secrets-relay`. The lifecycle
tests are offline and never contact a vendor or read operator credentials.
They exercise SDK logical requests, not a live OpenBao server.

## Local OpenBao

Run `make local-up` to start a disposable Docker instance at
`http://127.0.0.1:18200`. Relay is registered and mounted at `relay/`.
`make local-check` verifies plugin RPC and entity authentication; run
`make local-password` yourself to set the local UI login. No GitHub adapter
is enabled. See [local setup](docs/local-openbao.md) for access and cleanup.

## Layout

```text
cmd/openbao-plugin-secrets-relay/  Plugin process entry point
provider/                        Vendor adapter contract
backend.go                       Factory, storage models, registry
paths.go                         Configuration and role API
issuance.go                      Issuance, revocation, recovery
backend_test.go                  Offline lifecycle and failure tests
docs/architecture.md            Guarantees and remaining work
examples/policies/              Least-privilege policy starting points
```

## API

Paths are relative to the mount:

| Path | Operations | Purpose |
| --- | --- | --- |
| `providers` | list | Names of adapters compiled into this binary |
| `config` | read, update | Bind provider, replace adapter config; read metadata only |
| `roles` | list | Role names |
| `roles/:name` | read, update, delete | Replace issuance constraints; read TTL metadata only |
| `issue/:name` | update | Issue for the authenticated OpenBao entity |

Configuration and role writes replace the complete object, not a partial
patch. Unknown top-level fields are rejected; adapters must also strictly
validate their options. Config and role options are intentionally not reflected
by read endpoints.

Once an adapter has been implemented and wired into `Factory`, the interface
will look like this:

```sh
bao secrets enable -path=vendor-a relay
bao list vendor-a/providers
bao write vendor-a/config provider=vendor-a
bao write vendor-a/roles/dev ttl=10m max_ttl=15m
bao write vendor-a/issue/dev ttl=5m
```

These are interface examples, not a currently usable vendor integration.
Production credential consumption should use an in-memory helper or SDK;
the final command displays the returned credential. Do not use terminal
output to inspect production credentials, put secrets in command arguments,
or record them in shell history. Future onboarding must send secrets through
an authenticated client directly into the plugin, without local files.

Register the binary in the OpenBao plugin catalog as `relay` with an exact
SHA-256 checksum before enabling a mount. Artifact distribution, catalog
registration outside the local helper, and production deployment are not
included. The local helper verifies catalog/RPC behavior, not vendor issuance.

## Lifecycle

- Issuance requires a non-empty authenticated `EntityID`. Request fields cannot
  select a different identity. OpenBao ACL policies control access to roles.
- Leases are non-renewable, with a 15-minute hard ceiling and lower role/mount
  limits. Native provider expiry can further reduce the returned TTL.
- Each issuance gets an independent recovery ID and a durable record before
  upstream creation. That record contains the original configuration snapshot.
- Revocation uses that snapshot even after configuration rotation or role
  deletion. The old upstream management credential must remain valid until
  all credentials issued with it have been cleaned up.
- The lease contains only the internal issuance reference, not upstream
  revocation secrets. Sensitive records use OpenBao barrier storage and
  request seal wrapping where available.
- Failed or interrupted issuance is recovered through its request ID.
  Periodic cleanup retries records after their recorded deadline.
- Upstream errors are withheld from API responses and the entry point uses a
  null logger. Never introduce raw request/response or credential logging.

An adapter without native expiry provides **revocation on lease expiry**, not
guaranteed remote invalidation at an exact instant. OpenBao downtime, remote
outages, and revocation failures can extend validity. The issuance response
warns callers about this distinction.

## Adding a provider

Implement `provider.Adapter`, then register it explicitly through
`FactoryWithAdapters` in the production factory. Provider names and capabilities
are code-owned. The current contract requires independent credentials and
recovery by the preallocated request ID, even when creation timed out before
returning a credential ID. Do not advertise a capability without testing the
upstream semantics.

See [the architecture notes](docs/architecture.md) before adding an adapter.

## License

MPL-2.0. See [LICENSE](LICENSE).
