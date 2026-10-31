# Local OpenBao Docker instance

This environment validates Relay against a real OpenBao 2.7.1 server and
plugin RPC transport. It is an ephemeral Linux development environment,
not a production deployment or a working GitHub UAT issuer.

## Start and inspect

Requires Docker, Python 3 with its standard library, and the project's pinned
Go toolchain:

```sh
make local-init
make local-status
make local-check
```

`local-init` builds the plugin and runs the complete initialization workflow:

1. Start the pinned Docker image with loopback-only access.
2. Initialize and unseal OpenBao through its API.
3. Register the plugin checksum and version, then mount it at `relay/`.
4. Enable userpass and install the limited local policy.
5. Generate a disposable test user and random password in supervisor memory,
   authenticate through the API, and verify entity identity, plugin RPC and ACLs.
6. Revoke the temporary login token and remove the test user.

No browser, username/password entry, or token configuration is required.
The command returns only initialization metadata and boolean checks. It does
not retain a client session or export credentials. Run `make local-login` to
repeat the programmatic authentication and checks against the running instance.

Repeating `local-init` reuses the owned supervisor and reruns verification;
it does not reset OpenBao, replace an optional `developer` password, or claim
an unrelated container. If initialization or verification fails, the command
exits nonzero without returning a successful initialization report. An instance
that already started remains available for inspection with `local-status`
and cleanup with `local-down`. The existing `local-up` command remains available
for starting the instance separately.

OpenBao listens at `http://127.0.0.1:18200`; the UI is at
`http://127.0.0.1:18200/ui/`. Docker publishes only the loopback address.
The service deliberately uses HTTP for this disposable loopback environment.
Do not publish it on a network interface, reverse proxy it, or use real vendor
credentials here.

The helper registers the built Relay binary with its exact SHA-256 checksum
and version, mounts it at `relay/`, enables `userpass`, and installs a limited
local policy. The production provider registry is empty; attempts to configure
`provider=github` are expected to be rejected.

## Optional manual access

This section is only for inspecting the UI or using the native `bao` CLI
yourself. It is not needed for automated initialization or verification.

Run this yourself in an interactive terminal:

```sh
make local-password
```

Enter a local-only password of at least 16 characters twice. The helper sends
it to the local supervisor through a private Unix socket without echoing it,
putting it in command arguments, or writing it to a file.

If using the UI, open
`http://127.0.0.1:18200/ui/vault/auth?with=userpass` yourself and enter username
`developer` and your local password. The helper's `login` command now performs
API verification; browser launching and the former `--no-open` option were removed.

Your policy allows Relay configuration, roles, and issuance paths,
plus read-only mount metadata. It does not grant plugin-catalog administration
or access to the supervisor's bootstrap token.

If you prefer the CLI, use the local server and interactive userpass login in
your own terminal. Tokens and secrets returned by CLI operations must not be
copied into chat or diagnostic logs. This helper does not export tokens or
create a credential-bearing CLI configuration.

## What local-check verifies

The check creates a disposable, in-memory test password and user, logs in,
and verifies:

- OpenBao is initialized and unsealed.
- A real external Relay plugin answers through the server.
- Userpass creates an authenticated OpenBao entity.
- The provider registry is empty.
- Configuring the unimplemented GitHub provider fails.
- The local user cannot administer the plugin catalog.

The temporary token is revoked and the test user is removed. Output contains
only boolean results; no initialization material, password, token, or upstream
response body is printed.

This closes the earlier catalog/RPC/authentication validation gap. It does
not validate real vendor issuance, dynamic lease scheduling, server failover,
or native GitHub token semantics.

## Stop and reset

```sh
make local-down
```

The helper removes only the exact container created by its supervisor.
All OpenBao data uses the in-memory storage backend and disappears with the
container. There is no data volume or persisted unseal key.

Initialization and bootstrap-token handling happen in a detached local Python
supervisor. Its token stays in process memory. The owner-only runtime directory
under `/tmp/relay-openbao-local-<uid>/` contains a Unix socket, a lock file,
and sanitized status metadata, not credentials. Docker logging is disabled.
The container uses the invoking user's numeric UID/GID, a read-only filesystem,
all capabilities dropped, and no privilege escalation.

Keep the supervisor alive while using the instance. If it crashes, an existing
container may remain; recovery is to remove this disposable container and start
again, not to retrieve a root token or unseal key. The helper refuses to take
over an existing container name. Use `make local-down` before changing the
binary and restarting so its catalog checksum matches the mounted file.
