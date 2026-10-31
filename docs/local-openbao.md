# Local OpenBao Docker instance

This environment validates Relay against a real OpenBao 2.7.1 server and
plugin RPC transport. It is an ephemeral Linux development environment,
not a production deployment or a working GitHub UAT issuer.

## Start and inspect

Requires Docker, Python 3 with its standard library, and the project's pinned
Go toolchain:

```sh
make local-up
make local-status
make local-check
```

OpenBao listens at `http://127.0.0.1:18200`; the UI is at
`http://127.0.0.1:18200/ui/`. Docker publishes only the loopback address.
The service deliberately uses HTTP for this disposable loopback environment.
Do not publish it on a network interface, reverse proxy it, or use real vendor
credentials here.

The helper registers the built Relay binary with its exact SHA-256 checksum
and version, mounts it at `relay/`, enables `userpass`, and installs a limited
local policy. The production provider registry is empty; attempts to configure
`provider=github` are expected to be rejected.

## Set your local login

Run this yourself in an interactive terminal:

```sh
make local-password
```

Enter a local-only password of at least 16 characters twice. The helper sends
it to the local supervisor through a private Unix socket without echoing it,
putting it in command arguments, or writing it to a file.

In the UI, choose the Username/Password method (mount `userpass`) and username
`developer`. Your policy allows Relay configuration, roles, and issuance paths,
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
