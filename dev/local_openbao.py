#!/usr/bin/env python3
"""Disposable local OpenBao; bootstrap secrets stay in the supervisor's memory."""

import argparse
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
ADDRESS = "http://127.0.0.1:18200"
IMAGE = "quay.io/openbao/openbao:2.7.1@sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf"
CONTAINER = "relay-openbao-local"
LABEL = "net.openbao-relay.local"
VERSION = "v0.1.0-dev"
STATE = Path(tempfile.gettempdir()) / f"relay-openbao-local-{os.getuid()}"
POLICY = '''
path "relay/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "sys/mounts" {
  capabilities = ["read"]
}
path "sys/internal/ui/mounts" {
  capabilities = ["read"]
}
path "sys/internal/ui/mounts/*" {
  capabilities = ["read"]
}
path "sys/plugins/catalog/secret/relay" {
  capabilities = ["read"]
}
'''


class LocalError(Exception):
    pass


class APIError(LocalError):
    def __init__(self, status):
        self.status = status
        super().__init__(f"OpenBao returned HTTP {status}; response body withheld")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class API:
    def __init__(self):
        self.token = None
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect()
        )

    def call(self, method, path, data=None, token=None):
        headers = {"Content-Type": "application/json"}
        auth = token if token is not None else self.token
        if auth:
            headers["X-Vault-Token"] = auth
        request = urllib.request.Request(
            ADDRESS + "/v1/" + path,
            data=None if data is None else json.dumps(data).encode(),
            headers=headers,
            method=method,
        )
        try:
            with self.opener.open(request, timeout=5) as response:
                raw = response.read(1048577)
                if len(raw) > 1048576:
                    raise LocalError("OpenBao response exceeds local limit")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            raise APIError(status) from None
        except (OSError, ValueError):
            raise LocalError("OpenBao request failed; details withheld") from None


def docker(*args, required=True):
    result = subprocess.run(
        ["docker", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    if required and result.returncode:
        raise LocalError("Docker operation failed; diagnostics withheld")
    return result


def secure_state(path=STATE):
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise LocalError("Local runtime directory is not an owned directory")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise LocalError("Local runtime directory must have mode 0700")


def control(action, **fields):
    secure_state()
    try:
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(45)
            client.connect(str(STATE / "control.sock"))
            client.sendall(json.dumps({"action": action, **fields}).encode() + b"\n")
            with client.makefile("rb") as stream:
                raw = stream.readline(65537)
            if len(raw) > 65536:
                raise LocalError("Local supervisor response exceeds limit")
            response = json.loads(raw)
    except (OSError, ValueError):
        raise LocalError("Local supervisor unavailable; run make local-up") from None
    if response.get("error"):
        raise LocalError("Local supervisor rejected request; details withheld")
    return response


class Supervisor:
    def __init__(self):
        self.api = API()
        self.container_id = None
        self.stopping = False
        self.checks = {}
        self.phase = "docker"

    def bootstrap(self):
        binary = ROOT / "dist" / "openbao-plugin-secrets-relay"
        if not binary.is_file():
            raise LocalError("Build Relay before starting OpenBao")
        # The container runs as the invoking host UID and reads only these mounts.
        config = ROOT / "dev" / "openbao.hcl"
        if docker("image", "inspect", "--format={{.Id}}", IMAGE, required=False).returncode:
            docker("pull", IMAGE)
        result = docker(
            "run", "--detach", "--pull=never", "--name", CONTAINER,
            "--label", LABEL + "=true",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--log-driver=none", "--tmpfs", "/tmp:rw,nosuid,nodev,size=67108864",
            "--publish", "127.0.0.1:18200:8200",
            "--mount", f"type=bind,src={config},dst=/config/openbao.hcl,readonly",
            "--mount", f"type=bind,src={binary.parent},dst=/plugins,readonly",
            "--entrypoint", "bao", IMAGE, "server", "-config=/config/openbao.hcl",
        )
        self.container_id = result.stdout.decode().strip()
        self.phase = "wait-for-server"
        deadline = time.monotonic() + 30
        while True:
            try:
                if not self.api.call("GET", "sys/init")["initialized"]:
                    break
                raise LocalError("Unexpected initialized instance on local port")
            except LocalError:
                if time.monotonic() >= deadline:
                    raise LocalError("Local OpenBao startup timed out") from None
                time.sleep(0.2)
        self.phase = "initialize-and-unseal"
        init = self.api.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        self.api.call("POST", "sys/unseal", {"key": init["keys_base64"][0]})
        self.api.token = init["root_token"]
        init.clear()
        self.phase = "register-plugin"
        self.api.call("POST", "sys/plugins/catalog/secret/relay", {
            "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "command": binary.name, "version": VERSION,
        })
        self.phase = "mount-plugin"
        self.api.call("POST", "sys/mounts/relay", {
            "type": "relay",
            "description": "Relay local framework validation; no vendor adapter",
            "config": {
                "plugin_version": VERSION, "default_lease_ttl": "15m",
                "max_lease_ttl": "15m",
            },
        })
        self.phase = "configure-local-auth"
        self.api.call("POST", "sys/auth/userpass", {"type": "userpass"})
        self.api.call("PUT", "sys/policies/acl/relay-local", {"policy": POLICY})
        self.phase = "verify"
        self.verify()
        self.phase = "ready"

    def verify(self):
        user = "relay-smoke"
        password = secrets.token_urlsafe(32)
        token = None
        try:
            self.phase = "verify-authentication"
            self.api.call("POST", f"auth/userpass/users/{user}", {
                "password": password, "token_policies": ["relay-local"],
                "token_ttl": "5m", "token_max_ttl": "5m",
            })
            auth = self.api.call("POST", f"auth/userpass/login/{user}", {
                "password": password,
            })["auth"]
            token = auth["client_token"]
            if not auth.get("entity_id"):
                raise LocalError("Local authentication did not create an identity")
            self.phase = "verify-plugin-rpc"
            help_response = self.api.call("GET", "relay/?help=1", token=token)
            if "Relay" not in help_response.get("help", ""):
                raise LocalError("Relay root help was not returned by the plugin")
            try:
                response = self.api.call("LIST", "relay/providers", token=token)
            except APIError as error:
                # OpenBao returns 404 for a successful empty logical LIST.
                if error.status != 404:
                    raise
                response = {}
            if response.get("data", {}).get("keys", []):
                raise LocalError("Unexpected production provider in local binary")
            self.phase = "verify-provider-rejection"
            try:
                self.api.call("POST", "relay/config", {"provider": "github"}, token=token)
            except APIError as error:
                if error.status != 400:
                    raise
            else:
                raise LocalError("Unimplemented GitHub provider was accepted")
            self.phase = "verify-policy"
            try:
                self.api.call("GET", "sys/plugins/catalog/secret", token=token)
            except APIError as error:
                if error.status != 403:
                    raise
            else:
                raise LocalError("Local user unexpectedly has catalog administration")
            if self.api.call("GET", "sys/health").get("sealed", True):
                raise LocalError("Local instance is sealed")
            self.checks = {
                "unsealed": True, "plugin_rpc": True, "entity_authentication": True,
                "empty_provider_registry": True, "github_rejected": True,
                "limited_user_policy": True,
            }
        finally:
            try:
                if token:
                    self.api.call("POST", "auth/token/revoke-self", {}, token=token)
            finally:
                self.api.call("DELETE", f"auth/userpass/users/{user}")

    def dispatch(self, request):
        action = request.get("action")
        if action == "status":
            self.api.call("GET", "sys/health")
            return {"address": ADDRESS, "container": CONTAINER, "checks": self.checks}
        if action == "check":
            self.verify()
            return {"checks": self.checks}
        if action == "password":
            password = request.get("password")
            if not isinstance(password, str) or not 16 <= len(password) <= 1024:
                raise LocalError("Local password must contain 16 to 1024 characters")
            self.api.call("POST", "auth/userpass/users/developer", {
                "password": password, "token_policies": ["relay-local"],
                "token_ttl": "1h", "token_max_ttl": "2h",
            })
            return {"username": "developer", "auth_method": "userpass", "address": ADDRESS}
        if action == "stop":
            self.stopping = True
            return {"stopped": True}
        raise LocalError("Unsupported supervisor action")

    def close(self):
        self.api.token = None
        if self.container_id:
            # Use only the exact container ID created by this supervisor.
            docker("rm", "--force", self.container_id, required=False)
            self.container_id = None


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(45)
        try:
            raw = self.rfile.readline(65537)
            if len(raw) > 65536:
                raise LocalError("Request exceeds limit")
            request = json.loads(raw)
            if not isinstance(request, dict):
                raise LocalError("Invalid request")
            response = self.server.supervisor.dispatch(request)
        except Exception:
            response = {"error": "Local operation failed; diagnostics withheld"}
        self.wfile.write(json.dumps(response).encode() + b"\n")


def serve():
    os.umask(0o077)
    secure_state()
    # Keep one supervisor per owned runtime directory, including during bootstrap.
    lock = (STATE / "supervisor.lock").open("w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock.close()
        return
    supervisor = Supervisor()
    status = STATE / "status.json"
    control_socket = STATE / "control.sock"

    def shutdown(_signum, _frame):
        supervisor.stopping = True

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try:
        supervisor.bootstrap()
        with socketserver.UnixStreamServer(str(control_socket), Handler) as server:
            server.supervisor = supervisor
            server.timeout = 0.5
            status.write_text(json.dumps({"ready": True}))
            while not supervisor.stopping:
                server.handle_request()
    except Exception as error:
        status.write_text(json.dumps({
            "error": "Local bootstrap failed; diagnostics withheld",
            "phase": supervisor.phase,
            "http_status": error.status if isinstance(error, APIError) else None,
            "failure_type": type(error).__name__,
        }))
    finally:
        supervisor.close()
        control_socket.unlink(missing_ok=True)
        lock.close()


def start():
    secure_state()
    if (STATE / "control.sock").exists():
        return control("status")
    if docker("inspect", "--format={{.Id}}", CONTAINER, required=False).returncode == 0:
        raise LocalError("Container name already exists; inspect or retire it manually")
    (STATE / "status.json").unlink(missing_ok=True)
    subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "_serve"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    deadline = time.monotonic() + 55
    while time.monotonic() < deadline:
        if (STATE / "control.sock").exists():
            return control("status")
        status_file = STATE / "status.json"
        if status_file.exists() and json.loads(status_file.read_text()).get("error"):
            status = json.loads(status_file.read_text())
            raise LocalError(
                f"Local bootstrap failed at {status['phase']} "
                f"({status['failure_type']}, HTTP {status['http_status']}); credential diagnostics withheld"
            )
        time.sleep(0.2)
    raise LocalError("Local startup did not complete within 55 seconds")


def login():
    # The supervisor creates, authenticates, and removes a disposable test user.
    # Only verification results cross the socket, never the password or token.
    response = control("check")
    return {
        "address": ADDRESS,
        "auth_method": "userpass",
        "session_retained": False,
        "checks": response["checks"],
    }


def initialize():
    status = start()
    authentication = login()
    return {
        "address": status["address"],
        "container": status["container"],
        "initialized": True,
        "mount": "relay/",
        "authentication": {
            "method": authentication["auth_method"],
            "session_retained": authentication["session_retained"],
        },
        "checks": authentication["checks"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["init", "up", "status", "check", "password", "login", "stop", "_serve"])
    args = parser.parse_args()
    try:
        if args.action == "_serve":
            serve()
            return
        if args.action == "init":
            response = initialize()
        elif args.action == "up":
            response = start()
        elif args.action == "login":
            response = login()
        elif args.action == "password":
            if not sys.stdin.isatty():
                raise LocalError("Set the local password interactively in your own terminal")
            password = getpass.getpass("Local developer password (16+ characters): ")
            if getpass.getpass("Repeat password: ") != password:
                raise LocalError("Passwords do not match")
            response = control("password", password=password)
        else:
            response = control(args.action)
            if args.action == "stop":
                deadline = time.monotonic() + 15
                while (STATE / "control.sock").exists():
                    if time.monotonic() >= deadline:
                        raise LocalError("Local container shutdown did not finish within 15 seconds")
                    time.sleep(0.1)
        print(json.dumps(response, indent=2))
    except LocalError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Local OpenBao operation interrupted", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
