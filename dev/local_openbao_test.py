import importlib.util
import io
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

spec = importlib.util.spec_from_file_location(
    "local_openbao", Path(__file__).with_name("local_openbao.py")
)
local = importlib.util.module_from_spec(spec)
spec.loader.exec_module(local)


class LocalOpenBaoTests(unittest.TestCase):
    def test_login_uses_supervisor_check_without_retaining_a_session(self):
        checks = {"entity_authentication": True, "plugin_rpc": True}
        with patch.object(local, "control", return_value={"checks": checks}) as control:
            response = local.login()
        control.assert_called_once_with("check")
        self.assertEqual(response, {
            "address": local.ADDRESS, "auth_method": "userpass",
            "session_retained": False, "checks": checks,
        })

    def test_login_unavailable_does_not_report_success(self):
        with patch.object(local, "control", side_effect=local.LocalError("Not running")):
            with self.assertRaises(local.LocalError):
                local.login()

    def test_initialize_starts_then_authenticates_and_uses_fresh_checks(self):
        steps = []

        def start():
            steps.append("start")
            return {"address": local.ADDRESS, "container": local.CONTAINER, "checks": {}}

        def request(action):
            steps.append(action)
            return {"checks": {"entity_authentication": True}}

        with patch.object(local, "start", side_effect=start):
            with patch.object(local, "control", side_effect=request):
                response = local.initialize()
        self.assertEqual(steps, ["start", "check"])
        self.assertEqual(response["checks"], {"entity_authentication": True})
        self.assertTrue(response["initialized"])
        self.assertFalse(response["authentication"]["session_retained"])

    def test_initialize_failure_does_not_return_partial_success(self):
        for stage in ("start", "check"):
            with self.subTest(stage=stage):
                with patch.object(
                    local, "start",
                    return_value={"address": local.ADDRESS, "container": local.CONTAINER},
                    side_effect=local.LocalError("Startup failed") if stage == "start" else None,
                ):
                    with patch.object(
                        local, "control", side_effect=local.LocalError("Check failed")
                    ) as control:
                        with self.assertRaises(local.LocalError):
                            local.initialize()
                self.assertEqual(control.call_count, 0 if stage == "start" else 1)

    def test_api_errors_do_not_reflect_upstream_body(self):
        disposable = secrets.token_urlsafe(32)
        error = urllib.error.HTTPError(
            local.ADDRESS, 400, "rejected", {}, io.BytesIO(disposable.encode())
        )
        api = local.API()
        with patch.object(api.opener, "open", side_effect=error):
            with self.assertRaises(local.APIError) as result:
                api.call("GET", "test")
        self.assertTrue(disposable not in str(result.exception), "Credential diagnostics were reflected")
        self.assertEqual(result.exception.status, 400)

    def test_connection_reset_is_retryable_without_error_reflection(self):
        disposable = secrets.token_urlsafe(32)
        api = local.API()
        captured = None
        with patch.object(api.opener, "open", side_effect=ConnectionResetError(disposable)):
            try:
                api.call("GET", "sys/init")
            except Exception as error:
                captured = error
        self.assertTrue(isinstance(captured, local.LocalError), "Connection failure was not sanitized")
        self.assertTrue(disposable not in str(captured), "Credential diagnostics were reflected")

    def test_supervisor_has_no_token_export_action(self):
        supervisor = local.Supervisor()
        supervisor.api.token = secrets.token_urlsafe(32)
        with patch.object(supervisor.api, "call", return_value={}):
            response = supervisor.dispatch({"action": "status"})
        self.assertEqual(set(response), {"address", "container", "checks"})
        with self.assertRaises(local.LocalError):
            supervisor.dispatch({"action": "token"})

    def test_runtime_directory_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            target = parent / "target"
            target.mkdir(mode=0o700)
            link = parent / "link"
            link.symlink_to(target)
            with self.assertRaises(local.LocalError):
                local.secure_state(link)

    def test_password_request_returns_metadata_only(self):
        supervisor = local.Supervisor()
        disposable = secrets.token_urlsafe(32)
        with patch.object(supervisor.api, "call", return_value={}) as call:
            response = supervisor.dispatch({"action": "password", "password": disposable})
        self.assertEqual(set(response), {"username", "auth_method", "address"})
        # Do not use mock assertion helpers that dump credential-bearing arguments.
        self.assertEqual(call.call_count, 1)
        self.assertTrue(disposable not in str(response), "Password was reflected")

    def test_short_password_rejected_before_api_call(self):
        supervisor = local.Supervisor()
        with patch.object(supervisor.api, "call") as call:
            with self.assertRaises(local.LocalError):
                supervisor.dispatch({"action": "password", "password": ""})
        self.assertEqual(call.call_count, 0)

    def test_redirect_handler_does_not_forward_authentication(self):
        self.assertIsNone(local.NoRedirect().redirect_request(
            None, None, 302, "redirect", {}, "https://example.invalid"
        ))


    def test_live_protocol_empty_list_and_top_level_help(self):
        supervisor = local.Supervisor()
        cleaned = []

        def request(method, path, data=None, token=None):
            if path.startswith("auth/userpass/login/"):
                return {"auth": {"entity_id": "test-entity", "client_token": secrets.token_urlsafe(32)}}
            if path == "relay/?help=1":
                return {"help": "Relay plugin help"}
            if path == "relay/providers":
                raise local.APIError(404)
            if path == "relay/config":
                raise local.APIError(400)
            if path == "sys/plugins/catalog/secret":
                raise local.APIError(403)
            if path == "sys/health":
                return {"sealed": False}
            if method == "DELETE" or path == "auth/token/revoke-self":
                cleaned.append(path)
            return {}

        with patch.object(supervisor.api, "call", side_effect=request):
            supervisor.verify()
        self.assertTrue(all(supervisor.checks.values()))
        self.assertEqual(len(cleaned), 2)

    def test_smoke_failure_still_cleans_up_credentials(self):
        supervisor = local.Supervisor()
        cleaned = []

        def request(method, path, data=None, token=None):
            if path.startswith("auth/userpass/login/"):
                return {"auth": {"entity_id": "test-entity", "client_token": secrets.token_urlsafe(32)}}
            if path == "relay/?help=1":
                return {"help": "Relay plugin help"}
            if path == "relay/providers":
                return {"data": {"keys": ["unexpected"]}}
            if method == "DELETE" or path == "auth/token/revoke-self":
                cleaned.append(path)
            return {}

        with patch.object(supervisor.api, "call", side_effect=request):
            with self.assertRaises(local.LocalError):
                supervisor.verify()
        self.assertEqual(len(cleaned), 2)


if __name__ == "__main__":
    unittest.main()
