import contextlib
import importlib.util
import io
import json
from pathlib import Path
import secrets
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "github_verify", Path(__file__).with_name("github_verify.py")
)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class GitHubVerifierTests(unittest.TestCase):
    def test_noninteractive_invocation_never_prompts_or_runs_requests(self):
        with patch.object(verifier.sys, "stdin", io.StringIO()):
            with patch.object(verifier.subprocess, "run") as child:
                with patch.object(verifier.getpass, "getpass") as prompt:
                    with contextlib.redirect_stderr(io.StringIO()):
                        self.assertEqual(verifier.main(), 1)
        self.assertEqual(child.call_count, 0)
        self.assertEqual(prompt.call_count, 0)

    def test_credentials_only_enter_child_stdin_and_not_output_or_arguments(self):
        client_secret = secrets.token_urlsafe(32)
        base = secrets.token_urlsafe(32)
        report = {"passed": True, "cleanup_complete": True, "production_eligible": False}

        def child(argv, **options):
            self.assertTrue(
                client_secret not in str(argv) and base not in str(argv),
                "Credentials were put in command arguments",
            )
            payload = json.loads(options["input"])
            self.assertTrue(
                payload["config"]["client_secret"] == client_secret
                and payload["config"]["base_token"] == base,
                "Credentials were not passed through stdin",
            )
            return subprocess.CompletedProcess(argv, 0, json.dumps(report).encode())

        output = io.StringIO()
        with patch.object(verifier.sys.stdin, "isatty", return_value=True):
            with patch("builtins.input", side_effect=["test-client", "77", "101", "202"]):
                with patch.object(verifier.getpass, "getpass", side_effect=[client_secret, base]):
                    with patch.object(verifier.subprocess, "run", side_effect=child):
                        with contextlib.redirect_stdout(output):
                            self.assertEqual(verifier.main(), 0)
        self.assertTrue(
            client_secret not in output.getvalue() and base not in output.getvalue(),
            "Credentials were reflected in verifier output",
        )

    def test_hidden_input_failure_stops_before_subprocess(self):
        with patch.object(verifier.sys.stdin, "isatty", return_value=True):
            with patch("builtins.input", side_effect=["test-client", "77", "101", "202"]):
                with patch.object(verifier.getpass, "getpass", side_effect=verifier.getpass.GetPassWarning):
                    with patch.object(verifier.subprocess, "run") as child:
                        with contextlib.redirect_stdout(io.StringIO()):
                            with contextlib.redirect_stderr(io.StringIO()):
                                self.assertEqual(verifier.main(), 1)
        self.assertEqual(child.call_count, 0)
