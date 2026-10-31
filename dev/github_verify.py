#!/usr/bin/env python3
"""Human-only GitHub scoped-UAT acceptance; credentials never leave process pipes."""

import getpass
import json
from pathlib import Path
import subprocess
import sys
import warnings


def main():
    if not sys.stdin.isatty():
        print("Run this verifier yourself in an interactive terminal.", file=sys.stderr)
        return 1
    print(
        "Use an isolated GitHub App with expiring UATs and two private test repositories.\n"
        "The base UAT must read both repositories, contents, and Actions workflows.\n"
        "Only known child tokens will be revoked. A lost creation response cannot be\n"
        "recovered; retire the isolated authorization yourself if cleanup is uncertain.\n"
        "Do not paste credentials or credential-bearing diagnostics into chat."
    )
    try:
        warnings.simplefilter("error", getpass.GetPassWarning)
        client_id = input("GitHub App client ID: ").strip()
        target_id = int(input("Repository owner numeric ID: "))
        allowed_id = int(input("Allowed private repository numeric ID: "))
        outside_id = int(input("Excluded private repository numeric ID: "))
        client_secret = getpass.getpass("GitHub App client secret (hidden): ")
        base_token = getpass.getpass("Expiring non-scoped user access token (hidden): ")
        payload = {
            "config": {
                "client_id": client_id, "client_secret": client_secret,
                "base_token": base_token, "entity_id": "human-acceptance",
            },
            "role": {
                "target_id": target_id, "repository_ids": [allowed_id],
                "permissions": {"contents": "read"},
            },
            "outside_repository_id": outside_id,
        }
        binary = Path(__file__).resolve().parents[1] / "dist/relay-github-verify"
        result = subprocess.run(
            [str(binary)], input=json.dumps(payload).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=390,
        )
        # Project verifier output is a deliberately credential-free report.
        report = json.loads(result.stdout)
        print(json.dumps(report, indent=2))
        return 0 if result.returncode == 0 else 1
    except (OSError, ValueError, subprocess.TimeoutExpired, getpass.GetPassWarning):
        print("Verifier failed; diagnostics withheld. Cleanup may require human action.", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("Verifier interrupted. Cleanup may require human action.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
