from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def test_wave16_real_socket_runner_and_public_artifacts(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [
            sys.executable,
            str(root / "scripts/run_wave16_crypto_authority_ci.py"),
            "--root",
            str(tmp_path),
        ],
        env={**os.environ, "PYTHONPATH": str(root / "src")},
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    payload = json.loads(result.stdout)
    assert payload["passed"] and all(payload["checks"].values())
    assert payload["receipt_count"] == 9 and payload["upstream_invocation_count"] == 2
    assert all(status == "NOT_RUN" for status in payload["external_services"].values())
    output = tmp_path / ".blackfox-artifacts/wave16"
    assert {p.name for p in output.iterdir()} == {
        "authority-bundle.json",
        "external-checkpoint.json",
        "trust-policy.json",
        "wave16-crypto-authority-summary.json",
    }
    assert not list(tmp_path.rglob("*.pem")) and not list(tmp_path.rglob("*.sqlite3"))
