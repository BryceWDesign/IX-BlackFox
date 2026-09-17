from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_wave14_runner_emits_real_network_proof(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    completed = subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "run_wave14_live_gateway_ci.py"),
            "--root",
            str(tmp_path),
        ],
        cwd=root,
        env={**__import__("os").environ, "PYTHONPATH": str(root / "src")},
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    output = tmp_path / ".blackfox-artifacts" / "wave14" / "wave14-live-authority-gateway-summary.json"
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["wave"] == "14"
    assert payload["passed"] is True
    assert payload["proof"]["scope_block_upstream_count"] == 0
    assert payload["proof"]["evidence_block_upstream_count"] == 0
    assert payload["proof"]["replay_block_http_status"] == 409
    assert payload["proof"]["replay_block_upstream_count"] == 1
    assert payload["proof"]["api_allow_upstream_count"] == 2
    assert payload["proof"]["receipt_chain"]["passed"] is True
