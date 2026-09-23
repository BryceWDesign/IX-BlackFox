from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def test_wave15_runner_emits_green_live_network_proof(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    completed = subprocess.run(
        [sys.executable, str(root / "scripts" / "run_wave15_enterprise_identity_ci.py"), "--root", str(tmp_path)],
        cwd=root,
        env={**os.environ, "PYTHONPATH": str(root / "src")},
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    output = tmp_path / ".blackfox-artifacts" / "wave15" / "wave15-enterprise-identity-summary.json"
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert payload["upstream_count_after_denials"] == 0
    assert payload["upstream_count_after_allow"] == 1
    assert payload["upstream_count_after_revocation"] == 1
    assert payload["identity_context_digest"] == payload["subject_identity_context_digest"]
