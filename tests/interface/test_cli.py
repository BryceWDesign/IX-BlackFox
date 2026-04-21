from __future__ import annotations

import json
from pathlib import Path

from ix_blackfox.interface.cli import main


def test_cli_run_json_returns_zero_and_prints_report(capsys, tmp_path: Path) -> None:
    code = main(
        [
            "run",
            "--prompt",
            "Fix the failing tests and patch the code.",
            "--kind",
            "programming",
            "--root-dir",
            str(tmp_path),
            "--json",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 0
    assert payload["pack_name"] == "programming"
    assert payload["status"] == "passed"
