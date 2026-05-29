from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

from ix_blackfox.audit import WAVE8_CI_REPORT_PATH, AuditDisposition
from ix_blackfox.interface import main

_HEAD_SHA = "abc123def456"


def test_top_level_cli_routes_audit_report_command(tmp_path: Path) -> None:
    _write_known_wave8_report(tmp_path)
    output_path = tmp_path / "artifacts" / "wave9-report.json"
    buffer = io.StringIO()

    with redirect_stdout(buffer):
        exit_code = main(
            [
                "audit",
                "report",
                "--root",
                str(tmp_path),
                "--repository",
                "IX-BlackFox",
                "--head-sha",
                _HEAD_SHA,
                "--scope",
                "repository intelligence diagnostic audit",
                "--claim",
                "repository intelligence impact architecture_memory",
                "--no-require-human-approval",
                "--generated-at",
                "2026-01-01T00:00:00+00:00",
                "--output",
                str(output_path),
                "--json",
            ]
        )

    payload = json.loads(buffer.getvalue())
    written_payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert payload == written_payload
    assert payload["wave"] == 9
    assert payload["disposition"] == AuditDisposition.AUDIT_READY.value
    assert payload["evidence_manifest"]["artifact_count"] == 1
    assert payload["metadata"]["cli"] is True


def test_top_level_cli_routes_audit_validate_command(tmp_path: Path) -> None:
    _write_known_wave8_report(tmp_path)
    report_path = tmp_path / "artifacts" / "wave9-report.json"
    assert (
        main(
            [
                "audit",
                "report",
                "--root",
                str(tmp_path),
                "--head-sha",
                _HEAD_SHA,
                "--scope",
                "repository intelligence diagnostic audit",
                "--claim",
                "repository intelligence impact architecture_memory",
                "--no-require-human-approval",
                "--generated-at",
                "2026-01-01T00:00:00+00:00",
                "--output",
                str(report_path),
            ]
        )
        == 0
    )
    buffer = io.StringIO()

    with redirect_stdout(buffer):
        exit_code = main(["audit", "validate", "--report", str(report_path), "--json"])

    validation = json.loads(buffer.getvalue())
    assert exit_code == 0
    assert validation["passed"] is True
    assert validation["disposition"] == AuditDisposition.AUDIT_READY.value


def _write_known_wave8_report(root: Path) -> Path:
    report_path = root / WAVE8_CI_REPORT_PATH
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(
            {
                "schema_version": "wave8.repository_intelligence_ci_report.v1",
                "head_sha": _HEAD_SHA,
                "passed": True,
                "run_id": "wave8:routing-test",
                "report_digest": "a" * 64,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return report_path
