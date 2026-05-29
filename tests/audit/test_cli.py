from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from datetime import UTC, datetime
from pathlib import Path

from ix_blackfox.audit import (
    WAVE8_CI_REPORT_PATH,
    AuditDisposition,
    AuditSubject,
    create_human_approval_signoff,
    default_wave9_policy_pack,
)
from ix_blackfox.audit.cli import main as audit_main

_HEAD_SHA = "abc123def456"
_GENERATED_AT = "2026-01-01T00:00:00+00:00"
_DEFAULT_SCOPE = (
    "ai-assisted code-change governance audit for policy, evidence, "
    "repository intelligence, and human review"
)
_REPOSITORY_SCOPE = "repository intelligence audit"


def test_audit_cli_report_writes_blocked_report_without_evidence_or_human_approval(tmp_path: Path) -> None:
    output_path = tmp_path / "wave9" / "blocked-report.json"
    buffer = io.StringIO()

    with redirect_stdout(buffer):
        exit_code = audit_main(
            [
                "report",
                "--root",
                str(tmp_path),
                "--repository",
                "IX-BlackFox",
                "--head-sha",
                _HEAD_SHA,
                "--generated-at",
                _GENERATED_AT,
                "--output",
                str(output_path),
            ]
        )

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    summary = buffer.getvalue()

    assert exit_code == 0
    assert payload["schema_version"] == "wave9.compliance_audit_attestation.v1"
    assert payload["wave"] == 9
    assert payload["subject"]["head_sha"] == _HEAD_SHA
    assert payload["disposition"] == AuditDisposition.BLOCKED.value
    assert payload["evidence_manifest"]["artifact_count"] == 0
    assert payload["signoff_authority"]["has_authoritative_human_approval"] is False
    assert payload["report_digest"]
    assert "Wave 9 governance report generated" in summary
    assert "Disposition: blocked" in summary


def test_audit_cli_report_can_emit_audit_ready_json_with_known_wave8_evidence_and_human_signoff(
    tmp_path: Path,
) -> None:
    _write_known_wave8_report(tmp_path)
    signoff_file = _write_matching_human_signoff_file(tmp_path)
    output_path = tmp_path / "wave9" / "audit-ready-report.json"
    buffer = io.StringIO()

    with redirect_stdout(buffer):
        exit_code = audit_main(
            [
                "report",
                "--root",
                str(tmp_path),
                "--repository",
                "IX-BlackFox",
                "--head-sha",
                _HEAD_SHA,
                "--scope",
                _REPOSITORY_SCOPE,
                "--claim",
                "repository intelligence impact architecture_memory",
                "--signoff-file",
                str(signoff_file),
                "--generated-at",
                _GENERATED_AT,
                "--output",
                str(output_path),
                "--json",
            ]
        )

    printed_payload = json.loads(buffer.getvalue())
    written_payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert printed_payload == written_payload
    assert written_payload["disposition"] == AuditDisposition.AUDIT_READY.value
    assert written_payload["evidence_manifest"]["artifact_count"] == 1
    assert written_payload["signoff_authority"]["has_authoritative_human_approval"] is True
    assert written_payload["signoff_authority"]["authoritative_human_approval_ids"] == [
        "signoff:human-release-reviewer"
    ]
    assert written_payload["control_evaluation"]["blocked_count"] == 0


def test_audit_cli_validate_accepts_exported_report_and_rejects_tampered_digest(
    tmp_path: Path,
) -> None:
    report_path = _write_blocked_report(tmp_path)
    buffer = io.StringIO()

    with redirect_stdout(buffer):
        exit_code = audit_main(["validate", "--report", str(report_path), "--json"])

    validation = json.loads(buffer.getvalue())
    assert exit_code == 0
    assert validation["passed"] is True
    assert validation["issue_count"] == 0

    tampered = json.loads(report_path.read_text(encoding="utf-8"))
    tampered["disposition"] = "audit_ready"
    tampered_path = tmp_path / "wave9" / "tampered-report.json"
    tampered_path.write_text(json.dumps(tampered, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    buffer = io.StringIO()

    with redirect_stdout(buffer):
        tampered_exit_code = audit_main(["validate", "--report", str(tampered_path), "--json"])

    tampered_validation = json.loads(buffer.getvalue())
    assert tampered_exit_code == 1
    assert tampered_validation["passed"] is False
    assert "report_digest does not match" in tampered_validation["issues"][0]


def test_audit_cli_gate_blocks_blocked_report_and_passes_audit_ready_report(tmp_path: Path) -> None:
    blocked_report_path = _write_blocked_report(tmp_path / "blocked")
    blocked_buffer = io.StringIO()

    with redirect_stdout(blocked_buffer):
        blocked_exit_code = audit_main(["gate", "--report", str(blocked_report_path), "--json"])

    blocked_gate = json.loads(blocked_buffer.getvalue())
    assert blocked_exit_code == 1
    assert blocked_gate["passed"] is False
    assert blocked_gate["disposition"] == AuditDisposition.BLOCKED.value

    _write_known_wave8_report(tmp_path / "ready")
    signoff_file = _write_matching_human_signoff_file(tmp_path / "ready")
    ready_report_path = tmp_path / "ready" / "wave9" / "audit-ready-report.json"
    assert (
        audit_main(
            [
                "report",
                "--root",
                str(tmp_path / "ready"),
                "--repository",
                "IX-BlackFox",
                "--head-sha",
                _HEAD_SHA,
                "--scope",
                _REPOSITORY_SCOPE,
                "--claim",
                "repository intelligence impact architecture_memory",
                "--signoff-file",
                str(signoff_file),
                "--generated-at",
                _GENERATED_AT,
                "--output",
                str(ready_report_path),
            ]
        )
        == 0
    )
    ready_buffer = io.StringIO()

    with redirect_stdout(ready_buffer):
        ready_exit_code = audit_main(["gate", "--report", str(ready_report_path), "--json"])

    ready_gate = json.loads(ready_buffer.getvalue())
    assert ready_exit_code == 0
    assert ready_gate["passed"] is True
    assert ready_gate["disposition"] == AuditDisposition.AUDIT_READY.value


def _write_known_wave8_report(root: Path) -> Path:
    report_path = root / WAVE8_CI_REPORT_PATH
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(
            {
                "schema_version": "wave8.repository_intelligence_ci_report.v1",
                "head_sha": _HEAD_SHA,
                "passed": True,
                "run_id": "wave8:test",
                "report_digest": "a" * 64,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return report_path


def _write_matching_human_signoff_file(root: Path) -> Path:
    subject = AuditSubject(
        repository="IX-BlackFox",
        head_sha=_HEAD_SHA,
        scope=_REPOSITORY_SCOPE,
        metadata={"cli": True},
    )
    policy_pack = default_wave9_policy_pack()
    signoff = create_human_approval_signoff(
        signoff_id="signoff:human-release-reviewer",
        reviewer_id="reviewer:human",
        subject=subject,
        policy_pack=policy_pack,
        role="release-reviewer",
        signed_at=datetime(2026, 1, 1, tzinfo=UTC),
        notes="Approved Wave 9 audit evidence for CLI test subject.",
    )
    signoff_file = root / "signoffs" / "human-signoff.json"
    signoff_file.parent.mkdir(parents=True, exist_ok=True)
    signoff_file.write_text(
        json.dumps([signoff.to_dict()], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return signoff_file


def _write_blocked_report(root: Path) -> Path:
    output_path = root / "wave9" / "blocked-report.json"
    exit_code = audit_main(
        [
            "report",
            "--root",
            str(root),
            "--repository",
            "IX-BlackFox",
            "--head-sha",
            _HEAD_SHA,
            "--generated-at",
            _GENERATED_AT,
            "--output",
            str(output_path),
        ]
    )
    assert exit_code == 0
    return output_path
