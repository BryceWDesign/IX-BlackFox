from __future__ import annotations

import json
import sys
from dataclasses import replace

from ix_blackfox.runtime.authoring_repair import (
    AuthoredRepairStatus,
    StaticPatchProposalProvider,
)
from ix_blackfox.runtime.control_plane import (
    AuthoredEngineeringControlPlaneReport,
    EngineeringControlPlane,
)
from ix_blackfox.runtime.wave3_acceptance import (
    Wave3AcceptanceFindingCode,
    Wave3AcceptanceReport,
    Wave3AcceptanceStatus,
    Wave3AcceptanceValidator,
)


def test_wave3_acceptance_passes_for_authored_wave2_success(tmp_path) -> None:
    workspace = tmp_path
    _make_workspace_marker(workspace)
    _write(workspace, "src/example.py", "def add(a, b):\n    return a - b\n")
    _write(
        workspace,
        "tests/test_example.py",
        "from pathlib import Path\n\n"
        "def test_patch_changed_source():\n"
        "    text = Path('src/example.py').read_text(encoding='utf-8')\n"
        "    assert 'return a + b' in text\n",
    )

    control_plane = EngineeringControlPlane.from_workspace(
        workspace_root=workspace,
        artifact_root=workspace,
        test_command=(sys.executable, "-m", "pytest", "-q", "tests"),
        allowed_test_executables=(sys.executable, "python", "python3", "py", "pytest"),
        test_timeout_seconds=30,
    )

    authored_report = control_plane.run_authored_programming_repair(
        task_id="task-add",
        run_id="run-add",
        objective="Repair addition behavior.",
        include_paths=("src", "tests"),
        proposal_provider=StaticPatchProposalProvider(
            responses=(
                _proposal_json(
                    path="src/example.py",
                    before_text="return a - b",
                    after_text="return a + b",
                ),
            )
        ),
        raw_test_output=_authoring_failure_text(),
        authoring_test_return_code=1,
        test_command=(sys.executable, "-m", "pytest", "-q", "tests"),
    )

    acceptance = Wave3AcceptanceValidator().validate(authored_report)

    assert acceptance.status is Wave3AcceptanceStatus.PASSED
    assert acceptance.passed
    assert acceptance.selected_patch_id == authored_report.selected_patch_id
    assert acceptance.authoring_chain_digest == authored_report.authored_repair_report.receipt_snapshot.latest_chain_digest
    assert Wave3AcceptanceFindingCode.ACCEPTANCE_PASSED.value in acceptance.finding_codes
    assert Wave3AcceptanceFindingCode.WAVE2_SUCCEEDED.value in acceptance.finding_codes
    assert Wave3AcceptanceFindingCode.POLICY_ALLOWED.value in acceptance.finding_codes


def test_wave3_acceptance_not_executed_when_no_candidate(tmp_path) -> None:
    workspace = tmp_path
    _make_workspace_marker(workspace)
    _write(workspace, "src/example.py", "VALUE = 1\n")

    control_plane = EngineeringControlPlane.from_workspace(
        workspace_root=workspace,
        artifact_root=workspace,
        test_command=(sys.executable, "-m", "pytest", "-q"),
        allowed_test_executables=(sys.executable, "python", "python3", "py", "pytest"),
    )

    authored_report = control_plane.run_authored_programming_repair(
        task_id="task-none",
        run_id="run-none",
        objective="Repair reported behavior.",
        include_paths=("src",),
        raw_test_output=_authoring_failure_text(),
        authoring_test_return_code=1,
    )

    acceptance = Wave3AcceptanceValidator().validate(authored_report)

    assert authored_report.authored_repair_report.status is AuthoredRepairStatus.NO_CANDIDATE
    assert acceptance.status is Wave3AcceptanceStatus.NOT_EXECUTED
    assert not acceptance.passed
    assert Wave3AcceptanceFindingCode.AUTHORING_NO_CANDIDATE.value in acceptance.finding_codes
    assert Wave3AcceptanceFindingCode.WAVE2_REPORT_MISSING.value in acceptance.finding_codes


def test_wave3_acceptance_requires_review_when_authoring_requires_review(tmp_path) -> None:
    workspace = tmp_path
    _make_workspace_marker(workspace)
    _write(workspace, "tests/test_example.py", "assert True\n")

    control_plane = EngineeringControlPlane.from_workspace(
        workspace_root=workspace,
        artifact_root=workspace,
        test_command=(sys.executable, "-m", "pytest", "-q", "tests"),
        allowed_test_executables=(sys.executable, "python", "python3", "py", "pytest"),
    )

    authored_report = control_plane.run_authored_programming_repair(
        task_id="task-review",
        run_id="run-review",
        objective="Add test coverage.",
        include_paths=("tests",),
        proposal_provider=StaticPatchProposalProvider(
            responses=(
                _proposal_json(
                    path="tests/test_example.py",
                    before_text="assert True",
                    after_text="assert True\nassert 1 == 1",
                ),
            )
        ),
        raw_test_output=_authoring_failure_text(),
        authoring_test_return_code=1,
    )

    acceptance = Wave3AcceptanceValidator().validate(authored_report)

    assert acceptance.status is Wave3AcceptanceStatus.REQUIRES_REVIEW
    assert acceptance.requires_review
    assert Wave3AcceptanceFindingCode.AUTHORING_REQUIRES_REVIEW.value in acceptance.finding_codes
    assert Wave3AcceptanceFindingCode.WAVE2_REPORT_MISSING.value in acceptance.finding_codes


def test_wave3_acceptance_blocks_when_authoring_blocked(tmp_path) -> None:
    workspace = tmp_path
    _make_workspace_marker(workspace)
    _write(workspace, "config/api_token.txt", "old\n")

    control_plane = EngineeringControlPlane.from_workspace(
        workspace_root=workspace,
        artifact_root=workspace,
        test_command=(sys.executable, "-m", "pytest", "-q"),
        allowed_test_executables=(sys.executable, "python", "python3", "py", "pytest"),
    )

    authored_report = control_plane.run_authored_programming_repair(
        task_id="task-blocked",
        run_id="run-blocked",
        objective="Repair token file.",
        include_paths=("config",),
        proposal_provider=StaticPatchProposalProvider(
            responses=(
                _proposal_json(
                    path="config/api_token.txt",
                    before_text="old",
                    after_text="new",
                ),
            )
        ),
        raw_test_output=_authoring_failure_text(),
        authoring_test_return_code=1,
    )

    acceptance = Wave3AcceptanceValidator().validate(authored_report)

    assert acceptance.status is Wave3AcceptanceStatus.BLOCKED
    assert acceptance.blocked
    assert Wave3AcceptanceFindingCode.AUTHORING_BLOCKED.value in acceptance.finding_codes


def test_wave3_acceptance_fails_when_authoring_receipt_chain_is_tampered(tmp_path) -> None:
    authored_report = _passing_authored_report(tmp_path)

    original_authored = authored_report.authored_repair_report
    original_snapshot = original_authored.receipt_snapshot
    tampered_receipts = list(original_snapshot.receipts)
    tampered_first = replace(
        tampered_receipts[0],
        parent_chain_digest="0" * 64,
    )
    tampered_receipts[0] = tampered_first
    tampered_snapshot = type(original_snapshot)(receipts=tuple(tampered_receipts))
    tampered_authored = replace(
        original_authored,
        receipt_snapshot=tampered_snapshot,
    )
    tampered_report = replace(
        authored_report,
        authored_repair_report=tampered_authored,
    )

    acceptance = Wave3AcceptanceValidator().validate(tampered_report)

    assert acceptance.status is Wave3AcceptanceStatus.FAILED
    assert Wave3AcceptanceFindingCode.AUTHORING_RECEIPT_CHAIN_INVALID.value in acceptance.finding_codes


def test_wave3_acceptance_fails_when_wave2_metadata_does_not_match_selected_patch(tmp_path) -> None:
    authored_report = _passing_authored_report(tmp_path)

    assert authored_report.wave2_report is not None

    tampered_wave2 = replace(
        authored_report.wave2_report,
        metadata={
            **dict(authored_report.wave2_report.metadata),
            "selected_patch_id": "patch-wrong",
        },
    )
    tampered_report = replace(
        authored_report,
        wave2_report=tampered_wave2,
    )

    acceptance = Wave3AcceptanceValidator().validate(tampered_report)

    assert acceptance.status is Wave3AcceptanceStatus.FAILED
    assert Wave3AcceptanceFindingCode.WAVE2_SELECTED_PATCH_MISMATCH.value in acceptance.finding_codes


def test_wave3_acceptance_fails_when_wave2_report_missing_after_authored_success(tmp_path) -> None:
    authored_report = _passing_authored_report(tmp_path)
    missing_wave2 = AuthoredEngineeringControlPlaneReport(
        run_id=authored_report.run_id,
        task_id=authored_report.task_id,
        authored_repair_report=authored_report.authored_repair_report,
        wave2_report=None,
        metadata=authored_report.metadata,
    )

    acceptance = Wave3AcceptanceValidator().validate(missing_wave2)

    assert acceptance.status is Wave3AcceptanceStatus.FAILED
    assert Wave3AcceptanceFindingCode.WAVE2_REPORT_MISSING.value in acceptance.finding_codes
    assert Wave3AcceptanceFindingCode.WAVE2_NOT_EXECUTED.value in acceptance.finding_codes


def test_wave3_acceptance_report_round_trip_preserves_payload(tmp_path) -> None:
    authored_report = _passing_authored_report(tmp_path)
    acceptance = Wave3AcceptanceValidator().validate(authored_report)

    restored = Wave3AcceptanceReport.from_dict(acceptance.to_dict())

    assert restored.status is acceptance.status
    assert restored.run_id == acceptance.run_id
    assert restored.task_id == acceptance.task_id
    assert restored.selected_patch_id == acceptance.selected_patch_id
    assert restored.authoring_chain_digest == acceptance.authoring_chain_digest
    assert restored.finding_codes == acceptance.finding_codes
    assert restored.digest == acceptance.digest


def _passing_authored_report(tmp_path):
    workspace = tmp_path
    _make_workspace_marker(workspace)
    _write(workspace, "src/example.py", "before\n")
    _write(
        workspace,
        "tests/test_example.py",
        "from pathlib import Path\n\n"
        "def test_patch_changed_source():\n"
        "    assert Path('src/example.py').read_text(encoding='utf-8') == 'after\\n'\n",
    )

    control_plane = EngineeringControlPlane.from_workspace(
        workspace_root=workspace,
        artifact_root=workspace,
        test_command=(sys.executable, "-m", "pytest", "-q", "tests"),
        allowed_test_executables=(sys.executable, "python", "python3", "py", "pytest"),
        test_timeout_seconds=30,
    )

    return control_plane.run_authored_programming_repair(
        task_id="task-pass",
        run_id="run-pass",
        objective="Repair file content.",
        include_paths=("src", "tests"),
        raw_proposal_responses=(
            _proposal_json(
                path="src/example.py",
                before_text="before",
                after_text="after",
            ),
        ),
        raw_test_output=_authoring_failure_text(),
        authoring_test_return_code=1,
        test_command=(sys.executable, "-m", "pytest", "-q", "tests"),
    )


def _make_workspace_marker(workspace) -> None:
    (workspace / ".blackfox-workspace").write_text(
        "reserved IX-BlackFox test workspace\n",
        encoding="utf-8",
    )


def _write(workspace, path: str, text: str) -> None:
    file_path = workspace / path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(text, encoding="utf-8")


def _authoring_failure_text() -> str:
    return """
============================= FAILURES =============================
____________________________ test_patch_changed_source ____________________________

    def test_patch_changed_source():
>       assert False
E       assert False

tests/test_example.py:4: AssertionError
====================== short test summary info ======================
FAILED tests/test_example.py::test_patch_changed_source - assert False
=========================== 1 failed in 0.09s =======================
""".strip()


def _proposal_json(
    *,
    path: str,
    before_text: str,
    after_text: str,
    confidence: float = 0.72,
) -> str:
    if not after_text.endswith("\n"):
        after_text = after_text + "\n"

    return json.dumps(
        {
            "schema_version": "wave3.patch_authoring_response.v1",
            "proposal_id": "proposal-1",
            "objective_summary": "Repair the failing behavior.",
            "reasoning_summary": "The proposed source change aligns with the failure evidence.",
            "confidence": confidence,
            "assumptions": [
                "The compiler must verify before_text against the current workspace.",
            ],
            "risk_notes": [
                "The patch must still pass policy and Wave 2 execution.",
            ],
            "expected_tests": [
                "The targeted behavior test should pass after governed execution.",
            ],
            "mutations": [
                {
                    "mutation_id": "mutation-1",
                    "mutation_type": "replace_text",
                    "path": path,
                    "before_text": before_text,
                    "after_text": after_text,
                    "rationale": "Repair source behavior.",
                }
            ],
        },
        sort_keys=True,
    )
