from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW_PATH = _REPO_ROOT / ".github" / "workflows" / "wave5-pr-gate.yml"


def test_wave5_pr_gate_workflow_exists_and_is_manual_operator_gate() -> None:
    workflow = _WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "name: IX-BlackFox Wave 5 PR Gate" in workflow
    assert "workflow_dispatch:" in workflow
    assert "evidence_pack_path:" in workflow
    assert "ci_evidence_path:" in workflow
    assert "required_checks:" in workflow
    assert "push:" not in workflow
    assert "pull_request:" not in workflow


def test_wave5_pr_gate_workflow_uses_read_only_permissions() -> None:
    workflow = _WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "permissions:" in workflow
    assert "contents: read" in workflow
    assert "actions: read" in workflow
    assert "pull-requests: read" in workflow
    assert "contents: write" not in workflow
    assert "pull-requests: write" not in workflow
    assert "actions: write" not in workflow


def test_wave5_pr_gate_workflow_runs_real_cli_gate_without_synthesizing_reviews() -> None:
    workflow = _WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "python -m ix_blackfox.interface.cli workflow pr-gate" in workflow
    assert '--evidence-pack "$EVIDENCE_PACK_PATH"' in workflow
    assert '--ci-evidence "$CI_EVIDENCE_PATH"' in workflow
    assert '--required-check "$check_name"' in workflow
    assert "approval_id" not in workflow
    assert "reviewer_kind" not in workflow
    assert "decision: approved" not in workflow


def test_wave5_pr_gate_workflow_preserves_decision_artifact_for_review() -> None:
    workflow = _WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "wave5-pr-gate-decision.json" in workflow
    assert "actions/upload-artifact@v4" in workflow
    assert "if: always()" in workflow
