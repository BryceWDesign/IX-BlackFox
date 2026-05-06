from __future__ import annotations

import json
import sys

import pytest

from ix_blackfox.runtime.authoring_repair import StaticPatchProposalProvider
from ix_blackfox.runtime.control_plane import EngineeringControlPlane
from ix_blackfox.runtime.wave3_acceptance import (
    Wave3AcceptanceStatus,
    Wave3AcceptanceValidator,
)
from ix_blackfox.runtime.wave3_bundle import (
    Wave3EvidenceArtifact,
    Wave3EvidenceArtifactKind,
    Wave3EvidencePackageManifest,
    Wave3EvidencePackageWriter,
    Wave3EvidencePackageWriterConfig,
)


def test_wave3_evidence_package_writer_persists_all_core_artifacts(tmp_path) -> None:
    authored_report = _passing_authored_report(tmp_path)
    acceptance_report = Wave3AcceptanceValidator().validate(authored_report)

    writer = Wave3EvidencePackageWriter(root_dir=tmp_path / "packages")
    manifest = writer.write(
        authored_report=authored_report,
        acceptance_report=acceptance_report,
        metadata={"test": "wave3_bundle"},
    )

    assert manifest.acceptance_status == Wave3AcceptanceStatus.PASSED.value
    assert manifest.selected_patch_id == authored_report.selected_patch_id
    assert manifest.authoring_chain_digest == authored_report.authored_repair_report.receipt_snapshot.latest_chain_digest
    assert manifest.artifact_count == 5
    assert len(manifest.digest) == 64

    expected_kinds = {
        Wave3EvidenceArtifactKind.AUTHORED_ENGINEERING_REPORT,
        Wave3EvidenceArtifactKind.AUTHORING_RECEIPTS,
        Wave3EvidenceArtifactKind.WAVE3_ACCEPTANCE_REPORT,
        Wave3EvidenceArtifactKind.WAVE2_ENGINEERING_REPORT,
        Wave3EvidenceArtifactKind.WAVE3_EVIDENCE_INDEX,
        Wave3EvidenceArtifactKind.WAVE3_PACKAGE_MANIFEST,
    }
    assert {artifact.kind for artifact in manifest.artifacts} == expected_kinds

    for artifact in manifest.artifacts:
        artifact_path = writer.root_dir / artifact.path
        assert artifact_path.is_file()
        data = artifact_path.read_bytes()
        assert len(data) == artifact.size_bytes
        assert _sha256(data) == artifact.sha256


def test_wave3_evidence_package_manifest_round_trip(tmp_path) -> None:
    authored_report = _passing_authored_report(tmp_path)
    acceptance_report = Wave3AcceptanceValidator().validate(authored_report)

    manifest = Wave3EvidencePackageWriter(root_dir=tmp_path / "packages").write(
        authored_report=authored_report,
        acceptance_report=acceptance_report,
    )

    restored = Wave3EvidencePackageManifest.from_dict(manifest.to_dict())

    assert restored.package_id == manifest.package_id
    assert restored.run_id == manifest.run_id
    assert restored.task_id == manifest.task_id
    assert restored.acceptance_status == manifest.acceptance_status
    assert restored.selected_patch_id == manifest.selected_patch_id
    assert restored.artifact_count == manifest.artifact_count
    assert restored.artifact_paths == manifest.artifact_paths
    assert restored.digest == manifest.digest


def test_wave3_evidence_index_contains_review_critical_ids(tmp_path) -> None:
    authored_report = _passing_authored_report(tmp_path)
    acceptance_report = Wave3AcceptanceValidator().validate(authored_report)

    manifest = Wave3EvidencePackageWriter(root_dir=tmp_path / "packages").write(
        authored_report=authored_report,
        acceptance_report=acceptance_report,
    )

    index_artifact = next(
        artifact
        for artifact in manifest.artifacts
        if artifact.kind is Wave3EvidenceArtifactKind.WAVE3_EVIDENCE_INDEX
    )
    index_payload = json.loads((tmp_path / "packages" / index_artifact.path).read_text(encoding="utf-8"))

    assert index_payload["schema_version"] == "wave3.evidence_index.v1"
    assert index_payload["run_id"] == authored_report.run_id
    assert index_payload["task_id"] == authored_report.task_id
    assert index_payload["acceptance_status"] == "passed"
    assert index_payload["selected_patch_id"] == authored_report.selected_patch_id
    assert index_payload["authoring_chain_digest"] == authored_report.authored_repair_report.receipt_snapshot.latest_chain_digest
    assert index_payload["proposal_count"] == 1
    assert index_payload["compiled_candidate_count"] == 1
    assert index_payload["policy_report_count"] == 1


def test_wave3_evidence_writer_preserves_not_executed_case_without_wave2_report(tmp_path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
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
    acceptance_report = Wave3AcceptanceValidator().validate(authored_report)

    manifest = Wave3EvidencePackageWriter(root_dir=tmp_path / "packages").write(
        authored_report=authored_report,
        acceptance_report=acceptance_report,
    )

    assert manifest.acceptance_status == "not_executed"
    assert manifest.selected_patch_id is None
    assert Wave3EvidenceArtifactKind.WAVE2_ENGINEERING_REPORT not in {
        artifact.kind for artifact in manifest.artifacts
    }
    assert Wave3EvidenceArtifactKind.AUTHORED_ENGINEERING_REPORT in {
        artifact.kind for artifact in manifest.artifacts
    }


def test_wave3_evidence_writer_rejects_existing_package_when_overwrite_disabled(tmp_path) -> None:
    authored_report = _passing_authored_report(tmp_path)
    acceptance_report = Wave3AcceptanceValidator().validate(authored_report)
    writer = Wave3EvidencePackageWriter(
        root_dir=tmp_path / "packages",
        config=Wave3EvidencePackageWriterConfig(overwrite_existing=False),
    )

    writer.write(
        authored_report=authored_report,
        acceptance_report=acceptance_report,
    )

    with pytest.raises(FileExistsError, match="already exists"):
        writer.write(
            authored_report=authored_report,
            acceptance_report=acceptance_report,
        )


def test_wave3_evidence_artifact_round_trip() -> None:
    artifact = Wave3EvidenceArtifact(
        kind=Wave3EvidenceArtifactKind.WAVE3_ACCEPTANCE_REPORT,
        path="run/wave3/wave3-acceptance-report.json",
        sha256="a" * 64,
        size_bytes=100,
        media_type="application/json",
        metadata={"status": "passed"},
    )

    restored = Wave3EvidenceArtifact.from_dict(artifact.to_dict())

    assert restored == artifact


def _passing_authored_report(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
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
        proposal_provider=StaticPatchProposalProvider(
            responses=(
                _proposal_json(
                    path="src/example.py",
                    before_text="before",
                    after_text="after",
                ),
            )
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


def _sha256(data: bytes) -> str:
    return __import__("hashlib").sha256(data).hexdigest()
