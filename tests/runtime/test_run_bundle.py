from __future__ import annotations

import json
from pathlib import Path

import pytest

from ix_blackfox.runtime import (
    RunBundleArtifactKind,
    RunBundleLayout,
    RunBundleManifest,
    RunBundleWriter,
)


def test_run_bundle_layout_creates_expected_directory_tree(tmp_path: Path) -> None:
    layout = RunBundleLayout(root_dir=tmp_path, run_id="run-abc")
    layout.ensure_directories()

    assert layout.bundle_root == tmp_path / "artifacts/runs/run-abc"
    assert layout.reports_dir.exists() is True
    assert layout.receipts_dir.exists() is True
    assert layout.patches_dir.exists() is True
    assert layout.tests_dir.exists() is True
    assert layout.verification_dir.exists() is True
    assert layout.traces_dir.exists() is True
    assert layout.manifest_path == tmp_path / "artifacts/runs/run-abc/manifest.json"


def test_run_bundle_layout_routes_artifact_kinds_to_stable_directories(
    tmp_path: Path,
) -> None:
    layout = RunBundleLayout(root_dir=tmp_path, run_id="run-abc")

    assert layout.path_for_kind(
        RunBundleArtifactKind.RUN_REPORT,
        "run-report.json",
    ) == layout.reports_dir / "run-report.json"
    assert layout.path_for_kind(
        RunBundleArtifactKind.OPERATOR_SUMMARY,
        "operator-summary.md",
    ) == layout.reports_dir / "operator-summary.md"
    assert layout.path_for_kind(
        RunBundleArtifactKind.GOVERNANCE_RECEIPTS,
        "governance-receipts.json",
    ) == layout.receipts_dir / "governance-receipts.json"
    assert layout.path_for_kind(
        RunBundleArtifactKind.PATCH_DIFF,
        "patch.diff",
    ) == layout.patches_dir / "patch.diff"
    assert layout.path_for_kind(
        RunBundleArtifactKind.TEST_RESULT,
        "test-result.json",
    ) == layout.tests_dir / "test-result.json"
    assert layout.path_for_kind(
        RunBundleArtifactKind.VERIFICATION_SUMMARY,
        "verification-summary.json",
    ) == layout.verification_dir / "verification-summary.json"
    assert layout.path_for_kind(
        RunBundleArtifactKind.TRACE,
        "trace.jsonl",
    ) == layout.traces_dir / "trace.jsonl"


def test_run_bundle_layout_rejects_path_like_filenames(tmp_path: Path) -> None:
    layout = RunBundleLayout(root_dir=tmp_path, run_id="run-abc")

    with pytest.raises(ValueError, match="simple file name"):
        layout.path_for_kind(RunBundleArtifactKind.RUN_REPORT, "../escape.json")

    with pytest.raises(ValueError, match="simple file name"):
        layout.path_for_kind(RunBundleArtifactKind.RUN_REPORT, "reports/escape.json")

    with pytest.raises(ValueError, match="simple file name"):
        layout.path_for_kind(RunBundleArtifactKind.RUN_REPORT, ".hidden")


def test_run_bundle_writer_persists_json_text_bytes_and_manifest(
    tmp_path: Path,
) -> None:
    writer = RunBundleWriter(
        layout=RunBundleLayout(root_dir=tmp_path, run_id="run-abc"),
        task_id="task-abc",
        metadata={"suite": "unit"},
    )

    run_report_artifact = writer.write_json(
        kind=RunBundleArtifactKind.RUN_REPORT,
        filename="run-report.json",
        payload={"status": "passed", "run_id": "run-abc"},
        metadata={"source": "test"},
    )
    summary_artifact = writer.write_text(
        kind=RunBundleArtifactKind.OPERATOR_SUMMARY,
        filename="operator-summary.md",
        text="# Operator Summary\n\nPassed.\n",
        media_type="text/markdown",
    )
    trace_artifact = writer.write_bytes(
        kind=RunBundleArtifactKind.TRACE,
        filename="trace.jsonl",
        payload=b'{"event":"started"}\n',
        media_type="application/jsonl",
    )
    manifest_artifact = writer.persist_manifest()

    assert run_report_artifact.relative_path == "reports/run-report.json"
    assert summary_artifact.relative_path == "reports/operator-summary.md"
    assert trace_artifact.relative_path == "traces/trace.jsonl"
    assert manifest_artifact.relative_path == "manifest.json"

    assert (tmp_path / "artifacts/runs/run-abc/reports/run-report.json").exists() is True
    assert (tmp_path / "artifacts/runs/run-abc/reports/operator-summary.md").exists() is True
    assert (tmp_path / "artifacts/runs/run-abc/traces/trace.jsonl").exists() is True
    assert (tmp_path / "artifacts/runs/run-abc/manifest.json").exists() is True

    manifest_payload = json.loads(
        (tmp_path / "artifacts/runs/run-abc/manifest.json").read_text(
            encoding="utf-8"
        )
    )

    assert writer.manifest.run_id == "run-abc"
    assert writer.manifest.task_id == "task-abc"
    assert writer.manifest.metadata == {"suite": "unit"}
    assert writer.manifest.artifact_count == 3
    assert writer.manifest.artifact_paths == (
        "reports/run-report.json",
        "reports/operator-summary.md",
        "traces/trace.jsonl",
    )

    assert manifest_payload["run_id"] == "run-abc"
    assert manifest_payload["task_id"] == "task-abc"
    assert manifest_payload["artifact_count"] == 3
    assert manifest_payload["artifacts"][0]["relative_path"] == "reports/run-report.json"
    assert manifest_artifact.metadata["artifact_count"] == 3
    assert len(manifest_artifact.metadata["manifest_digest"]) == 64


def test_run_bundle_manifest_round_trips_without_losing_artifact_metadata(
    tmp_path: Path,
) -> None:
    writer = RunBundleWriter(
        layout=RunBundleLayout(root_dir=tmp_path, run_id="run-round-trip"),
        task_id="task-round-trip",
    )
    writer.write_json(
        kind=RunBundleArtifactKind.VERIFICATION_SUMMARY,
        filename="verification-summary.json",
        payload={"verified": True},
        metadata={"kind": "verification"},
    )

    payload = writer.manifest.to_dict()
    restored = RunBundleManifest.from_dict(payload)

    assert restored.bundle_id == writer.manifest.bundle_id
    assert restored.run_id == "run-round-trip"
    assert restored.task_id == "task-round-trip"
    assert restored.artifact_count == 1
    assert restored.artifacts[0].kind is RunBundleArtifactKind.VERIFICATION_SUMMARY
    assert restored.artifacts[0].metadata == {"kind": "verification"}
    assert restored.digest == writer.manifest.digest


def test_run_bundle_manifest_rejects_duplicate_artifact_paths(tmp_path: Path) -> None:
    writer = RunBundleWriter(
        layout=RunBundleLayout(root_dir=tmp_path, run_id="run-duplicates"),
    )
    writer.write_json(
        kind=RunBundleArtifactKind.RUN_REPORT,
        filename="run-report.json",
        payload={"status": "passed"},
    )

    with pytest.raises(ValueError, match="already exists"):
        writer.write_json(
            kind=RunBundleArtifactKind.RUN_REPORT,
            filename="run-report.json",
            payload={"status": "failed"},
        )
