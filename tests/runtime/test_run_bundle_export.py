from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from ix_blackfox.runtime import (
    RunBundleArtifactKind,
    RunBundleExporter,
    RunBundleExportFormat,
    RunBundleExportRequest,
    RunBundleLayout,
    RunBundleWriter,
)


def test_run_bundle_exporter_creates_zip_archive_with_manifest_and_artifacts(
    tmp_path: Path,
) -> None:
    writer = _make_bundle(tmp_path, run_id="run-export-zip")
    manifest_artifact = writer.persist_manifest()

    request = RunBundleExportRequest.from_layout(
        layout=writer.layout,
        destination_dir=tmp_path / "exports",
        export_format=RunBundleExportFormat.ZIP,
        export_name="review-pack",
    )

    result = RunBundleExporter().export(request)

    assert result.run_id == "run-export-zip"
    assert result.export_format is RunBundleExportFormat.ZIP
    assert result.export_path == tmp_path / "exports/review-pack.zip"
    assert result.export_path.exists() is True
    assert result.size_bytes > 0
    assert result.file_count == 3
    assert len(result.sha256) == 64
    assert result.manifest_digest == writer.manifest.digest
    assert result.metadata["export_name"] == "review-pack"

    with zipfile.ZipFile(result.export_path) as archive:
        names = sorted(archive.namelist())

    assert names == [
        "manifest.json",
        "reports/operator-summary.md",
        "reports/run-report.json",
    ]
    assert manifest_artifact.relative_path == "manifest.json"


def test_run_bundle_exporter_copies_bundle_directory(tmp_path: Path) -> None:
    writer = _make_bundle(tmp_path, run_id="run-export-directory")
    writer.persist_manifest()

    request = RunBundleExportRequest.from_layout(
        layout=writer.layout,
        destination_dir=tmp_path / "exports",
        export_format=RunBundleExportFormat.DIRECTORY,
        export_name="directory-review-pack",
    )

    result = RunBundleExporter().export(request)

    assert result.run_id == "run-export-directory"
    assert result.export_format is RunBundleExportFormat.DIRECTORY
    assert result.export_path == tmp_path / "exports/directory-review-pack"
    assert result.export_path.is_dir() is True
    assert result.file_count == 3
    assert result.size_bytes > 0
    assert len(result.sha256) == 64
    assert (result.export_path / "manifest.json").exists() is True
    assert (result.export_path / "reports/run-report.json").exists() is True
    assert (result.export_path / "reports/operator-summary.md").exists() is True

    manifest_payload = json.loads(
        (result.export_path / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest_payload["run_id"] == "run-export-directory"


def test_run_bundle_exporter_rejects_missing_required_manifest(tmp_path: Path) -> None:
    layout = RunBundleLayout(root_dir=tmp_path, run_id="run-missing-manifest")
    layout.ensure_directories()
    (layout.reports_dir / "run-report.json").write_text(
        "{}\n",
        encoding="utf-8",
    )

    request = RunBundleExportRequest.from_layout(
        layout=layout,
        destination_dir=tmp_path / "exports",
        require_manifest=True,
    )

    with pytest.raises(FileNotFoundError, match="manifest is required"):
        RunBundleExporter().export(request)


def test_run_bundle_exporter_can_export_without_manifest_when_allowed(
    tmp_path: Path,
) -> None:
    layout = RunBundleLayout(root_dir=tmp_path, run_id="run-no-manifest")
    layout.ensure_directories()
    (layout.reports_dir / "run-report.json").write_text(
        "{}\n",
        encoding="utf-8",
    )

    request = RunBundleExportRequest.from_layout(
        layout=layout,
        destination_dir=tmp_path / "exports",
        require_manifest=False,
    )

    result = RunBundleExporter().export(request)

    assert result.export_path.exists() is True
    assert result.file_count == 1
    assert result.manifest_digest is None


def test_run_bundle_exporter_rejects_export_name_path_traversal(tmp_path: Path) -> None:
    layout = RunBundleLayout(root_dir=tmp_path, run_id="run-export-name")
    layout.ensure_directories()

    with pytest.raises(ValueError, match="simple non-hidden name"):
        RunBundleExportRequest.from_layout(
            layout=layout,
            destination_dir=tmp_path / "exports",
            export_name="../escape",
        )

    with pytest.raises(ValueError, match="simple non-hidden name"):
        RunBundleExportRequest.from_layout(
            layout=layout,
            destination_dir=tmp_path / "exports",
            export_name="nested/export",
        )

    with pytest.raises(ValueError, match="simple non-hidden name"):
        RunBundleExportRequest.from_layout(
            layout=layout,
            destination_dir=tmp_path / "exports",
            export_name=".hidden",
        )


def test_run_bundle_exporter_refuses_overwrite_unless_requested(tmp_path: Path) -> None:
    writer = _make_bundle(tmp_path, run_id="run-overwrite")
    writer.persist_manifest()

    request = RunBundleExportRequest.from_layout(
        layout=writer.layout,
        destination_dir=tmp_path / "exports",
        export_format=RunBundleExportFormat.ZIP,
        export_name="same-name",
    )

    first_result = RunBundleExporter().export(request)

    assert first_result.export_path.exists() is True

    with pytest.raises(FileExistsError, match="already exists"):
        RunBundleExporter().export(request)

    overwrite_request = RunBundleExportRequest.from_layout(
        layout=writer.layout,
        destination_dir=tmp_path / "exports",
        export_format=RunBundleExportFormat.ZIP,
        export_name="same-name",
        overwrite=True,
    )

    second_result = RunBundleExporter().export(overwrite_request)

    assert second_result.export_path.exists() is True
    assert second_result.sha256 == first_result.sha256


def test_run_bundle_export_result_serializes_to_dict(tmp_path: Path) -> None:
    writer = _make_bundle(tmp_path, run_id="run-result-dict")
    writer.persist_manifest()

    result = RunBundleExporter().export(
        RunBundleExportRequest.from_layout(
            layout=writer.layout,
            destination_dir=tmp_path / "exports",
            export_format=RunBundleExportFormat.ZIP,
        )
    )

    payload = result.to_dict()

    assert payload["run_id"] == "run-result-dict"
    assert payload["export_format"] == "zip"
    assert payload["export_path"].endswith("run-result-dict.zip")
    assert payload["size_bytes"] == result.size_bytes
    assert payload["file_count"] == 3
    assert payload["sha256"] == result.sha256
    assert payload["manifest_digest"] == writer.manifest.digest


def _make_bundle(tmp_path: Path, *, run_id: str) -> RunBundleWriter:
    writer = RunBundleWriter(
        layout=RunBundleLayout(root_dir=tmp_path, run_id=run_id),
        task_id=f"task-{run_id}",
    )
    writer.write_json(
        kind=RunBundleArtifactKind.RUN_REPORT,
        filename="run-report.json",
        payload={
            "run_id": run_id,
            "status": "passed",
        },
    )
    writer.write_text(
        kind=RunBundleArtifactKind.OPERATOR_SUMMARY,
        filename="operator-summary.md",
        text="# Operator Summary\n\nPassed.\n",
        media_type="text/markdown",
    )
    return writer
