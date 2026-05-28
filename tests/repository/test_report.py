from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ix_blackfox.repository import (
    RepositoryEvidenceEventType,
    RepositoryImpactSeverity,
    RepositoryIntelligenceRunner,
    build_repository_intelligence_report,
    validate_repository_evidence_snapshot,
)

_FIXED_TIME = datetime(2026, 5, 27, 12, 0, 0, tzinfo=UTC)


def test_repository_intelligence_runner_builds_complete_wave8_report(
    tmp_path: Path,
) -> None:
    repo = _build_report_repo(tmp_path)

    report = RepositoryIntelligenceRunner().run(
        root=repo,
        changed_paths=("src/ix_blackfox/runtime/brain_repair.py",),
        head_sha="abc123",
        run_id="wave8-unit",
        generated_at=_FIXED_TIME,
    )
    payload = report.to_dict(include_full=False)

    assert report.passed is True
    assert payload["schema_version"] == "wave8.repository_intelligence.v1"
    assert payload["wave"] == 8
    assert payload["passed"] is True
    assert payload["summary"]["file_count"] >= 10
    assert payload["summary"]["source_file_count"] >= 3
    assert payload["summary"]["test_file_count"] >= 2
    assert payload["summary"]["syntax_error_count"] == 0
    assert payload["summary"]["receipt_count"] == 7
    assert payload["summary"]["evidence_chain_valid"] is True
    assert payload["impact_report"]["max_severity"] == RepositoryImpactSeverity.HIGH.value
    assert payload["evidence_snapshot"]["chain_valid"] is True
    assert payload["evidence_snapshot"]["event_types"][-1] == (
        RepositoryEvidenceEventType.REPORT_EXPORTED.value
    )
    assert "not certify code correctness" in payload["scope_note"]
    assert payload["digests"]["snapshot"] == report.snapshot.digest
    assert payload["digests"]["evidence_snapshot"] == report.evidence_snapshot.digest


def test_repository_intelligence_runner_full_payload_contains_all_artifacts(
    tmp_path: Path,
) -> None:
    repo = _build_report_repo(tmp_path)

    report = build_repository_intelligence_report(
        root=repo,
        changed_paths=("src/ix_blackfox/repository/__init__.py",),
        head_sha="abc123",
        run_id="wave8-full",
        generated_at=_FIXED_TIME,
    )
    payload = report.to_dict(include_full=True)

    assert "snapshot" in payload
    assert "code_graph" in payload
    assert "dependency_map" in payload
    assert "coverage_map" in payload
    assert "architecture_memory" in payload
    assert payload["summary"]["impacted_subsystem_count"] >= 1
    assert report.evidence_snapshot.receipt_count == 7
    assert validate_repository_evidence_snapshot(report.evidence_snapshot)["valid"] is True


def test_repository_intelligence_report_writes_json(
    tmp_path: Path,
) -> None:
    repo = _build_report_repo(tmp_path)
    output = tmp_path / "out" / "wave8-report.json"

    report = RepositoryIntelligenceRunner().run(
        root=repo,
        changed_paths=("pyproject.toml",),
        head_sha="abc123",
        run_id="wave8-json",
        generated_at=_FIXED_TIME,
    )
    report.write_json(output, include_full=False)
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert payload["passed"] is True
    assert payload["summary"]["max_severity"] == "high"
    assert payload["summary"]["requires_human_review"] is True
    assert payload["digests"]["architecture_memory"]
    assert payload["evidence_snapshot"]["receipt_count"] == 7


def test_repository_intelligence_runner_rejects_missing_root(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="Repository root does not exist"):
        RepositoryIntelligenceRunner().run(
            root=tmp_path / "missing",
            changed_paths=("pyproject.toml",),
            head_sha="abc123",
            run_id="wave8-missing",
            generated_at=_FIXED_TIME,
        )


def _build_report_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "IX-BlackFox-main"

    _write_text(
        repo / "pyproject.toml",
        "\n".join(
            [
                "[build-system]",
                'requires = ["setuptools>=69", "wheel"]',
                'build-backend = "setuptools.build_meta"',
                "",
                "[project]",
                'name = "ix-blackfox"',
                'dependencies = []',
                "",
                "[project.optional-dependencies]",
                'dev = ["pytest>=8.2"]',
                "",
            ]
        ),
    )
    _write_text(
        repo / ".github" / "workflows" / "ci.yml",
        "\n".join(
            [
                "name: CI",
                "on: [push]",
                "jobs:",
                "  test:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - uses: actions/checkout@v4",
                "      - uses: actions/setup-python@v5",
                "",
            ]
        ),
    )
    _write_text(
        repo / "src" / "ix_blackfox" / "repository" / "__init__.py",
        "class RepositorySnapshot:\n    pass\n",
    )
    _write_text(
        repo / "src" / "ix_blackfox" / "runtime" / "evidence.py",
        "class EvidenceReceipt:\n    pass\n",
    )
    _write_text(
        repo / "src" / "ix_blackfox" / "runtime" / "brain_repair.py",
        "\n".join(
            [
                "from ix_blackfox.repository import RepositorySnapshot",
                "from .evidence import EvidenceReceipt",
                "",
                "def repair(snapshot: RepositorySnapshot) -> EvidenceReceipt:",
                "    return EvidenceReceipt()",
                "",
            ]
        ),
    )
    _write_text(
        repo / "src" / "ix_blackfox" / "sandbox" / "workspace.py",
        "class Workspace:\n    pass\n",
    )
    _write_text(
        repo / "tests" / "runtime" / "test_brain_repair.py",
        "\n".join(
            [
                "from ix_blackfox.runtime.brain_repair import repair",
                "",
                "def test_repair() -> None:",
                "    assert repair is not None",
                "",
            ]
        ),
    )
    _write_text(
        repo / "tests" / "repository" / "test_report.py",
        "def test_report() -> None:\n    assert True\n",
    )
    _write_text(repo / "scripts" / "run_wave8.py", "print('wave8')\n")
    _write_text(repo / "docs" / "wave8.md", "# Wave 8\n")
    _write_text(repo / "blackfox.policy.toml", "[policy]\n")
    _write_text(repo / "README.md", "# IX-BlackFox\n")
    _write_text(repo / "LICENSE", "source-available evaluation license\n")
    _write_text(repo / "NOTICE.md", "IX-BlackFox notice\n")

    return repo


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{content.rstrip()}\n", encoding="utf-8")
