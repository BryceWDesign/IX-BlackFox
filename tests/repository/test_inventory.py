from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from ix_blackfox.repository import (
    RepositoryFileRole,
    RepositoryInventoryScanner,
    RepositorySensitivity,
    classify_generated_reason,
    classify_repository_file,
    classify_repository_sensitivity,
    scan_repository,
)


def test_inventory_scanner_classifies_files_and_builds_stable_snapshot(
    tmp_path: Path,
) -> None:
    repo = _build_sample_repo(tmp_path)

    snapshot = RepositoryInventoryScanner().scan(repo)
    same_snapshot = RepositoryInventoryScanner().scan(repo)

    records = {record.path: record for record in snapshot.files}

    assert snapshot.file_count == 12
    assert snapshot.digest == same_snapshot.digest
    assert snapshot.metadata["ignored_path_count"] >= 3
    assert snapshot.metadata["sensitive_file_count"] >= 6

    assert records["src/ix_blackfox/runtime/brain_repair.py"].role is RepositoryFileRole.SOURCE
    assert records["src/ix_blackfox/sandbox/workspace.py"].role is RepositoryFileRole.SOURCE
    assert records["tests/runtime/test_brain_repair.py"].role is RepositoryFileRole.TEST
    assert records[".github/workflows/ci.yml"].role is RepositoryFileRole.WORKFLOW
    assert records["scripts/run_wave8.py"].role is RepositoryFileRole.SCRIPT
    assert records["LICENSE"].role is RepositoryFileRole.LICENSE
    assert records["README.md"].role is RepositoryFileRole.DOCUMENTATION
    assert records["IX-BlackFox-Logo.png"].role is RepositoryFileRole.UNKNOWN

    assert records[".github/workflows/ci.yml"].sensitivity is RepositorySensitivity.RELEASE_RELEVANT
    assert records["blackfox.policy.toml"].sensitivity is RepositorySensitivity.POLICY_RELEVANT
    assert records["scripts/run_wave8.py"].sensitivity is RepositorySensitivity.SECURITY_RELEVANT
    assert records["src/ix_blackfox/runtime/brain_repair.py"].sensitivity is RepositorySensitivity.SECURITY_RELEVANT

    assert ".pytest_cache/CACHEDIR.TAG" not in records
    assert "__pycache__/ignored.pyc" not in records
    assert ".blackfox-artifacts/wave8/report.json" not in records

    source_paths = snapshot.paths_by_role(RepositoryFileRole.SOURCE)
    assert source_paths == (
        "src/ix_blackfox/runtime/brain_repair.py",
        "src/ix_blackfox/sandbox/workspace.py",
    )


def test_inventory_scanner_hashes_file_bytes(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    source = repo / "src" / "ix_blackfox" / "runtime" / "brain_repair.py"
    _write_text(source, "VALUE = 1\n")

    snapshot = RepositoryInventoryScanner().scan(repo)
    record = snapshot.files[0]

    assert record.path == "src/ix_blackfox/runtime/brain_repair.py"
    assert record.sha256 == hashlib.sha256(b"VALUE = 1\n").hexdigest()
    assert record.size_bytes == len(b"VALUE = 1\n")
    assert record.metadata["suffix"] == ".py"
    assert record.metadata["text"] is True


def test_inventory_scanner_rejects_missing_root(tmp_path: Path) -> None:
    missing = tmp_path / "missing"

    with pytest.raises(ValueError, match="Repository root does not exist"):
        RepositoryInventoryScanner().scan(missing)


def test_scan_repository_convenience_wrapper_uses_default_scanner(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write_text(repo / "README.md", "# IX-BlackFox\n")

    snapshot = scan_repository(repo, root_label="IX-BlackFox")

    assert snapshot.snapshot_id == "wave-8-repository-inventory"
    assert snapshot.root_label == "IX-BlackFox"
    assert snapshot.files[0].path == "README.md"


def test_classify_repository_file_handles_wave8_review_roles() -> None:
    assert classify_repository_file("src/ix_blackfox/runtime/foo.py") is RepositoryFileRole.SOURCE
    assert classify_repository_file("tests/runtime/test_foo.py") is RepositoryFileRole.TEST
    assert classify_repository_file(".github/workflows/ci.yml") is RepositoryFileRole.WORKFLOW
    assert classify_repository_file("scripts/run_wave8.py") is RepositoryFileRole.SCRIPT
    assert classify_repository_file("LICENSE") is RepositoryFileRole.LICENSE
    assert classify_repository_file("docs/system-architecture.md") is RepositoryFileRole.DOCUMENTATION
    assert classify_repository_file("pyproject.toml") is RepositoryFileRole.CONFIGURATION
    assert classify_repository_file("artifacts/report.json") is RepositoryFileRole.ARTIFACT
    assert classify_repository_file("IX-BlackFox-Logo.png") is RepositoryFileRole.UNKNOWN


def test_classify_repository_file_rejects_unsafe_paths() -> None:
    with pytest.raises(ValueError, match="repository-relative"):
        classify_repository_file("/absolute/path.py")

    with pytest.raises(ValueError, match="traversal"):
        classify_repository_file("../escape.py")


def test_classify_repository_sensitivity_marks_policy_release_and_security_paths() -> None:
    assert (
        classify_repository_sensitivity(
            ".github/workflows/ci.yml",
            RepositoryFileRole.WORKFLOW,
        )
        is RepositorySensitivity.RELEASE_RELEVANT
    )
    assert (
        classify_repository_sensitivity(
            "COMMERCIAL.md",
            RepositoryFileRole.DOCUMENTATION,
        )
        is RepositorySensitivity.POLICY_RELEVANT
    )
    assert (
        classify_repository_sensitivity(
            "scripts/run_wave8.py",
            RepositoryFileRole.SCRIPT,
        )
        is RepositorySensitivity.SECURITY_RELEVANT
    )
    assert (
        classify_repository_sensitivity(
            "src/ix_blackfox/sandbox/workspace.py",
            RepositoryFileRole.SOURCE,
        )
        is RepositorySensitivity.SECURITY_RELEVANT
    )
    assert (
        classify_repository_sensitivity(
            "tests/runtime/test_runtime.py",
            RepositoryFileRole.TEST,
        )
        is RepositorySensitivity.NORMAL
    )


def test_generated_file_detection_can_be_included_when_requested(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write_bytes(repo / "module.pyc", b"compiled")

    default_snapshot = RepositoryInventoryScanner().scan(repo)
    inclusive_snapshot = RepositoryInventoryScanner(include_generated=True).scan(repo)

    assert default_snapshot.files == ()
    assert inclusive_snapshot.file_count == 1
    assert inclusive_snapshot.files[0].generated is True
    assert inclusive_snapshot.files[0].role is RepositoryFileRole.ARTIFACT
    assert (
        inclusive_snapshot.files[0].sensitivity
        is RepositorySensitivity.GENERATED_OR_ARTIFACT
    )
    assert classify_generated_reason("module.pyc") == "python bytecode"


def _build_sample_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "IX-BlackFox-main"

    _write_text(
        repo / "src" / "ix_blackfox" / "runtime" / "brain_repair.py",
        "def repair() -> str:\n    return 'ok'\n",
    )
    _write_text(
        repo / "src" / "ix_blackfox" / "sandbox" / "workspace.py",
        "class Workspace:\n    pass\n",
    )
    _write_text(
        repo / "tests" / "runtime" / "test_brain_repair.py",
        "def test_repair() -> None:\n    assert True\n",
    )
    _write_text(repo / ".github" / "workflows" / "ci.yml", "name: CI\n")
    _write_text(repo / "scripts" / "run_wave8.py", "print('wave8')\n")
    _write_text(repo / "README.md", "# IX-BlackFox\n")
    _write_text(repo / "LICENSE", "source-available evaluation license\n")
    _write_text(repo / "COMMERCIAL.md", "Commercial use requires permission.\n")
    _write_text(repo / "blackfox.policy.toml", "[policy]\n")
    _write_text(repo / "pyproject.toml", "[project]\nname = 'ix-blackfox'\n")
    _write_text(repo / "docs" / "system-architecture.md", "# Architecture\n")
    _write_bytes(repo / "IX-BlackFox-Logo.png", b"\x89PNG\r\n")

    _write_text(repo / ".pytest_cache" / "CACHEDIR.TAG", "cache\n")
    _write_bytes(repo / "__pycache__" / "ignored.pyc", b"bytecode")
    _write_text(repo / ".blackfox-artifacts" / "wave8" / "report.json", "{}\n")

    return repo


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
