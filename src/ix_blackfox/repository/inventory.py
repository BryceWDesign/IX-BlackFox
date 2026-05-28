from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Final

from ix_blackfox.repository.models import (
    RepositoryFileRecord,
    RepositoryFileRole,
    RepositorySensitivity,
    RepositorySnapshot,
)

TEXT_FILE_SUFFIXES: Final[frozenset[str]] = frozenset(
    {
        ".cfg",
        ".css",
        ".csv",
        ".html",
        ".ini",
        ".java",
        ".js",
        ".json",
        ".jsx",
        ".md",
        ".py",
        ".rs",
        ".sh",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)

CONFIG_FILE_SUFFIXES: Final[frozenset[str]] = frozenset(
    {
        ".cfg",
        ".ini",
        ".json",
        ".toml",
        ".yaml",
        ".yml",
    }
)

IGNORED_DIR_NAMES: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "htmlcov",
        "node_modules",
    }
)

IGNORED_PATH_PREFIXES: Final[tuple[str, ...]] = (
    ".blackfox-artifacts/",
    ".coverage",
)

GENERATED_FILE_SUFFIXES: Final[frozenset[str]] = frozenset(
    {
        ".pyc",
        ".pyo",
    }
)

EXACT_TEXT_FILE_NAMES: Final[frozenset[str]] = frozenset(
    {
        ".editorconfig",
        ".gitattributes",
        ".gitignore",
        "COMMERCIAL.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "NOTICE",
        "NOTICE.md",
        "README.md",
        "SECURITY.md",
        "blackfox.policy.toml",
        "pyproject.toml",
    }
)

POLICY_RELEVANT_FILE_NAMES: Final[frozenset[str]] = frozenset(
    {
        "COMMERCIAL.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "NOTICE",
        "NOTICE.md",
        "README.md",
        "SECURITY.md",
        "blackfox.policy.toml",
    }
)

RELEASE_RELEVANT_FILE_NAMES: Final[frozenset[str]] = frozenset(
    {
        "pyproject.toml",
    }
)

SECURITY_RELEVANT_SOURCE_PREFIXES: Final[tuple[str, ...]] = (
    "src/ix_blackfox/brains/",
    "src/ix_blackfox/forge/",
    "src/ix_blackfox/governance/",
    "src/ix_blackfox/repository/",
    "src/ix_blackfox/runtime/",
    "src/ix_blackfox/sandbox/",
    "src/ix_blackfox/sentinel/",
    "src/ix_blackfox/vault/",
)


@dataclass(frozen=True, slots=True)
class RepositoryInventoryScanner:
    """Build deterministic inventory evidence for a repository workspace.

    The scanner does not execute repository code. It walks reviewable files,
    records stable SHA-256 digests, classifies file roles, and marks files that
    should receive stronger human review because they affect policy, release,
    security, workflow, or generated-artifact posture.
    """

    text_suffixes: frozenset[str] = field(default_factory=lambda: TEXT_FILE_SUFFIXES)
    ignored_dir_names: frozenset[str] = field(default_factory=lambda: IGNORED_DIR_NAMES)
    ignored_path_prefixes: tuple[str, ...] = IGNORED_PATH_PREFIXES
    include_generated: bool = False

    def scan(
        self,
        root: str | Path,
        *,
        snapshot_id: str = "wave-8-repository-inventory",
        root_label: str | None = None,
    ) -> RepositorySnapshot:
        repo_root = Path(root).resolve()
        if not repo_root.is_dir():
            raise ValueError(f"Repository root does not exist: {repo_root}")

        records: list[RepositoryFileRecord] = []
        ignored_path_count = 0

        for candidate in sorted(repo_root.rglob("*"), key=_path_sort_key):
            relative_path = _relative_path(candidate, repo_root)
            if self._should_ignore(relative_path):
                ignored_path_count += 1
                continue
            if candidate.is_symlink():
                ignored_path_count += 1
                continue
            if not candidate.is_file():
                continue

            generated_reason = classify_generated_reason(relative_path)
            if generated_reason is not None and not self.include_generated:
                ignored_path_count += 1
                continue

            records.append(
                build_file_record(
                    candidate,
                    relative_path,
                    text_suffixes=self.text_suffixes,
                    generated_reason=generated_reason,
                )
            )

        return RepositorySnapshot(
            snapshot_id=snapshot_id,
            root_label=root_label or repo_root.name,
            files=tuple(records),
            metadata=build_inventory_metadata(records, ignored_path_count),
        )

    def _should_ignore(self, relative_path: str) -> bool:
        path = PurePosixPath(relative_path)
        if any(part in self.ignored_dir_names for part in path.parts):
            return True
        return any(
            relative_path == prefix.rstrip("/") or relative_path.startswith(prefix)
            for prefix in self.ignored_path_prefixes
        )


def scan_repository(
    root: str | Path,
    *,
    snapshot_id: str = "wave-8-repository-inventory",
    root_label: str | None = None,
) -> RepositorySnapshot:
    """Convenience wrapper for the default Wave 8 repository inventory scan."""
    return RepositoryInventoryScanner().scan(
        root,
        snapshot_id=snapshot_id,
        root_label=root_label,
    )


def build_file_record(
    path: Path,
    relative_path: str,
    *,
    text_suffixes: frozenset[str] = TEXT_FILE_SUFFIXES,
    generated_reason: str | None = None,
) -> RepositoryFileRecord:
    normalized_path = normalize_scanner_path(relative_path)
    role = classify_repository_file(normalized_path)
    if generated_reason is not None:
        role = RepositoryFileRole.ARTIFACT

    sensitivity = classify_repository_sensitivity(
        normalized_path,
        role,
        generated_reason=generated_reason,
    )
    suffix = PurePosixPath(normalized_path).suffix.lower()
    metadata: dict[str, str | bool] = {
        "suffix": suffix,
        "text": is_text_repository_file(normalized_path, text_suffixes=text_suffixes),
    }
    if generated_reason is not None:
        metadata["generated_reason"] = generated_reason

    return RepositoryFileRecord(
        path=normalized_path,
        role=role,
        sha256=hash_file(path),
        size_bytes=path.stat().st_size,
        sensitivity=sensitivity,
        executable=is_executable_file(path),
        generated=generated_reason is not None,
        metadata=metadata,
    )


def classify_repository_file(relative_path: str) -> RepositoryFileRole:
    """Classify a repository path by review role, not only by extension."""
    path = normalize_scanner_path(relative_path)
    pure_path = PurePosixPath(path)
    name = pure_path.name
    suffix = pure_path.suffix.lower()
    upper_name = name.upper()

    if path.startswith(".github/workflows/") and suffix in {".yaml", ".yml"}:
        return RepositoryFileRole.WORKFLOW
    if path.startswith("scripts/"):
        return RepositoryFileRole.SCRIPT
    if path.startswith("tests/") and suffix == ".py":
        return RepositoryFileRole.TEST
    if path.startswith("src/") and suffix == ".py":
        return RepositoryFileRole.SOURCE
    if path.startswith((".blackfox-artifacts/", "artifacts/")):
        return RepositoryFileRole.ARTIFACT
    if _is_license_name(upper_name):
        return RepositoryFileRole.LICENSE
    if path.startswith("docs/") or suffix == ".md":
        return RepositoryFileRole.DOCUMENTATION
    if suffix in CONFIG_FILE_SUFFIXES or name.startswith("."):
        return RepositoryFileRole.CONFIGURATION
    return RepositoryFileRole.UNKNOWN


def classify_repository_sensitivity(
    relative_path: str,
    role: RepositoryFileRole,
    *,
    generated_reason: str | None = None,
) -> RepositorySensitivity:
    """Classify review sensitivity for a repository path."""
    path = normalize_scanner_path(relative_path)
    name = PurePosixPath(path).name

    if generated_reason is not None or role is RepositoryFileRole.ARTIFACT:
        return RepositorySensitivity.GENERATED_OR_ARTIFACT
    if role is RepositoryFileRole.WORKFLOW or name in RELEASE_RELEVANT_FILE_NAMES:
        return RepositorySensitivity.RELEASE_RELEVANT
    if role is RepositoryFileRole.LICENSE or name in POLICY_RELEVANT_FILE_NAMES:
        return RepositorySensitivity.POLICY_RELEVANT
    if path.startswith(".github/") or "policy" in path.lower():
        return RepositorySensitivity.POLICY_RELEVANT
    if role is RepositoryFileRole.SCRIPT:
        return RepositorySensitivity.SECURITY_RELEVANT
    if role is RepositoryFileRole.SOURCE and path.startswith(SECURITY_RELEVANT_SOURCE_PREFIXES):
        return RepositorySensitivity.SECURITY_RELEVANT
    if role is RepositoryFileRole.CONFIGURATION:
        return RepositorySensitivity.POLICY_RELEVANT
    return RepositorySensitivity.NORMAL


def classify_generated_reason(relative_path: str) -> str | None:
    path = normalize_scanner_path(relative_path)
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in GENERATED_FILE_SUFFIXES:
        return "python bytecode"
    if ".egg-info/" in path or path.endswith(".egg-info/PKG-INFO"):
        return "packaging metadata"
    return None


def is_text_repository_file(
    relative_path: str,
    *,
    text_suffixes: frozenset[str] = TEXT_FILE_SUFFIXES,
) -> bool:
    path = normalize_scanner_path(relative_path)
    pure_path = PurePosixPath(path)
    return pure_path.suffix.lower() in text_suffixes or pure_path.name in EXACT_TEXT_FILE_NAMES


def build_inventory_metadata(
    records: list[RepositoryFileRecord],
    ignored_path_count: int,
) -> dict[str, object]:
    role_counts = Counter(record.role for record in records)
    sensitivity_counts = Counter(record.sensitivity for record in records)
    return {
        "ignored_path_count": ignored_path_count,
        "sensitive_file_count": sum(
            1
            for record in records
            if record.sensitivity is not RepositorySensitivity.NORMAL
        ),
        "generated_file_count": sum(1 for record in records if record.generated),
        "role_counts": {
            role.value: role_counts.get(role, 0)
            for role in RepositoryFileRole
        },
        "sensitivity_counts": {
            sensitivity.value: sensitivity_counts.get(sensitivity, 0)
            for sensitivity in RepositorySensitivity
        },
    }


def normalize_scanner_path(relative_path: str) -> str:
    cleaned = relative_path.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("relative_path must not be empty.")
    path = PurePosixPath(cleaned)
    if path.is_absolute():
        raise ValueError("relative_path must be repository-relative.")
    if any(part == ".." for part in path.parts):
        raise ValueError("relative_path traversal is not allowed.")
    return path.as_posix()


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_executable_file(path: Path) -> bool:
    try:
        return bool(path.stat().st_mode & 0o111)
    except OSError:
        return False


def _relative_path(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _path_sort_key(path: Path) -> str:
    return path.as_posix()


def _is_license_name(upper_name: str) -> bool:
    return (
        upper_name == "LICENSE"
        or upper_name == "NOTICE"
        or upper_name.startswith("LICENSE.")
        or upper_name.startswith("NOTICE.")
    )
