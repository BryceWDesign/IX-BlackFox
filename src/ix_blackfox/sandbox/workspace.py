from __future__ import annotations

import hashlib
import json
import shutil
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from ix_blackfox.sandbox.contracts import (
    SandboxFilesystemPolicy,
    SandboxMount,
    SandboxMountAccess,
    SandboxProfile,
)

_SANDBOX_ROOT = PurePosixPath("/")


@dataclass(frozen=True, slots=True)
class SandboxArtifactRecord:
    path: str
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _normalize_manifest_path(self.path))
        object.__setattr__(self, "sha256", _normalize_sha256(self.sha256))
        if self.size_bytes < 0:
            raise ValueError("size_bytes must be non-negative.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True, slots=True)
class SandboxArtifactManifest:
    workspace_id: str
    profile_id: str
    profile_digest: str
    collected_at: datetime
    sandbox_path: str
    artifacts: tuple[SandboxArtifactRecord, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "workspace_id", _normalize_id(self.workspace_id, label="workspace_id"))
        object.__setattr__(self, "profile_id", _normalize_id(self.profile_id, label="profile_id"))
        object.__setattr__(self, "profile_digest", _normalize_sha256(self.profile_digest))
        _require_aware_datetime(self.collected_at, label="collected_at")
        object.__setattr__(self, "sandbox_path", _normalize_absolute_sandbox_path(self.sandbox_path, label="sandbox_path"))
        object.__setattr__(self, "artifacts", tuple(sorted(self.artifacts, key=lambda item: item.path)))
        paths = tuple(artifact.path for artifact in self.artifacts)
        if len(set(paths)) != len(paths):
            raise ValueError("artifact manifest paths must not contain duplicates.")

    @property
    def total_size_bytes(self) -> int:
        return sum(artifact.size_bytes for artifact in self.artifacts)

    @property
    def artifact_count(self) -> int:
        return len(self.artifacts)

    @property
    def digest(self) -> str:
        return _sha256_json(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "workspace_id": self.workspace_id,
            "profile_id": self.profile_id,
            "profile_digest": self.profile_digest,
            "collected_at": self.collected_at.isoformat(),
            "sandbox_path": self.sandbox_path,
            "artifact_count": self.artifact_count,
            "total_size_bytes": self.total_size_bytes,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class SandboxWorkspace:
    workspace_id: str
    root_path: Path
    profile_id: str
    profile_digest: str
    target_map: Mapping[str, Path]
    created_at: datetime
    max_artifact_bytes: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "workspace_id", _normalize_id(self.workspace_id, label="workspace_id"))
        object.__setattr__(self, "root_path", self.root_path.resolve())
        object.__setattr__(self, "profile_id", _normalize_id(self.profile_id, label="profile_id"))
        object.__setattr__(self, "profile_digest", _normalize_sha256(self.profile_digest))
        normalized_map = {
            _normalize_absolute_sandbox_path(key, label="target_map_key"): value.resolve()
            for key, value in self.target_map.items()
        }
        object.__setattr__(self, "target_map", dict(sorted(normalized_map.items())))
        _require_aware_datetime(self.created_at, label="created_at")
        if self.max_artifact_bytes <= 0:
            raise ValueError("max_artifact_bytes must be greater than zero.")

    def resolve_sandbox_path(self, sandbox_path: str) -> Path:
        normalized_path = _normalize_absolute_sandbox_path(sandbox_path, label="sandbox_path")
        best_target: str | None = None
        for target in self.target_map:
            if normalized_path == target or normalized_path.startswith(f"{target}/"):
                if best_target is None or len(target) > len(best_target):
                    best_target = target
        if best_target is None:
            raise ValueError("sandbox_path is not covered by a staged workspace target.")
        suffix = normalized_path.removeprefix(best_target).lstrip("/")
        host_base = self.target_map[best_target]
        resolved = (host_base / suffix).resolve()
        if not _is_relative_to(resolved, host_base):
            raise ValueError("sandbox_path escapes the staged workspace target.")
        return resolved

    def to_dict(self) -> dict[str, Any]:
        return {
            "workspace_id": self.workspace_id,
            "root_path": str(self.root_path),
            "profile_id": self.profile_id,
            "profile_digest": self.profile_digest,
            "created_at": self.created_at.isoformat(),
            "max_artifact_bytes": self.max_artifact_bytes,
            "target_map": {key: str(value) for key, value in self.target_map.items()},
        }


@dataclass(frozen=True, slots=True)
class SandboxWorkspaceManager:
    base_dir: Path
    keep_workspaces: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "base_dir", self.base_dir.resolve())

    def create_workspace(
        self,
        profile: SandboxProfile,
        *,
        repo_root: Path,
        workspace_id: str | None = None,
    ) -> SandboxWorkspace:
        normalized_id = _normalize_id(
            workspace_id if workspace_id is not None else f"workspace-{uuid.uuid4().hex}",
            label="workspace_id",
        )
        root_path = (self.base_dir / normalized_id).resolve()
        if not _is_relative_to(root_path, self.base_dir):
            raise ValueError("workspace root escapes the workspace base directory.")
        if root_path.exists():
            raise ValueError(f"workspace already exists: {normalized_id}")
        root_path.mkdir(parents=True)
        target_map: dict[str, Path] = {}
        repo_root_resolved = repo_root.resolve()
        try:
            for mount in profile.filesystem.mounts:
                target_path = _stage_mount(
                    mount,
                    repo_root=repo_root_resolved,
                    workspace_root=root_path,
                    filesystem=profile.filesystem,
                )
                target_map[mount.target] = target_path
        except Exception:
            if not self.keep_workspaces:
                shutil.rmtree(root_path, ignore_errors=True)
            raise
        return SandboxWorkspace(
            workspace_id=normalized_id,
            root_path=root_path,
            profile_id=profile.profile_id,
            profile_digest=profile.digest,
            target_map=target_map,
            created_at=datetime.now(tz=UTC),
            max_artifact_bytes=profile.resources.max_artifact_bytes,
        )

    def collect_artifacts(
        self,
        workspace: SandboxWorkspace,
        *,
        sandbox_path: str = "/workspace/out",
    ) -> SandboxArtifactManifest:
        host_path = workspace.resolve_sandbox_path(sandbox_path)
        records: list[SandboxArtifactRecord] = []
        if host_path.exists():
            if host_path.is_symlink():
                raise ValueError("artifact collection path must not be a symlink.")
            if host_path.is_file():
                records.append(_artifact_record(host_path, manifest_root=host_path.parent))
            else:
                for item in sorted(host_path.rglob("*")):
                    if item.is_symlink():
                        raise ValueError("artifact collection refuses symlinked outputs.")
                    if item.is_file():
                        records.append(_artifact_record(item, manifest_root=host_path))
        manifest = SandboxArtifactManifest(
            workspace_id=workspace.workspace_id,
            profile_id=workspace.profile_id,
            profile_digest=workspace.profile_digest,
            collected_at=datetime.now(tz=UTC),
            sandbox_path=sandbox_path,
            artifacts=tuple(records),
        )
        if manifest.total_size_bytes > workspace.max_artifact_bytes:
            raise ValueError("artifact manifest exceeds max_artifact_bytes.")
        return manifest

    def cleanup_workspace(self, workspace: SandboxWorkspace) -> None:
        root_path = workspace.root_path.resolve()
        if not _is_relative_to(root_path, self.base_dir):
            raise ValueError("workspace root escapes the workspace base directory.")
        if root_path.exists():
            shutil.rmtree(root_path)


def _stage_mount(
    mount: SandboxMount,
    *,
    repo_root: Path,
    workspace_root: Path,
    filesystem: SandboxFilesystemPolicy,
) -> Path:
    host_source_raw = repo_root / mount.source
    if _path_contains_symlink(host_source_raw, root=repo_root):
        raise ValueError("sandbox mount source must not be a symlink.")
    host_source = host_source_raw.resolve()
    if not _is_relative_to(host_source, repo_root):
        raise ValueError("sandbox mount source escapes the repository root.")

    target_path = _host_path_for_sandbox_target(workspace_root, mount.target)
    if not _is_relative_to(target_path, workspace_root):
        raise ValueError("mount target escapes the workspace root.")
    if mount.access is SandboxMountAccess.READ_WRITE and mount.target not in filesystem.writable_paths:
        raise ValueError("read-write mount target is not listed as writable.")

    if not host_source.exists():
        if mount.required:
            raise FileNotFoundError(f"required sandbox mount source does not exist: {mount.source}")
        target_path.mkdir(parents=True, exist_ok=True)
        return target_path

    if mount.access is SandboxMountAccess.READ_WRITE:
        target_path.mkdir(parents=True, exist_ok=True)
        if host_source.is_file():
            shutil.copy2(host_source, target_path / host_source.name)
        elif host_source.is_dir():
            _copy_directory_contents(host_source, target_path)
        return target_path

    if host_source.is_file():
        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(host_source, target_path)
        return target_path
    if host_source.is_dir():
        _copy_directory_contents(host_source, target_path)
        return target_path
    raise ValueError("sandbox mount source must be a file or directory.")


def _path_contains_symlink(path: Path, *, root: Path) -> bool:
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _copy_directory_contents(source: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for item in sorted(source.rglob("*")):
        if item.is_symlink():
            raise ValueError("sandbox workspace staging refuses symlinks.")
        relative = item.relative_to(source)
        destination = target / relative
        if item.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
        elif item.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, destination)


def _artifact_record(path: Path, *, manifest_root: Path) -> SandboxArtifactRecord:
    relative = path.relative_to(manifest_root).as_posix()
    data = path.read_bytes()
    return SandboxArtifactRecord(
        path=relative,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )


def _host_path_for_sandbox_target(workspace_root: Path, target: str) -> Path:
    relative = target.strip("/")
    if not relative:
        raise ValueError("sandbox mount target cannot be the filesystem root.")
    return (workspace_root / relative).resolve()


def _normalize_absolute_sandbox_path(value: str, *, label: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    if not cleaned.startswith("/"):
        raise ValueError(f"{label} must be an absolute sandbox path.")
    path = PurePosixPath(cleaned)
    if path == _SANDBOX_ROOT:
        raise ValueError(f"{label} must not be the sandbox filesystem root.")
    if any(part in ("", ".", "..") for part in path.parts[1:]):
        raise ValueError(f"{label} must not contain empty, '.', or '..' path segments.")
    return path.as_posix()


def _normalize_manifest_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("artifact path must not be empty.")
    if cleaned.startswith("/"):
        raise ValueError("artifact path must be relative.")
    path = PurePosixPath(cleaned)
    if any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("artifact path must not contain empty, '.', or '..' path segments.")
    return path.as_posix()


def _normalize_id(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    if "/" in cleaned or "\\" in cleaned or ".." in cleaned:
        raise ValueError(f"{label} must be a simple workspace identifier.")
    return cleaned


def _normalize_sha256(value: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) != 64 or any(char not in "0123456789abcdef" for char in cleaned):
        raise ValueError("value must be a 64-character lowercase SHA-256 digest.")
    return cleaned


def _sha256_json(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_aware_datetime(value: datetime, *, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware.")


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
    except ValueError:
        return False
    return True
