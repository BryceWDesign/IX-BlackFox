from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ix_blackfox.tools.contracts import (
    ToolFailure,
    ToolFailureKind,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolInvocationStatus,
    ToolOutputArtifact,
)
from ix_blackfox.tools.manifest import (
    ToolApprovalMode,
    ToolCapability,
    ToolManifest,
    ToolPathPolicy,
    ToolSideEffect,
)


class WorkspacePathViolation(ValueError):
    """
    Raised when a requested workspace path violates BlackFox path policy.
    """


@dataclass(frozen=True, slots=True)
class WorkspaceDirectoryEntry:
    """
    Normalized directory entry returned by the workspace list tool.
    """

    path: str
    name: str
    entry_type: str
    size_bytes: int | None
    sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "name": self.name,
            "entry_type": self.entry_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class WorkspacePathResolver:
    """
    Resolve and validate tool paths inside a governed workspace.

    The resolver deliberately rejects:
    - absolute paths unless explicitly allowed by the manifest path policy
    - path traversal outside the workspace root
    - blocked root prefixes such as .git, .env, secrets, or credentials
    - paths outside the manifest allowed roots when allowed roots are declared
    """

    workspace_root: Path
    path_policy: ToolPathPolicy

    def __post_init__(self) -> None:
        root = self.workspace_root.expanduser().resolve()
        if not root.exists():
            raise FileNotFoundError(f"Workspace root does not exist: {root}")
        if not root.is_dir():
            raise NotADirectoryError(f"Workspace root is not a directory: {root}")
        object.__setattr__(self, "workspace_root", root)

    def resolve(self, requested_path: str | Path) -> Path:
        raw_path = str(requested_path).strip()
        if not raw_path:
            raise WorkspacePathViolation("Workspace path must not be empty.")

        candidate = Path(raw_path)

        if candidate.is_absolute() and not self.path_policy.allow_absolute_paths:
            raise WorkspacePathViolation(
                f"Absolute paths are not allowed by workspace policy: {raw_path}"
            )

        normalized_candidate = (
            candidate.expanduser().resolve()
            if candidate.is_absolute()
            else (self.workspace_root / candidate).resolve()
        )

        if not _is_relative_to(normalized_candidate, self.workspace_root):
            raise WorkspacePathViolation(
                f"Path escapes the governed workspace root: {raw_path}"
            )

        relative_path = normalized_candidate.relative_to(self.workspace_root)
        normalized_relative = relative_path.as_posix()

        if self._matches_blocked_root(normalized_relative):
            raise WorkspacePathViolation(
                f"Path is blocked by workspace policy: {normalized_relative}"
            )

        if self.path_policy.allowed_roots and not self._matches_allowed_root(
            normalized_relative
        ):
            allowed = ", ".join(self.path_policy.allowed_roots)
            raise WorkspacePathViolation(
                f"Path is outside allowed workspace roots: {normalized_relative}. "
                f"Allowed roots: {allowed}."
            )

        return normalized_candidate

    def relative_path(self, path: Path) -> str:
        resolved = path.expanduser().resolve()
        if not _is_relative_to(resolved, self.workspace_root):
            raise WorkspacePathViolation(
                f"Resolved path is outside workspace root: {resolved}"
            )
        return resolved.relative_to(self.workspace_root).as_posix()

    def _matches_allowed_root(self, normalized_relative: str) -> bool:
        parts = tuple(Path(normalized_relative).parts)

        for allowed_root in self.path_policy.allowed_roots:
            allowed_parts = tuple(Path(allowed_root).parts)
            if _path_parts_start_with(parts, allowed_parts):
                return True

        return False

    def _matches_blocked_root(self, normalized_relative: str) -> bool:
        parts = tuple(Path(normalized_relative).parts)

        for blocked_root in self.path_policy.blocked_roots:
            blocked_parts = tuple(Path(blocked_root).parts)
            if _path_parts_start_with(parts, blocked_parts):
                return True

        return False


@dataclass(frozen=True, slots=True)
class WorkspaceFileReadTool:
    """
    Governed read-only file tool.

    This tool does not decide whether it is allowed to run. The policy/gateway
    layer must make that decision first. The tool still enforces workspace path
    safety locally so direct misuse cannot escape the governed workspace.
    """

    workspace_root: Path
    path_policy: ToolPathPolicy | None = None
    max_bytes: int = 1_000_000
    default_encoding: str = "utf-8"

    tool_id: str = "blackfox.workspace.read_file"

    def __post_init__(self) -> None:
        if self.max_bytes <= 0:
            raise ValueError("WorkspaceFileReadTool max_bytes must be positive.")

    @property
    def manifest(self) -> ToolManifest:
        return build_workspace_file_read_manifest(
            path_policy=self.path_policy or _default_workspace_path_policy(),
        )

    def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        if request.tool_id != self.tool_id:
            return _failed_result(
                request=request,
                status=ToolInvocationStatus.FAILED,
                kind=ToolFailureKind.INVALID_REQUEST,
                message=(
                    f"WorkspaceFileReadTool expected tool_id {self.tool_id!r}; "
                    f"got {request.tool_id!r}."
                ),
            )

        if request.capability is not ToolCapability.FILE_READ:
            return _failed_result(
                request=request,
                status=ToolInvocationStatus.FAILED,
                kind=ToolFailureKind.UNSUPPORTED_CAPABILITY,
                message="WorkspaceFileReadTool only supports FILE_READ capability.",
            )

        try:
            path_argument = _require_argument_text(request.arguments, "path")
            encoding = str(request.arguments.get("encoding", self.default_encoding))
            resolver = WorkspacePathResolver(
                workspace_root=self.workspace_root,
                path_policy=self.path_policy or _default_workspace_path_policy(),
            )
            resolved_path = resolver.resolve(path_argument)

            if not resolved_path.exists():
                return _failed_result(
                    request=request,
                    status=ToolInvocationStatus.FAILED,
                    kind=ToolFailureKind.INVALID_REQUEST,
                    message=f"Workspace file does not exist: {path_argument}",
                )

            if not resolved_path.is_file():
                return _failed_result(
                    request=request,
                    status=ToolInvocationStatus.FAILED,
                    kind=ToolFailureKind.INVALID_REQUEST,
                    message=f"Workspace path is not a file: {path_argument}",
                )

            size_bytes = resolved_path.stat().st_size
            if size_bytes > self.max_bytes:
                return _failed_result(
                    request=request,
                    status=ToolInvocationStatus.FAILED,
                    kind=ToolFailureKind.INVALID_REQUEST,
                    message=(
                        f"Workspace file exceeds max_bytes limit "
                        f"({size_bytes} > {self.max_bytes}): {path_argument}"
                    ),
                    metadata={
                        "size_bytes": size_bytes,
                        "max_bytes": self.max_bytes,
                    },
                )

            raw_bytes = resolved_path.read_bytes()
            text = raw_bytes.decode(encoding)
            digest = hashlib.sha256(raw_bytes).hexdigest()
            relative_path = resolver.relative_path(resolved_path)

            artifact = ToolOutputArtifact.create(
                name=Path(relative_path).name,
                uri=relative_path,
                media_type="text/plain",
                sha256=digest,
                metadata={
                    "source_tool": self.tool_id,
                    "relative_path": relative_path,
                    "size_bytes": size_bytes,
                    "encoding": encoding,
                },
            )

            return ToolInvocationResult.succeeded(
                request=request,
                output={
                    "path": relative_path,
                    "size_bytes": size_bytes,
                    "sha256": digest,
                    "encoding": encoding,
                    "text": text,
                },
                artifacts=(artifact,),
                metadata={
                    "workspace_root": str(Path(self.workspace_root).resolve()),
                    "tool_id": self.tool_id,
                },
            )

        except WorkspacePathViolation as exc:
            return _failed_result(
                request=request,
                status=ToolInvocationStatus.BLOCKED,
                kind=ToolFailureKind.PATH_VIOLATION,
                message=str(exc),
            )
        except UnicodeDecodeError as exc:
            return _failed_result(
                request=request,
                status=ToolInvocationStatus.FAILED,
                kind=ToolFailureKind.EXECUTION_ERROR,
                message=f"Could not decode workspace file: {exc}",
                metadata={"encoding": str(request.arguments.get("encoding", self.default_encoding))},
            )
        except Exception as exc:
            return _failed_result(
                request=request,
                status=ToolInvocationStatus.FAILED,
                kind=ToolFailureKind.EXECUTION_ERROR,
                message=f"Workspace file read failed: {exc}",
            )


@dataclass(frozen=True, slots=True)
class WorkspaceDirectoryListTool:
    """
    Governed read-only directory listing tool.
    """

    workspace_root: Path
    path_policy: ToolPathPolicy | None = None
    max_entries: int = 500
    include_file_hashes: bool = False

    tool_id: str = "blackfox.workspace.list_directory"

    def __post_init__(self) -> None:
        if self.max_entries <= 0:
            raise ValueError("WorkspaceDirectoryListTool max_entries must be positive.")

    @property
    def manifest(self) -> ToolManifest:
        return build_workspace_directory_list_manifest(
            path_policy=self.path_policy or _default_workspace_path_policy(),
        )

    def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        if request.tool_id != self.tool_id:
            return _failed_result(
                request=request,
                status=ToolInvocationStatus.FAILED,
                kind=ToolFailureKind.INVALID_REQUEST,
                message=(
                    f"WorkspaceDirectoryListTool expected tool_id {self.tool_id!r}; "
                    f"got {request.tool_id!r}."
                ),
            )

        if request.capability is not ToolCapability.DIRECTORY_LIST:
            return _failed_result(
                request=request,
                status=ToolInvocationStatus.FAILED,
                kind=ToolFailureKind.UNSUPPORTED_CAPABILITY,
                message=(
                    "WorkspaceDirectoryListTool only supports DIRECTORY_LIST capability."
                ),
            )

        try:
            path_argument = str(request.arguments.get("path", ".")).strip() or "."
            recursive = _coerce_bool(request.arguments.get("recursive", False))
            include_hidden = _coerce_bool(request.arguments.get("include_hidden", False))
            max_entries = int(request.arguments.get("max_entries", self.max_entries))

            if max_entries <= 0:
                return _failed_result(
                    request=request,
                    status=ToolInvocationStatus.FAILED,
                    kind=ToolFailureKind.INVALID_REQUEST,
                    message="Directory list max_entries must be positive.",
                )

            resolver = WorkspacePathResolver(
                workspace_root=self.workspace_root,
                path_policy=self.path_policy or _default_workspace_path_policy(),
            )
            resolved_path = resolver.resolve(path_argument)

            if not resolved_path.exists():
                return _failed_result(
                    request=request,
                    status=ToolInvocationStatus.FAILED,
                    kind=ToolFailureKind.INVALID_REQUEST,
                    message=f"Workspace directory does not exist: {path_argument}",
                )

            if not resolved_path.is_dir():
                return _failed_result(
                    request=request,
                    status=ToolInvocationStatus.FAILED,
                    kind=ToolFailureKind.INVALID_REQUEST,
                    message=f"Workspace path is not a directory: {path_argument}",
                )

            entries = self._collect_entries(
                resolver=resolver,
                directory=resolved_path,
                recursive=recursive,
                include_hidden=include_hidden,
                max_entries=max_entries,
            )

            return ToolInvocationResult.succeeded(
                request=request,
                output={
                    "path": resolver.relative_path(resolved_path),
                    "recursive": recursive,
                    "include_hidden": include_hidden,
                    "entry_count": len(entries),
                    "truncated": len(entries) >= max_entries,
                    "entries": [entry.to_dict() for entry in entries],
                },
                metadata={
                    "workspace_root": str(Path(self.workspace_root).resolve()),
                    "tool_id": self.tool_id,
                },
            )

        except WorkspacePathViolation as exc:
            return _failed_result(
                request=request,
                status=ToolInvocationStatus.BLOCKED,
                kind=ToolFailureKind.PATH_VIOLATION,
                message=str(exc),
            )
        except Exception as exc:
            return _failed_result(
                request=request,
                status=ToolInvocationStatus.FAILED,
                kind=ToolFailureKind.EXECUTION_ERROR,
                message=f"Workspace directory listing failed: {exc}",
            )

    def _collect_entries(
        self,
        *,
        resolver: WorkspacePathResolver,
        directory: Path,
        recursive: bool,
        include_hidden: bool,
        max_entries: int,
    ) -> tuple[WorkspaceDirectoryEntry, ...]:
        collected: list[WorkspaceDirectoryEntry] = []
        paths = directory.rglob("*") if recursive else directory.iterdir()

        for path in sorted(paths, key=lambda item: item.as_posix()):
            if len(collected) >= max_entries:
                break

            relative_path = resolver.relative_path(path)
            if not include_hidden and _contains_hidden_part(relative_path):
                continue

            stat = path.stat()
            if path.is_dir():
                entry_type = "directory"
                size_bytes = None
                digest = None
            elif path.is_file():
                entry_type = "file"
                size_bytes = stat.st_size
                digest = _sha256_file(path) if self.include_file_hashes else None
            else:
                entry_type = "other"
                size_bytes = stat.st_size
                digest = None

            collected.append(
                WorkspaceDirectoryEntry(
                    path=relative_path,
                    name=path.name,
                    entry_type=entry_type,
                    size_bytes=size_bytes,
                    sha256=digest,
                )
            )

        return tuple(collected)


def build_workspace_file_read_manifest(
    *,
    path_policy: ToolPathPolicy | None = None,
) -> ToolManifest:
    return ToolManifest(
        tool_id="blackfox.workspace.read_file",
        name="Workspace Read File",
        version="0.1.0",
        summary="Read one file from a governed BlackFox workspace.",
        capabilities=(ToolCapability.FILE_READ,),
        side_effects=(ToolSideEffect.READ_WORKSPACE,),
        approval_mode=ToolApprovalMode.POLICY,
        input_schema={
            "type": "object",
            "required": ["path"],
            "properties": {
                "path": {"type": "string"},
                "encoding": {"type": "string", "default": "utf-8"},
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "required": ["path", "size_bytes", "sha256", "encoding", "text"],
        },
        default_timeout_seconds=10.0,
        path_policy=path_policy or _default_workspace_path_policy(),
        tags=("workspace", "read-only", "file"),
        metadata={
            "wave": "2",
            "tool_family": "workspace",
            "side_effect_class": "read-only",
        },
    )


def build_workspace_directory_list_manifest(
    *,
    path_policy: ToolPathPolicy | None = None,
) -> ToolManifest:
    return ToolManifest(
        tool_id="blackfox.workspace.list_directory",
        name="Workspace List Directory",
        version="0.1.0",
        summary="List files and directories inside a governed BlackFox workspace.",
        capabilities=(ToolCapability.DIRECTORY_LIST,),
        side_effects=(ToolSideEffect.READ_WORKSPACE,),
        approval_mode=ToolApprovalMode.POLICY,
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "default": "."},
                "recursive": {"type": "boolean", "default": False},
                "include_hidden": {"type": "boolean", "default": False},
                "max_entries": {"type": "integer", "minimum": 1, "default": 500},
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "required": [
                "path",
                "recursive",
                "include_hidden",
                "entry_count",
                "truncated",
                "entries",
            ],
        },
        default_timeout_seconds=10.0,
        path_policy=path_policy or _default_workspace_path_policy(),
        tags=("workspace", "read-only", "directory"),
        metadata={
            "wave": "2",
            "tool_family": "workspace",
            "side_effect_class": "read-only",
        },
    )


def _default_workspace_path_policy() -> ToolPathPolicy:
    return ToolPathPolicy(
        allowed_roots=(),
        blocked_roots=(
            ".git",
            ".env",
            ".ssh",
            "secrets",
            "credentials",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
        ),
        allow_absolute_paths=False,
    )


def _failed_result(
    *,
    request: ToolInvocationRequest,
    status: ToolInvocationStatus,
    kind: ToolFailureKind,
    message: str,
    retryable: bool = False,
    metadata: Mapping[str, Any] | None = None,
) -> ToolInvocationResult:
    return ToolInvocationResult.failed(
        request=request,
        status=status,
        failure=ToolFailure(
            kind=kind,
            message=message,
            retryable=retryable,
            metadata=dict(metadata or {}),
        ),
    )


def _require_argument_text(arguments: Mapping[str, Any], key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str):
        raise WorkspacePathViolation(f"Required argument {key!r} must be a string.")
    cleaned = value.strip()
    if not cleaned:
        raise WorkspacePathViolation(f"Required argument {key!r} must not be empty.")
    return cleaned


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    return False


def _contains_hidden_part(relative_path: str) -> bool:
    return any(part.startswith(".") for part in Path(relative_path).parts)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _path_parts_start_with(parts: tuple[str, ...], prefix: tuple[str, ...]) -> bool:
    if not prefix:
        return False
    if len(parts) < len(prefix):
        return False
    return parts[: len(prefix)] == prefix
