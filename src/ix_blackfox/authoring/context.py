from __future__ import annotations

import fnmatch
import hashlib
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from pathlib import Path
from typing import Any, Self

from ix_blackfox.authoring.errors import AuthoringContextError
from ix_blackfox.authoring.models import AuthoringContext, AuthoringContextFile
from ix_blackfox.tools.manifest import ToolPathPolicy
from ix_blackfox.tools.workspace import WorkspacePathResolver, WorkspacePathViolation


class ContextSkipReason(StrEnum):
    """
    Reason a workspace path was excluded from Wave 3 authoring context.
    """

    BLOCKED_PATH = auto()
    BINARY_FILE = auto()
    DECODE_ERROR = auto()
    DUPLICATE_PATH = auto()
    FILE_TOO_LARGE = auto()
    HIDDEN_PATH = auto()
    NOT_FOUND = auto()
    NOT_REGULAR_FILE = auto()
    PATH_POLICY_VIOLATION = auto()
    SECRET_LIKE_PATH = auto()
    SYMLINK = auto()
    TOTAL_BYTES_LIMIT = auto()


@dataclass(frozen=True, slots=True)
class SkippedContextPath:
    """
    One path excluded from a bounded authoring context snapshot.
    """

    path: str
    reason: ContextSkipReason
    detail: str

    def __post_init__(self) -> None:
        path = self.path.strip().replace("\\", "/")
        detail = self.detail.strip()
        if not path:
            raise ValueError("Skipped context path must not be empty.")
        if not detail:
            raise ValueError("Skipped context detail must not be empty.")
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "detail", detail)

    def to_dict(self) -> dict[str, str]:
        return {
            "path": self.path,
            "reason": self.reason.value,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class AuthoringContextDocument:
    """
    Bounded text content admitted into a Wave 3 context snapshot.

    The persisted AuthoringContext manifest stores digest metadata. This object
    carries the actual text payload for prompt construction and later authoring
    stages without putting large text blobs into the manifest digest model.
    """

    path: str
    text: str
    sha256: str
    size_bytes: int
    encoding: str = "utf-8"

    def __post_init__(self) -> None:
        path = _normalize_relative_path(self.path)
        encoding = self.encoding.strip().lower()
        if not encoding:
            raise ValueError("Context document encoding must not be empty.")
        if self.size_bytes < 0:
            raise ValueError("Context document size_bytes must be zero or greater.")
        if len(self.sha256) != 64 or any(
            char not in "0123456789abcdef" for char in self.sha256
        ):
            raise ValueError("Context document sha256 must be a lowercase digest.")
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "encoding", encoding)

    def to_context_file(self) -> AuthoringContextFile:
        return AuthoringContextFile(
            path=self.path,
            sha256=self.sha256,
            size_bytes=self.size_bytes,
            purpose="wave3_authoring_context",
            metadata={"encoding": self.encoding},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "encoding": self.encoding,
            "text": self.text,
        }


@dataclass(frozen=True, slots=True)
class AuthoringContextBuilderConfig:
    """
    Limits and filters for bounded Wave 3 repository context collection.
    """

    include_paths: tuple[str, ...] = (".",)
    max_file_bytes: int = 64_000
    max_total_bytes: int = 256_000
    include_hidden: bool = False
    follow_symlinks: bool = False
    encoding: str = "utf-8"
    blocked_roots: tuple[str, ...] = (
        ".git",
        ".hg",
        ".svn",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "artifacts",
        "build",
        "dist",
        "env",
        "node_modules",
        "run_bundles",
        "venv",
    )
    secret_file_globs: tuple[str, ...] = (
        ".env",
        ".env.*",
        "*credentials*",
        "*secret*",
        "*token*",
        "*private-key*",
        "*private_key*",
        "authorized_keys",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "known_hosts",
    )
    secret_dir_names: tuple[str, ...] = (
        ".aws",
        ".azure",
        ".config/gcloud",
        ".docker",
        ".gnupg",
        ".kube",
        ".ssh",
    )

    def __post_init__(self) -> None:
        if self.max_file_bytes <= 0:
            raise ValueError("max_file_bytes must be positive.")
        if self.max_total_bytes <= 0:
            raise ValueError("max_total_bytes must be positive.")
        encoding = self.encoding.strip().lower()
        if not encoding:
            raise ValueError("encoding must not be empty.")
        object.__setattr__(self, "encoding", encoding)
        object.__setattr__(
            self,
            "include_paths",
            _normalize_path_tuple(self.include_paths, field_name="include_paths"),
        )
        object.__setattr__(
            self,
            "blocked_roots",
            _normalize_path_tuple(self.blocked_roots, field_name="blocked_roots"),
        )
        object.__setattr__(
            self,
            "secret_file_globs",
            _normalize_glob_tuple(
                self.secret_file_globs,
                field_name="secret_file_globs",
            ),
        )
        object.__setattr__(
            self,
            "secret_dir_names",
            _normalize_path_tuple(
                self.secret_dir_names,
                field_name="secret_dir_names",
            ),
        )

    def build_path_policy(self) -> ToolPathPolicy:
        return ToolPathPolicy(
            blocked_roots=self.blocked_roots,
            allow_absolute_paths=False,
        )


@dataclass(frozen=True, slots=True)
class AuthoringContextSnapshot:
    """
    Complete bounded context collection result.
    """

    context: AuthoringContext
    documents: tuple[AuthoringContextDocument, ...] = field(default_factory=tuple)
    skipped: tuple[SkippedContextPath, ...] = field(default_factory=tuple)
    truncated: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        documents = tuple(self.documents)
        skipped = tuple(self.skipped)
        object.__setattr__(self, "documents", documents)
        object.__setattr__(self, "skipped", skipped)
        object.__setattr__(self, "metadata", dict(self.metadata))

        manifest_paths = self.context.paths
        document_paths = tuple(document.path for document in documents)
        if manifest_paths != document_paths:
            raise ValueError(
                "AuthoringContext manifest paths must match document paths."
            )

    @property
    def skip_reason_counts(self) -> dict[str, int]:
        counts = Counter(item.reason.value for item in self.skipped)
        return dict(sorted(counts.items()))

    def document_by_path(self, path: str) -> AuthoringContextDocument:
        normalized = _normalize_relative_path(path)
        for document in self.documents:
            if document.path == normalized:
                return document
        raise KeyError(f"Context document not found: {normalized}")

    def to_manifest_dict(self) -> dict[str, Any]:
        return {
            "context": self.context.to_dict(),
            "document_count": len(self.documents),
            "skipped_count": len(self.skipped),
            "skip_reason_counts": self.skip_reason_counts,
            "truncated": self.truncated,
            "skipped": [item.to_dict() for item in self.skipped],
            "metadata": dict(self.metadata),
        }


class AuthoringContextBuilder:
    """
    Read-only, bounded repository context builder for Wave 3 authoring.

    The builder collects text files deterministically from a governed workspace,
    enforces size limits, excludes obvious secret-bearing paths, records skipped
    paths, and returns both text documents and a digest-only AuthoringContext
    manifest.
    """

    def __init__(
        self,
        *,
        workspace_root: Path,
        config: AuthoringContextBuilderConfig | None = None,
        path_policy: ToolPathPolicy | None = None,
    ) -> None:
        self.config = config or AuthoringContextBuilderConfig()
        self.workspace_root = workspace_root.expanduser().resolve()
        if not self.workspace_root.exists():
            raise AuthoringContextError(
                f"Workspace root does not exist: {self.workspace_root}"
            )
        if not self.workspace_root.is_dir():
            raise AuthoringContextError(
                f"Workspace root is not a directory: {self.workspace_root}"
            )

        self.path_policy = path_policy or self.config.build_path_policy()
        self.resolver = WorkspacePathResolver(
            workspace_root=self.workspace_root,
            path_policy=self.path_policy,
        )

    def build(self, include_paths: Iterable[str] | None = None) -> AuthoringContextSnapshot:
        requested_paths = tuple(include_paths or self.config.include_paths)
        if not requested_paths:
            raise AuthoringContextError("At least one include path is required.")

        skipped: list[SkippedContextPath] = []
        candidates = self._collect_candidates(
            requested_paths=requested_paths,
            skipped=skipped,
        )

        documents: list[AuthoringContextDocument] = []
        seen_paths: set[str] = set()
        total_bytes = 0
        truncated = False

        for candidate in candidates:
            relative_path = self.resolver.relative_path(candidate)

            if relative_path in seen_paths:
                skipped.append(
                    SkippedContextPath(
                        path=relative_path,
                        reason=ContextSkipReason.DUPLICATE_PATH,
                        detail="Path was already admitted or evaluated.",
                    )
                )
                continue

            seen_paths.add(relative_path)
            document = self._read_candidate(
                path=candidate,
                relative_path=relative_path,
                skipped=skipped,
            )
            if document is None:
                continue

            if total_bytes + document.size_bytes > self.config.max_total_bytes:
                truncated = True
                skipped.append(
                    SkippedContextPath(
                        path=relative_path,
                        reason=ContextSkipReason.TOTAL_BYTES_LIMIT,
                        detail=(
                            "File would exceed max_total_bytes "
                            f"({total_bytes + document.size_bytes} > "
                            f"{self.config.max_total_bytes})."
                        ),
                    )
                )
                continue

            documents.append(document)
            total_bytes += document.size_bytes

        context_files = tuple(document.to_context_file() for document in documents)
        context = AuthoringContext.create(
            files=context_files,
            metadata={
                "builder": "AuthoringContextBuilder",
                "max_file_bytes": self.config.max_file_bytes,
                "max_total_bytes": self.config.max_total_bytes,
                "include_hidden": self.config.include_hidden,
                "follow_symlinks": self.config.follow_symlinks,
                "requested_paths": list(requested_paths),
                "skipped_count": len(skipped),
            },
        )

        return AuthoringContextSnapshot(
            context=context,
            documents=tuple(documents),
            skipped=tuple(skipped),
            truncated=truncated,
            metadata={
                "workspace_root": str(self.workspace_root),
                "path_policy": self.path_policy.to_dict(),
            },
        )

    def _collect_candidates(
        self,
        *,
        requested_paths: tuple[str, ...],
        skipped: list[SkippedContextPath],
    ) -> tuple[Path, ...]:
        candidates: list[Path] = []

        for requested_path in requested_paths:
            normalized_request = requested_path.strip().replace("\\", "/")
            if not normalized_request:
                skipped.append(
                    SkippedContextPath(
                        path="<empty>",
                        reason=ContextSkipReason.PATH_POLICY_VIOLATION,
                        detail="Requested include path was empty.",
                    )
                )
                continue

            try:
                raw_path = (
                    Path(normalized_request)
                    if Path(normalized_request).is_absolute()
                    else self.workspace_root / normalized_request
                )
                if raw_path.is_symlink() and not self.config.follow_symlinks:
                    skipped.append(
                        SkippedContextPath(
                            path=normalized_request,
                            reason=ContextSkipReason.SYMLINK,
                            detail="Symlink include path refused by context policy.",
                        )
                    )
                    continue

                resolved = self.resolver.resolve(normalized_request)
            except WorkspacePathViolation as exc:
                skipped.append(
                    SkippedContextPath(
                        path=normalized_request,
                        reason=ContextSkipReason.PATH_POLICY_VIOLATION,
                        detail=str(exc),
                    )
                )
                continue

            if not resolved.exists():
                skipped.append(
                    SkippedContextPath(
                        path=normalized_request,
                        reason=ContextSkipReason.NOT_FOUND,
                        detail="Requested include path does not exist.",
                    )
                )
                continue

            if resolved.is_file():
                candidates.append(resolved)
                continue

            if resolved.is_dir():
                candidates.extend(self._walk_directory(resolved, skipped=skipped))
                continue

            skipped.append(
                SkippedContextPath(
                    path=normalized_request,
                    reason=ContextSkipReason.NOT_REGULAR_FILE,
                    detail="Requested path is not a regular file or directory.",
                )
            )

        return tuple(sorted(candidates, key=lambda path: self.resolver.relative_path(path)))

    def _walk_directory(
        self,
        directory: Path,
        *,
        skipped: list[SkippedContextPath],
    ) -> tuple[Path, ...]:
        candidates: list[Path] = []

        for child in sorted(directory.rglob("*"), key=lambda path: path.as_posix()):
            relative_path = self.resolver.relative_path(child)

            if child.is_symlink() and not self.config.follow_symlinks:
                skipped.append(
                    SkippedContextPath(
                        path=relative_path,
                        reason=ContextSkipReason.SYMLINK,
                        detail="Symlink refused by context policy.",
                    )
                )
                continue

            if not child.is_file():
                continue

            candidates.append(child)

        return tuple(candidates)

    def _read_candidate(
        self,
        *,
        path: Path,
        relative_path: str,
        skipped: list[SkippedContextPath],
    ) -> AuthoringContextDocument | None:
        try:
            self.resolver.resolve(relative_path)
        except WorkspacePathViolation as exc:
            skipped.append(
                SkippedContextPath(
                    path=relative_path,
                    reason=ContextSkipReason.PATH_POLICY_VIOLATION,
                    detail=str(exc),
                )
            )
            return None

        if self._is_config_blocked(relative_path):
            skipped.append(
                SkippedContextPath(
                    path=relative_path,
                    reason=ContextSkipReason.BLOCKED_PATH,
                    detail="Path matched a blocked authoring context root.",
                )
            )
            return None

        if not self.config.include_hidden and _has_hidden_path_part(relative_path):
            skipped.append(
                SkippedContextPath(
                    path=relative_path,
                    reason=ContextSkipReason.HIDDEN_PATH,
                    detail="Hidden paths are excluded by default.",
                )
            )
            return None

        if self._is_secret_like(relative_path):
            skipped.append(
                SkippedContextPath(
                    path=relative_path,
                    reason=ContextSkipReason.SECRET_LIKE_PATH,
                    detail="Path matched secret-like file or directory patterns.",
                )
            )
            return None

        if not path.is_file():
            skipped.append(
                SkippedContextPath(
                    path=relative_path,
                    reason=ContextSkipReason.NOT_REGULAR_FILE,
                    detail="Path is not a regular file.",
                )
            )
            return None

        size_bytes = path.stat().st_size
        if size_bytes > self.config.max_file_bytes:
            skipped.append(
                SkippedContextPath(
                    path=relative_path,
                    reason=ContextSkipReason.FILE_TOO_LARGE,
                    detail=(
                        f"File exceeds max_file_bytes "
                        f"({size_bytes} > {self.config.max_file_bytes})."
                    ),
                )
            )
            return None

        raw_bytes = path.read_bytes()
        if _looks_binary(raw_bytes):
            skipped.append(
                SkippedContextPath(
                    path=relative_path,
                    reason=ContextSkipReason.BINARY_FILE,
                    detail="File appears to be binary and was excluded.",
                )
            )
            return None

        try:
            text = raw_bytes.decode(self.config.encoding)
        except UnicodeDecodeError as exc:
            skipped.append(
                SkippedContextPath(
                    path=relative_path,
                    reason=ContextSkipReason.DECODE_ERROR,
                    detail=f"Could not decode file as {self.config.encoding}: {exc}",
                )
            )
            return None

        return AuthoringContextDocument(
            path=relative_path,
            text=text,
            sha256=hashlib.sha256(raw_bytes).hexdigest(),
            size_bytes=size_bytes,
            encoding=self.config.encoding,
        )

    def _is_config_blocked(self, relative_path: str) -> bool:
        path_parts = tuple(Path(relative_path).parts)

        for blocked_root in self.config.blocked_roots:
            blocked_parts = tuple(Path(blocked_root).parts)
            if _path_parts_start_with(path_parts, blocked_parts):
                return True

        return False

    def _is_secret_like(self, relative_path: str) -> bool:
        lowered_path = relative_path.lower()
        lowered_name = Path(relative_path).name.lower()
        path_parts = tuple(part.lower() for part in Path(relative_path).parts)

        for secret_dir in self.config.secret_dir_names:
            secret_parts = tuple(Path(secret_dir.lower()).parts)
            if _path_parts_start_with(path_parts, secret_parts):
                return True
            if any(part == secret_dir.lower() for part in path_parts):
                return True

        for pattern in self.config.secret_file_globs:
            lowered_pattern = pattern.lower()
            if fnmatch.fnmatch(lowered_name, lowered_pattern):
                return True
            if fnmatch.fnmatch(lowered_path, lowered_pattern):
                return True

        return False


def _normalize_path_tuple(values: Iterable[str], *, field_name: str) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise TypeError(f"{field_name} must contain only strings.")
        cleaned = value.strip().replace("\\", "/")
        if not cleaned:
            raise ValueError(f"{field_name} must not contain empty paths.")
        normalized.append(cleaned)
    return tuple(normalized)


def _normalize_glob_tuple(values: Iterable[str], *, field_name: str) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise TypeError(f"{field_name} must contain only strings.")
        cleaned = value.strip().replace("\\", "/").lower()
        if not cleaned:
            raise ValueError(f"{field_name} must not contain empty patterns.")
        normalized.append(cleaned)
    return tuple(normalized)


def _normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("Relative path must not be empty.")
    if cleaned.startswith(("/", "~")) or ":" in cleaned.split("/")[0]:
        raise ValueError(f"Path must be relative: {value!r}.")

    parts: list[str] = []
    for raw_part in cleaned.split("/"):
        part = raw_part.strip()
        if part in {"", "."}:
            continue
        if part == "..":
            raise ValueError(f"Path traversal is not allowed: {value!r}.")
        parts.append(part)

    if not parts:
        raise ValueError("Relative path must not resolve to workspace root.")
    return "/".join(parts)


def _has_hidden_path_part(relative_path: str) -> bool:
    return any(part.startswith(".") for part in Path(relative_path).parts)


def _looks_binary(raw_bytes: bytes) -> bool:
    if not raw_bytes:
        return False

    if b"\x00" in raw_bytes:
        return True

    sample = raw_bytes[:1024]
    control_bytes = 0
    for byte in sample:
        if byte in {9, 10, 13}:
            continue
        if byte < 32:
            control_bytes += 1

    return control_bytes > max(4, len(sample) // 20)


def _path_parts_start_with(path_parts: tuple[str, ...], root_parts: tuple[str, ...]) -> bool:
    if not root_parts:
        return False
    if len(path_parts) < len(root_parts):
        return False
    return path_parts[: len(root_parts)] == root_parts
