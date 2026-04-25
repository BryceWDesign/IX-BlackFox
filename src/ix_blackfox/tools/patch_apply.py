from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
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
from ix_blackfox.tools.patch import (
    PatchDiff,
    PatchFileChange,
    PatchFileChangeKind,
)
from ix_blackfox.tools.workspace import WorkspacePathResolver, WorkspacePathViolation


class PatchApplyWorkspaceError(RuntimeError):
    """
    Raised when a patch cannot be safely applied to a governed workspace.
    """


@dataclass(frozen=True, slots=True)
class PatchApplyFileResult:
    """
    Result for one file mutation applied by the patch tool.
    """

    path: str
    change_kind: PatchFileChangeKind
    before_sha256: str | None
    after_sha256: str | None
    bytes_written: int
    status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "change_kind": self.change_kind.value,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "bytes_written": self.bytes_written,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class PatchApplyTool:
    """
    Governed patch application tool for reserved BlackFox workspaces.

    The tool applies complete before/after patch changes only inside a workspace
    root controlled by BlackFox. By default, the workspace must contain a marker
    file named ``.blackfox-workspace`` so this tool cannot silently mutate an
    arbitrary directory that merely happens to be passed as a path.

    This tool still does not grant itself execution permission. The tool gateway
    must evaluate policy and approval before calling ``invoke``.
    """

    workspace_root: Path
    path_policy: ToolPathPolicy | None = None
    require_workspace_marker: bool = True
    workspace_marker_name: str = ".blackfox-workspace"
    encoding: str = "utf-8"

    tool_id: str = "blackfox.workspace.apply_patch"

    def __post_init__(self) -> None:
        if not self.workspace_marker_name.strip():
            raise ValueError("workspace_marker_name must not be empty.")

    @property
    def manifest(self) -> ToolManifest:
        return build_patch_apply_manifest(
            path_policy=self.path_policy or _default_patch_path_policy(),
        )

    def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        if request.tool_id != self.tool_id:
            return _failed_result(
                request=request,
                status=ToolInvocationStatus.FAILED,
                kind=ToolFailureKind.INVALID_REQUEST,
                message=(
                    f"PatchApplyTool expected tool_id {self.tool_id!r}; "
                    f"got {request.tool_id!r}."
                ),
            )

        if request.capability is not ToolCapability.PATCH_APPLY:
            return _failed_result(
                request=request,
                status=ToolInvocationStatus.FAILED,
                kind=ToolFailureKind.UNSUPPORTED_CAPABILITY,
                message="PatchApplyTool only supports PATCH_APPLY capability.",
            )

        try:
            workspace_root = self._validated_workspace_root()
            patch_diff = _patch_from_arguments(request.arguments)
            validation = patch_diff.validate()

            if not validation.is_valid:
                return _failed_result(
                    request=request,
                    status=ToolInvocationStatus.BLOCKED,
                    kind=ToolFailureKind.INVALID_REQUEST,
                    message="Patch validation failed; refusing to apply patch.",
                    metadata={
                        "patch_id": patch_diff.patch_id,
                        "validation": validation.to_dict(),
                    },
                )

            resolver = WorkspacePathResolver(
                workspace_root=workspace_root,
                path_policy=self.path_policy or _default_patch_path_policy(),
            )
            applied_results = self._apply_patch(
                patch_diff=patch_diff,
                resolver=resolver,
            )
            unified_diff = patch_diff.to_unified_diff()
            diff_digest = hashlib.sha256(unified_diff.encode(self.encoding)).hexdigest()

            artifact = ToolOutputArtifact.create(
                name=f"{patch_diff.patch_id}.diff",
                uri=f"patches/{patch_diff.patch_id}.diff",
                media_type="text/x-diff",
                sha256=diff_digest,
                metadata={
                    "patch_id": patch_diff.patch_id,
                    "changed_paths": list(patch_diff.changed_paths),
                    "file_count": patch_diff.file_count,
                    "source_tool": self.tool_id,
                },
            )

            return ToolInvocationResult.succeeded(
                request=request,
                output={
                    "patch_id": patch_diff.patch_id,
                    "patch_digest": patch_diff.digest,
                    "summary": patch_diff.summary,
                    "file_count": patch_diff.file_count,
                    "changed_paths": list(patch_diff.changed_paths),
                    "total_line_delta": patch_diff.total_line_delta,
                    "validation": validation.to_dict(),
                    "applied_files": [
                        applied_result.to_dict()
                        for applied_result in applied_results
                    ],
                    "unified_diff_sha256": diff_digest,
                },
                artifacts=(artifact,),
                metadata={
                    "workspace_root": str(workspace_root),
                    "workspace_marker": self.workspace_marker_name,
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
        except PatchApplyWorkspaceError as exc:
            return _failed_result(
                request=request,
                status=ToolInvocationStatus.BLOCKED,
                kind=ToolFailureKind.EXECUTION_ERROR,
                message=str(exc),
            )
        except Exception as exc:
            return _failed_result(
                request=request,
                status=ToolInvocationStatus.FAILED,
                kind=ToolFailureKind.EXECUTION_ERROR,
                message=f"Patch application failed: {exc}",
            )

    def _validated_workspace_root(self) -> Path:
        root = self.workspace_root.expanduser().resolve()

        if not root.exists():
            raise PatchApplyWorkspaceError(f"Workspace root does not exist: {root}")
        if not root.is_dir():
            raise PatchApplyWorkspaceError(f"Workspace root is not a directory: {root}")

        if self.require_workspace_marker:
            marker_path = root / self.workspace_marker_name
            if not marker_path.exists() or not marker_path.is_file():
                raise PatchApplyWorkspaceError(
                    "Patch application requires a reserved BlackFox workspace marker: "
                    f"{marker_path}"
                )

        return root

    def _apply_patch(
        self,
        *,
        patch_diff: PatchDiff,
        resolver: WorkspacePathResolver,
    ) -> tuple[PatchApplyFileResult, ...]:
        applied: list[PatchApplyFileResult] = []

        for change in patch_diff.file_changes:
            target_path = resolver.resolve(change.path)

            if change.change_kind is PatchFileChangeKind.ADD:
                applied.append(self._apply_add(change=change, target_path=target_path))
                continue

            if change.change_kind is PatchFileChangeKind.MODIFY:
                applied.append(
                    self._apply_modify(change=change, target_path=target_path)
                )
                continue

            if change.change_kind is PatchFileChangeKind.DELETE:
                applied.append(
                    self._apply_delete(change=change, target_path=target_path)
                )
                continue

            raise PatchApplyWorkspaceError(
                f"Unsupported patch change kind: {change.change_kind.value}"
            )

        return tuple(applied)

    def _apply_add(
        self,
        *,
        change: PatchFileChange,
        target_path: Path,
    ) -> PatchApplyFileResult:
        if target_path.exists():
            raise PatchApplyWorkspaceError(
                f"ADD change refuses to overwrite existing file: {change.path}"
            )
        if change.after_text is None:
            raise PatchApplyWorkspaceError(
                f"ADD change is missing after_text: {change.path}"
            )

        target_path.parent.mkdir(parents=True, exist_ok=True)
        encoded = change.after_text.encode(self.encoding)
        target_path.write_bytes(encoded)
        after_sha256 = _sha256_file(target_path)

        if after_sha256 != change.after_sha256:
            raise PatchApplyWorkspaceError(
                f"ADD change produced unexpected digest for {change.path!r}."
            )

        return PatchApplyFileResult(
            path=change.path,
            change_kind=change.change_kind,
            before_sha256=None,
            after_sha256=after_sha256,
            bytes_written=len(encoded),
            status="applied",
        )

    def _apply_modify(
        self,
        *,
        change: PatchFileChange,
        target_path: Path,
    ) -> PatchApplyFileResult:
        if not target_path.exists():
            raise PatchApplyWorkspaceError(
                f"MODIFY change target does not exist: {change.path}"
            )
        if not target_path.is_file():
            raise PatchApplyWorkspaceError(
                f"MODIFY change target is not a file: {change.path}"
            )
        if change.before_text is None or change.after_text is None:
            raise PatchApplyWorkspaceError(
                f"MODIFY change requires before_text and after_text: {change.path}"
            )

        current_text = target_path.read_text(encoding=self.encoding)
        current_sha256 = _sha256_text(current_text)

        if current_sha256 != change.before_sha256:
            raise PatchApplyWorkspaceError(
                f"MODIFY change before_sha256 mismatch for {change.path!r}."
            )
        if current_text != change.before_text:
            raise PatchApplyWorkspaceError(
                f"MODIFY change before_text mismatch for {change.path!r}."
            )

        encoded = change.after_text.encode(self.encoding)
        target_path.write_bytes(encoded)
        after_sha256 = _sha256_file(target_path)

        if after_sha256 != change.after_sha256:
            raise PatchApplyWorkspaceError(
                f"MODIFY change produced unexpected digest for {change.path!r}."
            )

        return PatchApplyFileResult(
            path=change.path,
            change_kind=change.change_kind,
            before_sha256=current_sha256,
            after_sha256=after_sha256,
            bytes_written=len(encoded),
            status="applied",
        )

    def _apply_delete(
        self,
        *,
        change: PatchFileChange,
        target_path: Path,
    ) -> PatchApplyFileResult:
        if not target_path.exists():
            raise PatchApplyWorkspaceError(
                f"DELETE change target does not exist: {change.path}"
            )
        if not target_path.is_file():
            raise PatchApplyWorkspaceError(
                f"DELETE change target is not a file: {change.path}"
            )
        if change.before_text is None:
            raise PatchApplyWorkspaceError(
                f"DELETE change requires before_text: {change.path}"
            )

        current_text = target_path.read_text(encoding=self.encoding)
        current_sha256 = _sha256_text(current_text)

        if current_sha256 != change.before_sha256:
            raise PatchApplyWorkspaceError(
                f"DELETE change before_sha256 mismatch for {change.path!r}."
            )
        if current_text != change.before_text:
            raise PatchApplyWorkspaceError(
                f"DELETE change before_text mismatch for {change.path!r}."
            )

        target_path.unlink()

        return PatchApplyFileResult(
            path=change.path,
            change_kind=change.change_kind,
            before_sha256=current_sha256,
            after_sha256=None,
            bytes_written=0,
            status="deleted",
        )


def build_patch_apply_manifest(
    *,
    path_policy: ToolPathPolicy | None = None,
) -> ToolManifest:
    return ToolManifest(
        tool_id="blackfox.workspace.apply_patch",
        name="Workspace Apply Patch",
        version="0.1.0",
        summary=(
            "Apply a validated before/after patch inside a reserved BlackFox "
            "workspace."
        ),
        capabilities=(ToolCapability.PATCH_APPLY, ToolCapability.FILE_WRITE),
        side_effects=(ToolSideEffect.WRITE_WORKSPACE,),
        approval_mode=ToolApprovalMode.ALWAYS,
        input_schema={
            "type": "object",
            "required": ["patch"],
            "properties": {
                "patch": {"type": "object"},
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "required": [
                "patch_id",
                "patch_digest",
                "summary",
                "file_count",
                "changed_paths",
                "total_line_delta",
                "validation",
                "applied_files",
                "unified_diff_sha256",
            ],
        },
        default_timeout_seconds=30.0,
        path_policy=path_policy or _default_patch_path_policy(),
        tags=("workspace", "patch", "write", "approval-required"),
        metadata={
            "wave": "2",
            "tool_family": "workspace",
            "side_effect_class": "write-workspace",
            "requires_reserved_workspace": True,
        },
    )


def _patch_from_arguments(arguments: Mapping[str, Any]) -> PatchDiff:
    raw_patch = arguments.get("patch")

    if isinstance(raw_patch, PatchDiff):
        return raw_patch

    if isinstance(raw_patch, Mapping):
        return PatchDiff.from_dict(raw_patch)

    raise PatchApplyWorkspaceError(
        "PatchApplyTool requires request.arguments['patch'] as a PatchDiff or mapping."
    )


def _default_patch_path_policy() -> ToolPathPolicy:
    return ToolPathPolicy(
        allowed_roots=(
            "src",
            "tests",
            "docs",
            "scripts",
            "examples",
            "artifacts",
        ),
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
            "dist",
            "build",
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


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
