from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Self

from ix_blackfox.tools.artifacts import ToolArtifactStore
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
from ix_blackfox.tools.patch import PatchDiff, PatchFileChange, PatchFileChangeKind
from ix_blackfox.tools.receipts import ToolInvocationReceiptLedger
from ix_blackfox.tools.workspace import WorkspacePathResolver, WorkspacePathViolation


class PatchApplyWorkspaceError(RuntimeError):
    """
    Raised when a governed patch cannot be safely applied to the workspace.
    """


@dataclass(frozen=True, slots=True)
class PatchApplyFileResult:
    """
    File-level result from one governed patch operation.
    """

    path: str
    change_kind: PatchFileChangeKind
    before_sha256: str | None
    after_sha256: str | None
    applied: bool
    bytes_before: int | None = None
    bytes_after: int | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _normalize_relative_path(self.path))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def action(self) -> str:
        return self.change_kind.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "change_kind": self.change_kind.value,
            "action": self.action,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "applied": self.applied,
            "bytes_before": self.bytes_before,
            "bytes_after": self.bytes_after,
            "metadata": dict(self.metadata),
        }


PatchApplyFileChange = PatchApplyFileResult


@dataclass(frozen=True, slots=True)
class PatchApplyOperation:
    """
    Legacy operation-list input retained for older callers.
    """

    operation: str
    path: str
    content: str | None = None
    old_text: str | None = None
    new_text: str | None = None
    expected_sha256: str | None = None

    def __post_init__(self) -> None:
        operation = self.operation.strip().lower().replace("-", "_")
        if operation not in {"create_file", "replace_file", "replace_text", "delete_file"}:
            raise ValueError(f"Unsupported patch operation: {self.operation!r}.")
        if operation in {"create_file", "replace_file"} and self.content is None:
            raise ValueError(f"{operation} requires content.")
        if operation == "replace_text" and (self.old_text is None or self.new_text is None):
            raise ValueError("replace_text requires old_text and new_text.")
        if operation == "delete_file" and any(
            value is not None for value in (self.content, self.old_text, self.new_text)
        ):
            raise ValueError("delete_file must not include content, old_text, or new_text.")

        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "path", _normalize_relative_path(self.path))
        object.__setattr__(self, "expected_sha256", _normalize_optional_sha256(self.expected_sha256))

    def to_file_change(self) -> PatchFileChange:
        metadata = {
            "source": "patch_apply_operation",
            "expected_sha256": self.expected_sha256,
        }
        if self.operation == "create_file":
            return PatchFileChange.add(path=self.path, after_text=self.content or "", metadata=metadata)
        if self.operation == "replace_file":
            return PatchFileChange.modify(
                path=self.path,
                before_text=self.old_text or "",
                after_text=self.content or "",
                metadata={**metadata, "before_text_optional": self.old_text is None},
            )
        if self.operation == "replace_text":
            return PatchFileChange.modify(
                path=self.path,
                before_text=self.old_text or "",
                after_text=self.new_text or "",
                metadata={**metadata, "replace_text": True},
            )
        return PatchFileChange.delete(
            path=self.path,
            before_text="",
            metadata={**metadata, "before_text_optional": True},
        )


@dataclass(frozen=True, slots=True)
class PatchApplyPlan:
    """
    Normalized patch-application plan accepted by PatchApplyTool.
    """

    patch: PatchDiff
    dry_run: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def patch_id(self) -> str:
        return self.patch.patch_id

    @property
    def file_changes(self) -> tuple[PatchFileChange, ...]:
        return self.patch.file_changes

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> Self:
        dry_run = _coerce_bool(payload.get("dry_run"), default=False)
        metadata = _coerce_optional_mapping(payload.get("metadata"), field_name="metadata")
        patch_payload = payload.get("patch")

        if isinstance(patch_payload, PatchDiff):
            return cls(patch=patch_payload, dry_run=dry_run, metadata=metadata)
        if isinstance(patch_payload, Mapping):
            return cls(patch=PatchDiff.from_dict(patch_payload), dry_run=dry_run, metadata=metadata)
        if "operations" in payload:
            return cls(
                patch=_patch_from_legacy_operations(payload),
                dry_run=dry_run,
                metadata={"source": "legacy_operations", **metadata},
            )
        raise ValueError("PatchApplyTool requires a PatchDiff under argument 'patch'.")


@dataclass(frozen=True, slots=True)
class PatchApplyReport:
    """
    Structured result from applying one governed patch.
    """

    patch_id: str
    applied: bool
    dry_run: bool
    file_results: tuple[PatchApplyFileResult, ...]
    message: str
    artifact_uri: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "file_results", tuple(self.file_results))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def changed_paths(self) -> tuple[str, ...]:
        return tuple(result.path for result in self.file_results)

    @property
    def file_count(self) -> int:
        return len(self.file_results)

    @property
    def file_changes(self) -> tuple[PatchApplyFileResult, ...]:
        return self.file_results

    def with_artifact(self, artifact: ToolOutputArtifact) -> PatchApplyReport:
        return PatchApplyReport(
            patch_id=self.patch_id,
            applied=self.applied,
            dry_run=self.dry_run,
            file_results=self.file_results,
            message=self.message,
            artifact_uri=artifact.uri,
            metadata={
                **dict(self.metadata),
                "artifact_id": artifact.artifact_id,
                "artifact_uri": artifact.uri,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        file_results = [result.to_dict() for result in self.file_results]
        return {
            "patch_id": self.patch_id,
            "applied": self.applied,
            "dry_run": self.dry_run,
            "file_count": self.file_count,
            "changed_paths": list(self.changed_paths),
            "file_results": file_results,
            "file_changes": file_results,
            "message": self.message,
            "artifact_uri": self.artifact_uri,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class PatchApplyTool:
    """
    Governed local patch application tool for reserved BlackFox workspaces.
    """

    workspace_root: Path
    path_policy: ToolPathPolicy | None = None
    require_workspace_marker: bool = True
    workspace_marker_name: str = ".blackfox-workspace"
    artifact_store: ToolArtifactStore | None = None
    receipt_ledger: ToolInvocationReceiptLedger | None = None

    tool_id: str = "blackfox.workspace.apply_patch"

    @property
    def manifest(self) -> ToolManifest:
        return build_patch_apply_manifest(
            path_policy=self.path_policy or _default_patch_apply_path_policy(),
        )

    def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        if request.tool_id != self.tool_id:
            return _failed_result(
                request=request,
                status=ToolInvocationStatus.FAILED,
                kind=ToolFailureKind.INVALID_REQUEST,
                message=f"PatchApplyTool expected tool_id {self.tool_id!r}; got {request.tool_id!r}.",
            )
        if request.capability is not ToolCapability.PATCH_APPLY:
            return _failed_result(
                request=request,
                status=ToolInvocationStatus.FAILED,
                kind=ToolFailureKind.UNSUPPORTED_CAPABILITY,
                message="PatchApplyTool only supports PATCH_APPLY capability.",
            )

        self._record_started(request)
        try:
            plan = PatchApplyPlan.from_payload(request.arguments)
            report = self.apply_plan(plan)
            artifacts = self._persist_report_artifact(request=request, report=report)
            if artifacts:
                report = report.with_artifact(artifacts[0])
            result = ToolInvocationResult.succeeded(
                request=request,
                output=report.to_dict(),
                artifacts=artifacts,
                metadata={
                    "workspace_root": str(self._validated_workspace_root()),
                    "tool_id": self.tool_id,
                    "artifact_uris": [artifact.uri for artifact in artifacts],
                },
            )
        except WorkspacePathViolation as exc:
            result = _failed_result(
                request=request,
                status=ToolInvocationStatus.BLOCKED,
                kind=ToolFailureKind.PATH_VIOLATION,
                message=str(exc),
            )
        except PatchApplyWorkspaceError as exc:
            result = _failed_result(
                request=request,
                status=ToolInvocationStatus.BLOCKED,
                kind=ToolFailureKind.PATH_VIOLATION,
                message=str(exc),
            )
        except ValueError as exc:
            result = _failed_result(
                request=request,
                status=ToolInvocationStatus.FAILED,
                kind=ToolFailureKind.INVALID_REQUEST,
                message=str(exc),
            )
        except Exception as exc:
            result = _failed_result(
                request=request,
                status=ToolInvocationStatus.FAILED,
                kind=ToolFailureKind.EXECUTION_ERROR,
                message=f"Governed patch application failed: {exc}",
            )

        self._record_result(request=request, result=result)
        if result.status is ToolInvocationStatus.SUCCEEDED:
            self._record_artifacts(result=result)
        return result

    def apply_plan(self, plan: PatchApplyPlan, *, dry_run: bool | None = None) -> PatchApplyReport:
        effective_dry_run = plan.dry_run if dry_run is None else dry_run
        workspace_root = self._validated_workspace_root()
        resolver = WorkspacePathResolver(
            workspace_root=workspace_root,
            path_policy=self.path_policy or _default_patch_apply_path_policy(),
        )

        file_results: list[PatchApplyFileResult] = []
        for change in plan.file_changes:
            target_path = resolver.resolve(change.path)
            relative_path = resolver.relative_path(target_path)
            if change.change_kind is PatchFileChangeKind.ADD:
                result = self._apply_add(change, target_path, relative_path, effective_dry_run)
            elif change.change_kind is PatchFileChangeKind.MODIFY:
                result = self._apply_modify(change, target_path, relative_path, effective_dry_run)
            elif change.change_kind is PatchFileChangeKind.DELETE:
                result = self._apply_delete(change, target_path, relative_path, effective_dry_run)
            else:  # pragma: no cover - PatchFileChange validates enum construction.
                raise ValueError(f"Unsupported patch change kind: {change.change_kind!r}.")
            file_results.append(result)

        return PatchApplyReport(
            patch_id=plan.patch_id,
            applied=not effective_dry_run,
            dry_run=effective_dry_run,
            file_results=tuple(file_results),
            message=(
                f"Validated {len(file_results)} patch file change(s) without writing files."
                if effective_dry_run
                else f"Applied {len(file_results)} patch file change(s)."
            ),
            metadata={
                "patch_digest": plan.patch.digest,
                "patch_summary": plan.patch.summary,
                **dict(plan.metadata),
            },
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

    def _apply_add(
        self,
        change: PatchFileChange,
        target_path: Path,
        relative_path: str,
        dry_run: bool,
    ) -> PatchApplyFileResult:
        if target_path.exists():
            raise ValueError(f"Cannot add file that already exists: {relative_path}")
        after_text = change.after_text or ""
        after_sha256 = _sha256_text(after_text)
        if change.after_sha256 != after_sha256:
            raise ValueError(f"Patch after_sha256 mismatch for added file: {relative_path}")
        if not dry_run:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text(after_text, encoding="utf-8")
        return PatchApplyFileResult(
            path=relative_path,
            change_kind=change.change_kind,
            before_sha256=None,
            after_sha256=after_sha256,
            applied=not dry_run,
            bytes_after=len(after_text.encode("utf-8")),
        )

    def _apply_modify(
        self,
        change: PatchFileChange,
        target_path: Path,
        relative_path: str,
        dry_run: bool,
    ) -> PatchApplyFileResult:
        if not target_path.exists():
            raise ValueError(f"Cannot modify missing file: {relative_path}")
        if not target_path.is_file():
            raise ValueError(f"Cannot modify non-file path: {relative_path}")

        current_text = target_path.read_text(encoding="utf-8")
        before_text = change.before_text or ""
        after_text = change.after_text or ""
        current_sha256 = _sha256_text(current_text)
        expected_sha256 = _expected_before_sha256(change)
        if expected_sha256 is not None and expected_sha256 != current_sha256:
            raise ValueError(
                "Patch before_sha256 mismatch for "
                f"{relative_path}: expected {expected_sha256}, got {current_sha256}."
            )

        if change.metadata.get("replace_text") is True:
            occurrences = current_text.count(before_text)
            if occurrences != 1:
                raise ValueError(
                    "replace_text requires exactly one old_text match for "
                    f"{relative_path}; found {occurrences}."
                )
            final_text = current_text.replace(before_text, after_text, 1)
        else:
            if change.metadata.get("before_text_optional") is not True and current_text != before_text:
                raise ValueError(
                    "Patch before_text mismatch for "
                    f"{relative_path}; refusing non-deterministic modification."
                )
            final_text = after_text

        after_sha256 = _sha256_text(final_text)
        if change.after_sha256 != after_sha256 and change.metadata.get("replace_text") is not True:
            raise ValueError(f"Patch after_sha256 mismatch for modified file: {relative_path}")
        if not dry_run:
            target_path.write_text(final_text, encoding="utf-8")
        return PatchApplyFileResult(
            path=relative_path,
            change_kind=change.change_kind,
            before_sha256=current_sha256,
            after_sha256=after_sha256,
            applied=not dry_run,
            bytes_before=len(current_text.encode("utf-8")),
            bytes_after=len(final_text.encode("utf-8")),
        )

    def _apply_delete(
        self,
        change: PatchFileChange,
        target_path: Path,
        relative_path: str,
        dry_run: bool,
    ) -> PatchApplyFileResult:
        if not target_path.exists():
            raise ValueError(f"Cannot delete missing file: {relative_path}")
        if not target_path.is_file():
            raise ValueError(f"Cannot delete non-file path: {relative_path}")

        current_text = target_path.read_text(encoding="utf-8")
        before_text = change.before_text or ""
        current_sha256 = _sha256_text(current_text)
        expected_sha256 = _expected_before_sha256(change)
        if expected_sha256 is not None and expected_sha256 != current_sha256:
            raise ValueError(
                "Patch before_sha256 mismatch for "
                f"{relative_path}: expected {expected_sha256}, got {current_sha256}."
            )
        if (
            change.metadata.get("before_text_optional") is not True
            and before_text
            and current_text != before_text
        ):
            raise ValueError(
                "Patch before_text mismatch for "
                f"{relative_path}; refusing non-deterministic deletion."
            )
        if not dry_run:
            target_path.unlink()
        return PatchApplyFileResult(
            path=relative_path,
            change_kind=change.change_kind,
            before_sha256=current_sha256,
            after_sha256=None,
            applied=not dry_run,
            bytes_before=len(current_text.encode("utf-8")),
        )

    def _persist_report_artifact(
        self,
        *,
        request: ToolInvocationRequest,
        report: PatchApplyReport,
    ) -> tuple[ToolOutputArtifact, ...]:
        if self.artifact_store is None:
            return ()
        run_segment = request.run_id or request.invocation_id
        artifact = self.artifact_store.write_json(
            relative_path=f"patches/{run_segment}/{request.invocation_id}/patch-apply-report.json",
            payload=report.to_dict(),
            metadata={
                "source_tool": self.tool_id,
                "artifact_kind": "patch_apply_report",
                "invocation_id": request.invocation_id,
                "run_id": request.run_id,
                "patch_id": report.patch_id,
            },
        )
        return (artifact,)

    def _record_started(self, request: ToolInvocationRequest) -> None:
        if self.receipt_ledger is not None:
            self.receipt_ledger.record_invocation_started(request=request, actor="tools.patch_apply")

    def _record_result(self, *, request: ToolInvocationRequest, result: ToolInvocationResult) -> None:
        if self.receipt_ledger is not None:
            self.receipt_ledger.record_invocation_result(
                result=result,
                request=request,
                actor="tools.patch_apply",
            )

    def _record_artifacts(self, *, result: ToolInvocationResult) -> None:
        if self.receipt_ledger is None:
            return
        for artifact in result.artifacts:
            self.receipt_ledger.record_artifact_emitted(
                result=result,
                artifact_name=artifact.name,
                artifact_uri=artifact.uri,
                actor="tools.patch_apply",
                metadata={
                    "artifact_id": artifact.artifact_id,
                    "sha256": artifact.sha256,
                    "media_type": artifact.media_type,
                },
            )


def build_patch_apply_manifest(*, path_policy: ToolPathPolicy | None = None) -> ToolManifest:
    return ToolManifest(
        tool_id="blackfox.workspace.apply_patch",
        name="Workspace Apply Patch",
        version="0.1.0",
        summary="Apply deterministic PatchDiff changes inside a reserved BlackFox workspace.",
        capabilities=(ToolCapability.PATCH_APPLY, ToolCapability.FILE_WRITE),
        side_effects=(ToolSideEffect.READ_WORKSPACE, ToolSideEffect.WRITE_WORKSPACE),
        approval_mode=ToolApprovalMode.ALWAYS,
        input_schema={
            "type": "object",
            "properties": {
                "patch": {"type": "object"},
                "dry_run": {"type": "boolean", "default": False},
                "metadata": {"type": "object"},
            },
            "required": ["patch"],
            "additionalProperties": True,
        },
        output_schema={
            "type": "object",
            "required": [
                "patch_id",
                "applied",
                "dry_run",
                "file_count",
                "changed_paths",
                "file_results",
                "message",
            ],
        },
        default_timeout_seconds=60.0,
        path_policy=path_policy or _default_patch_apply_path_policy(),
        tags=("workspace", "patch", "filesystem", "approval-required"),
        metadata={
            "wave": "2",
            "tool_family": "workspace",
            "side_effect_class": "workspace-write",
            "requires_reserved_workspace": True,
            "deterministic_patch_model": "PatchDiff",
        },
    )


def _default_patch_apply_path_policy() -> ToolPathPolicy:
    return ToolPathPolicy(
        allowed_roots=(".", "src", "tests", "scripts", "docs", "examples"),
        blocked_roots=(".git", ".env", ".ssh", "secrets", "credentials", "dist", "build"),
        allow_absolute_paths=False,
    )


def _patch_from_legacy_operations(payload: Mapping[str, Any]) -> PatchDiff:
    raw_operations = payload.get("operations")
    if not isinstance(raw_operations, Iterable) or isinstance(raw_operations, str):
        raise ValueError("Patch apply payload operations must be an iterable.")
    operations: list[PatchApplyOperation] = []
    for raw_operation in raw_operations:
        if not isinstance(raw_operation, Mapping):
            raise ValueError("Patch apply operations must all be mapping objects.")
        operations.append(
            PatchApplyOperation(
                operation=_require_text(raw_operation, "operation"),
                path=_require_text(raw_operation, "path"),
                content=_optional_text(raw_operation, "content"),
                old_text=_optional_text(raw_operation, "old_text"),
                new_text=_optional_text(raw_operation, "new_text"),
                expected_sha256=_optional_text(raw_operation, "expected_sha256"),
            )
        )
    if not operations:
        raise ValueError("Patch apply plan must include at least one operation.")
    return PatchDiff.create(
        summary=str(payload.get("summary", "Legacy patch apply operations.")),
        file_changes=tuple(operation.to_file_change() for operation in operations),
        created_by=str(payload.get("created_by", "blackfox-patch-apply")),
        metadata={"plan_id": _optional_text(payload, "plan_id"), "source": "legacy_operations"},
    )


def _expected_before_sha256(change: PatchFileChange) -> str | None:
    raw_expected = change.metadata.get("expected_sha256")
    if isinstance(raw_expected, str) and raw_expected.strip():
        return _normalize_optional_sha256(raw_expected)
    if change.metadata.get("before_text_optional") is True or change.metadata.get("replace_text") is True:
        return None
    return change.before_sha256


def _failed_result(
    *,
    request: ToolInvocationRequest,
    status: ToolInvocationStatus,
    kind: ToolFailureKind,
    message: str,
    metadata: Mapping[str, Any] | None = None,
) -> ToolInvocationResult:
    return ToolInvocationResult.failed(
        request=request,
        status=status,
        failure=ToolFailure(
            kind=kind,
            message=message,
            retryable=False,
            metadata=dict(metadata or {}),
        ),
    )


def _normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("Patch path must not be empty.")
    if cleaned.startswith(("/", "~")):
        raise ValueError(f"Patch path must be relative: {value!r}.")
    parts: list[str] = []
    for raw_part in cleaned.split("/"):
        part = raw_part.strip()
        if part in {"", "."}:
            continue
        if part == "..":
            raise ValueError(f"Patch path must not contain traversal: {value!r}.")
        parts.append(part)
    if not parts:
        raise ValueError("Patch path must not resolve to the workspace root.")
    return "/".join(parts)


def _normalize_optional_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().lower()
    if not cleaned:
        return None
    if len(cleaned) != 64:
        raise ValueError("expected_sha256 must be a 64-character SHA-256 digest.")
    int(cleaned, 16)
    return cleaned


def _coerce_bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _coerce_optional_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping when provided.")
    return dict(value)


def _require_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError(f"Patch apply field {key!r} must be a string.")
    return value


def _optional_text(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"Patch apply field {key!r} must be a string when provided.")
    return value


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
