from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
    ToolParameter,
    ToolRiskLevel,
    ToolSideEffect,
)


@dataclass(frozen=True, slots=True)
class PatchApplyFileChange:
    """
    One file-level change produced by the patch application tool.
    """

    path: str
    before_sha256: str | None
    after_sha256: str | None
    action: str


@dataclass(frozen=True, slots=True)
class PatchApplyOperation:
    """
    One normalized patch-apply operation.

    Attributes
    ----------
    operation:
        Operation type. Supported values are create_file, replace_file,
        replace_text, and delete_file.
    path:
        Workspace-relative target file path.
    content:
        New full file content for create_file or replace_file.
    old_text:
        Exact text to replace for replace_text.
    new_text:
        Replacement text for replace_text.
    expected_sha256:
        Optional expected current SHA-256 digest for optimistic concurrency.
    """

    operation: str
    path: str
    content: str | None = None
    old_text: str | None = None
    new_text: str | None = None
    expected_sha256: str | None = None

    def __post_init__(self) -> None:
        normalized_operation = _normalize_operation(self.operation)
        normalized_path = _normalize_relative_path(self.path)
        normalized_expected_sha256 = _normalize_optional_sha256(self.expected_sha256)

        object.__setattr__(self, "operation", normalized_operation)
        object.__setattr__(self, "path", normalized_path)
        object.__setattr__(self, "expected_sha256", normalized_expected_sha256)

        if normalized_operation in {"create_file", "replace_file"}:
            if self.content is None:
                raise ValueError(f"{normalized_operation} requires content.")

        if normalized_operation == "replace_text":
            if self.old_text is None:
                raise ValueError("replace_text requires old_text.")
            if self.new_text is None:
                raise ValueError("replace_text requires new_text.")

        if normalized_operation == "delete_file" and self.content is not None:
            raise ValueError("delete_file must not include content.")


@dataclass(frozen=True, slots=True)
class PatchApplyPlan:
    """
    Normalized patch-apply plan accepted by the tool.
    """

    operations: tuple[PatchApplyOperation, ...]
    plan_id: str | None = None
    metadata: Mapping[str, Any] | None = None

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> PatchApplyPlan:
        raw_operations = payload.get("operations")
        if not isinstance(raw_operations, list | tuple):
            raise ValueError("Patch apply payload requires an operations list.")

        operations = tuple(
            PatchApplyOperation(
                operation=_require_text(item, "operation"),
                path=_require_text(item, "path"),
                content=_optional_text(item, "content"),
                old_text=_optional_text(item, "old_text"),
                new_text=_optional_text(item, "new_text"),
                expected_sha256=_optional_text(item, "expected_sha256"),
            )
            for item in raw_operations
            if isinstance(item, Mapping)
        )

        if len(operations) != len(raw_operations):
            raise ValueError("Patch apply operations must all be mapping objects.")
        if not operations:
            raise ValueError("Patch apply plan must include at least one operation.")

        raw_metadata = payload.get("metadata")
        metadata: Mapping[str, Any] | None
        if raw_metadata is None:
            metadata = None
        elif isinstance(raw_metadata, Mapping):
            metadata = dict(raw_metadata)
        else:
            raise ValueError("Patch apply metadata must be a mapping when provided.")

        return cls(
            operations=operations,
            plan_id=_optional_text(payload, "plan_id"),
            metadata=metadata,
        )

    def __post_init__(self) -> None:
        if not self.operations:
            raise ValueError("Patch apply plan must include at least one operation.")
        if self.plan_id is not None and not self.plan_id.strip():
            raise ValueError("Patch apply plan_id must not be empty when provided.")
        object.__setattr__(self, "operations", tuple(self.operations))
        object.__setattr__(
            self,
            "metadata",
            None if self.metadata is None else dict(self.metadata),
        )


@dataclass(frozen=True, slots=True)
class PatchApplyReport:
    """
    Structured result from applying a patch plan.
    """

    plan_id: str | None
    applied: bool
    dry_run: bool
    file_changes: tuple[PatchApplyFileChange, ...]
    message: str
    artifact_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "applied": self.applied,
            "dry_run": self.dry_run,
            "file_changes": [
                {
                    "path": change.path,
                    "before_sha256": change.before_sha256,
                    "after_sha256": change.after_sha256,
                    "action": change.action,
                }
                for change in self.file_changes
            ],
            "message": self.message,
            "artifact_path": self.artifact_path,
        }


class PatchApplyTool:
    """
    Governed local patch application tool.

    This tool is intentionally conservative:
    - all paths must remain beneath the workspace root
    - replacement operations require exact old_text matches
    - optional expected SHA-256 guards are honored
    - dry-run mode computes planned changes without writing files
    """

    tool_name = "patch.apply"

    def __init__(
        self,
        *,
        workspace_root: Path,
        artifact_store: ToolArtifactStore | None = None,
    ) -> None:
        self._workspace_root = workspace_root.expanduser().resolve()
        self._artifact_store = artifact_store

    @property
    def workspace_root(self) -> Path:
        return self._workspace_root

    @classmethod
    def manifest(cls) -> ToolManifest:
        return ToolManifest(
            name=cls.tool_name,
            version="0.1.0",
            description="Apply bounded workspace-local patch plans with dry-run support.",
            parameters=(
                ToolParameter(
                    name="operations",
                    type_name="array",
                    description=(
                        "Patch operations. Each item requires operation and path. "
                        "Supported operations: create_file, replace_file, replace_text, delete_file."
                    ),
                    required=True,
                ),
                ToolParameter(
                    name="plan_id",
                    type_name="string",
                    description="Optional caller-supplied patch plan identifier.",
                    required=False,
                ),
                ToolParameter(
                    name="dry_run",
                    type_name="boolean",
                    description="When true, validate and report planned changes without writing files.",
                    required=False,
                    default=True,
                ),
            ),
            capabilities=(
                ToolCapability.FILE_WRITE,
                ToolCapability.PATCH_APPLY,
                ToolCapability.ARTIFACT_WRITE,
            ),
            side_effects=(
                ToolSideEffect.FILESYSTEM_WRITE,
                ToolSideEffect.ARTIFACT_WRITE,
            ),
            risk_level=ToolRiskLevel.HIGH,
            approval_mode=ToolApprovalMode.ALWAYS_REQUIRED,
            tags=("patch", "filesystem", "workspace", "governed"),
        )

    def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        if request.tool_name != self.tool_name:
            return _failed_result(
                request=request,
                message=(
                    f"PatchApplyTool cannot handle tool_name={request.tool_name!r}."
                ),
                kind=ToolFailureKind.INVALID_ARGUMENT,
            )

        try:
            dry_run = _coerce_bool(request.arguments.get("dry_run"), default=True)
            plan = PatchApplyPlan.from_payload(request.arguments)
            report = self.apply_plan(plan, dry_run=dry_run)
        except Exception as error:
            return _failed_result(
                request=request,
                message=str(error),
                kind=ToolFailureKind.EXECUTION_ERROR,
            )

        artifact: ToolOutputArtifact | None = None
        if self._artifact_store is not None:
            written_artifact = self._artifact_store.write_json(
                tool_name=self.tool_name,
                label="patch-apply-report",
                payload=report.to_dict(),
                metadata={"invocation_id": request.invocation_id},
            )
            artifact = ToolOutputArtifact(
                name=written_artifact.name,
                path=written_artifact.path,
                sha256=written_artifact.sha256,
                media_type=written_artifact.media_type,
                metadata=written_artifact.metadata,
            )
            report = PatchApplyReport(
                plan_id=report.plan_id,
                applied=report.applied,
                dry_run=report.dry_run,
                file_changes=report.file_changes,
                message=report.message,
                artifact_path=artifact.path,
            )

        return ToolInvocationResult(
            invocation_id=request.invocation_id,
            tool_name=self.tool_name,
            status=ToolInvocationStatus.SUCCEEDED,
            output=report.to_dict(),
            artifacts=() if artifact is None else (artifact,),
        )

    def apply_plan(
        self,
        plan: PatchApplyPlan,
        *,
        dry_run: bool = True,
    ) -> PatchApplyReport:
        changes: list[PatchApplyFileChange] = []

        for operation in plan.operations:
            target_path = self._resolve_workspace_path(operation.path)
            before_hash = _sha256_file(target_path) if target_path.exists() else None

            if operation.expected_sha256 is not None and before_hash != operation.expected_sha256:
                raise ValueError(
                    "Patch operation expected_sha256 mismatch for "
                    f"{operation.path}: expected {operation.expected_sha256}, got {before_hash}."
                )

            if operation.operation == "create_file":
                change = self._create_file(
                    target_path=target_path,
                    relative_path=operation.path,
                    content=operation.content or "",
                    before_hash=before_hash,
                    dry_run=dry_run,
                )
            elif operation.operation == "replace_file":
                change = self._replace_file(
                    target_path=target_path,
                    relative_path=operation.path,
                    content=operation.content or "",
                    before_hash=before_hash,
                    dry_run=dry_run,
                )
            elif operation.operation == "replace_text":
                change = self._replace_text(
                    target_path=target_path,
                    relative_path=operation.path,
                    old_text=operation.old_text or "",
                    new_text=operation.new_text or "",
                    before_hash=before_hash,
                    dry_run=dry_run,
                )
            elif operation.operation == "delete_file":
                change = self._delete_file(
                    target_path=target_path,
                    relative_path=operation.path,
                    before_hash=before_hash,
                    dry_run=dry_run,
                )
            else:  # pragma: no cover - guarded by PatchApplyOperation
                raise ValueError(f"Unsupported patch operation: {operation.operation}.")

            changes.append(change)

        applied = not dry_run
        return PatchApplyReport(
            plan_id=plan.plan_id,
            applied=applied,
            dry_run=dry_run,
            file_changes=tuple(changes),
            message=(
                f"Validated {len(changes)} patch operation(s) without writing files."
                if dry_run
                else f"Applied {len(changes)} patch operation(s)."
            ),
        )

    def _create_file(
        self,
        *,
        target_path: Path,
        relative_path: str,
        content: str,
        before_hash: str | None,
        dry_run: bool,
    ) -> PatchApplyFileChange:
        if target_path.exists():
            raise ValueError(f"Cannot create file that already exists: {relative_path}")

        after_hash = _sha256_text(content)
        if not dry_run:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text(content, encoding="utf-8")

        return PatchApplyFileChange(
            path=relative_path,
            before_sha256=before_hash,
            after_sha256=after_hash,
            action="create_file",
        )

    def _replace_file(
        self,
        *,
        target_path: Path,
        relative_path: str,
        content: str,
        before_hash: str | None,
        dry_run: bool,
    ) -> PatchApplyFileChange:
        if not target_path.exists():
            raise ValueError(f"Cannot replace missing file: {relative_path}")
        if not target_path.is_file():
            raise ValueError(f"Cannot replace non-file path: {relative_path}")

        after_hash = _sha256_text(content)
        if not dry_run:
            target_path.write_text(content, encoding="utf-8")

        return PatchApplyFileChange(
            path=relative_path,
            before_sha256=before_hash,
            after_sha256=after_hash,
            action="replace_file",
        )

    def _replace_text(
        self,
        *,
        target_path: Path,
        relative_path: str,
        old_text: str,
        new_text: str,
        before_hash: str | None,
        dry_run: bool,
    ) -> PatchApplyFileChange:
        if not target_path.exists():
            raise ValueError(f"Cannot replace text in missing file: {relative_path}")
        if not target_path.is_file():
            raise ValueError(f"Cannot replace text in non-file path: {relative_path}")

        current = target_path.read_text(encoding="utf-8")
        occurrences = current.count(old_text)
        if occurrences != 1:
            raise ValueError(
                "replace_text requires exactly one old_text match for "
                f"{relative_path}; found {occurrences}."
            )

        updated = current.replace(old_text, new_text, 1)
        after_hash = _sha256_text(updated)
        if not dry_run:
            target_path.write_text(updated, encoding="utf-8")

        return PatchApplyFileChange(
            path=relative_path,
            before_sha256=before_hash,
            after_sha256=after_hash,
            action="replace_text",
        )

    def _delete_file(
        self,
        *,
        target_path: Path,
        relative_path: str,
        before_hash: str | None,
        dry_run: bool,
    ) -> PatchApplyFileChange:
        if not target_path.exists():
            raise ValueError(f"Cannot delete missing file: {relative_path}")
        if not target_path.is_file():
            raise ValueError(f"Cannot delete non-file path: {relative_path}")

        if not dry_run:
            target_path.unlink()

        return PatchApplyFileChange(
            path=relative_path,
            before_sha256=before_hash,
            after_sha256=None,
            action="delete_file",
        )

    def _resolve_workspace_path(self, relative_path: str) -> Path:
        target = (self._workspace_root / relative_path).resolve()
        if not _is_relative_to(target, self._workspace_root):
            raise ValueError(f"Patch path escapes workspace root: {relative_path}")
        return target


def _failed_result(
    *,
    request: ToolInvocationRequest,
    message: str,
    kind: ToolFailureKind,
) -> ToolInvocationResult:
    return ToolInvocationResult(
        invocation_id=request.invocation_id,
        tool_name=request.tool_name,
        status=ToolInvocationStatus.FAILED,
        failure=ToolFailure(kind=kind, message=message),
    )


def _normalize_operation(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_")
    if normalized not in {"create_file", "replace_file", "replace_text", "delete_file"}:
        raise ValueError(f"Unsupported patch operation: {value!r}.")
    return normalized


def _normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("Patch operation path must not be empty.")
    if cleaned.startswith(("/", "~")):
        raise ValueError(f"Patch operation path must be relative: {value!r}.")

    parts: list[str] = []
    for part in cleaned.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            raise ValueError(f"Patch operation path must not contain traversal: {value!r}.")
        parts.append(part)

    if not parts:
        raise ValueError("Patch operation path must not resolve to workspace root.")

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


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True
