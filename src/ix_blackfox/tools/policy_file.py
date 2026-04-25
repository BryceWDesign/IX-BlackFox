from __future__ import annotations

import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Self

from ix_blackfox.runtime.repair_loop import RepairLoopConfig
from ix_blackfox.tools.manifest import (
    ToolCapability,
    ToolPathPolicy,
    ToolSideEffect,
)
from ix_blackfox.tools.policy import ToolPolicyEvaluatorConfig


class ToolPolicyDocumentError(ValueError):
    """
    Raised when a BlackFox policy document is malformed or unsafe.
    """


@dataclass(frozen=True, slots=True)
class ToolPolicyExecutionConfig:
    """
    Execution section of ``blackfox.policy.toml``.

    This section describes global tool-execution boundaries. It intentionally
    defaults to conservative local-only execution.
    """

    allow_file_read: bool = True
    allow_file_write: bool = True
    allow_process_execution: bool = True
    allow_network: bool = False
    allow_system_mutation: bool = False
    allow_absolute_paths: bool = False
    max_repair_attempts: int = 3
    max_tool_timeout_seconds: float = 900.0

    def __post_init__(self) -> None:
        if self.max_repair_attempts <= 0:
            raise ToolPolicyDocumentError("execution.max_repair_attempts must be positive.")
        if self.max_repair_attempts > 10:
            raise ToolPolicyDocumentError(
                "execution.max_repair_attempts must not exceed 10."
            )
        if self.max_tool_timeout_seconds <= 0:
            raise ToolPolicyDocumentError(
                "execution.max_tool_timeout_seconds must be positive."
            )
        if self.max_tool_timeout_seconds > 900:
            raise ToolPolicyDocumentError(
                "execution.max_tool_timeout_seconds must not exceed 900."
            )

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any] | None) -> Self:
        section = dict(payload or {})
        _reject_unknown_keys(
            section,
            allowed_keys={
                "allow_file_read",
                "allow_file_write",
                "allow_process_execution",
                "allow_network",
                "allow_system_mutation",
                "allow_absolute_paths",
                "max_repair_attempts",
                "max_tool_timeout_seconds",
            },
            section_name="execution",
        )

        return cls(
            allow_file_read=_coerce_bool(
                section.get("allow_file_read", True),
                field_name="execution.allow_file_read",
            ),
            allow_file_write=_coerce_bool(
                section.get("allow_file_write", True),
                field_name="execution.allow_file_write",
            ),
            allow_process_execution=_coerce_bool(
                section.get("allow_process_execution", True),
                field_name="execution.allow_process_execution",
            ),
            allow_network=_coerce_bool(
                section.get("allow_network", False),
                field_name="execution.allow_network",
            ),
            allow_system_mutation=_coerce_bool(
                section.get("allow_system_mutation", False),
                field_name="execution.allow_system_mutation",
            ),
            allow_absolute_paths=_coerce_bool(
                section.get("allow_absolute_paths", False),
                field_name="execution.allow_absolute_paths",
            ),
            max_repair_attempts=_coerce_int(
                section.get("max_repair_attempts", 3),
                field_name="execution.max_repair_attempts",
            ),
            max_tool_timeout_seconds=_coerce_float(
                section.get("max_tool_timeout_seconds", 900.0),
                field_name="execution.max_tool_timeout_seconds",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "allow_file_read": self.allow_file_read,
            "allow_file_write": self.allow_file_write,
            "allow_process_execution": self.allow_process_execution,
            "allow_network": self.allow_network,
            "allow_system_mutation": self.allow_system_mutation,
            "allow_absolute_paths": self.allow_absolute_paths,
            "max_repair_attempts": self.max_repair_attempts,
            "max_tool_timeout_seconds": self.max_tool_timeout_seconds,
        }

    def to_repair_loop_config(self) -> RepairLoopConfig:
        return RepairLoopConfig(max_attempts=self.max_repair_attempts)


@dataclass(frozen=True, slots=True)
class ToolPolicyApprovalConfig:
    """
    Approval section of ``blackfox.policy.toml``.

    This describes when the policy evaluator should require operator review.
    """

    require_for_delete: bool = True
    require_for_network: bool = True
    require_for_secret_access: bool = True
    require_for_workspace_write: bool = True
    require_for_process_execution: bool = True
    review_high_risk: bool = True
    block_critical_risk: bool = True

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any] | None) -> Self:
        section = dict(payload or {})
        _reject_unknown_keys(
            section,
            allowed_keys={
                "require_for_delete",
                "require_for_network",
                "require_for_secret_access",
                "require_for_workspace_write",
                "require_for_process_execution",
                "review_high_risk",
                "block_critical_risk",
            },
            section_name="approval",
        )

        return cls(
            require_for_delete=_coerce_bool(
                section.get("require_for_delete", True),
                field_name="approval.require_for_delete",
            ),
            require_for_network=_coerce_bool(
                section.get("require_for_network", True),
                field_name="approval.require_for_network",
            ),
            require_for_secret_access=_coerce_bool(
                section.get("require_for_secret_access", True),
                field_name="approval.require_for_secret_access",
            ),
            require_for_workspace_write=_coerce_bool(
                section.get("require_for_workspace_write", True),
                field_name="approval.require_for_workspace_write",
            ),
            require_for_process_execution=_coerce_bool(
                section.get("require_for_process_execution", True),
                field_name="approval.require_for_process_execution",
            ),
            review_high_risk=_coerce_bool(
                section.get("review_high_risk", True),
                field_name="approval.review_high_risk",
            ),
            block_critical_risk=_coerce_bool(
                section.get("block_critical_risk", True),
                field_name="approval.block_critical_risk",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "require_for_delete": self.require_for_delete,
            "require_for_network": self.require_for_network,
            "require_for_secret_access": self.require_for_secret_access,
            "require_for_workspace_write": self.require_for_workspace_write,
            "require_for_process_execution": self.require_for_process_execution,
            "review_high_risk": self.review_high_risk,
            "block_critical_risk": self.block_critical_risk,
        }


@dataclass(frozen=True, slots=True)
class ToolPolicyPathConfig:
    """
    Path section of ``blackfox.policy.toml``.
    """

    allowed_roots: tuple[str, ...] = ()
    blocked_roots: tuple[str, ...] = (
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
    )
    allow_absolute_paths: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "allowed_roots",
            _normalize_root_tuple(self.allowed_roots, field_name="paths.allowed_roots"),
        )
        object.__setattr__(
            self,
            "blocked_roots",
            _normalize_root_tuple(self.blocked_roots, field_name="paths.blocked_roots"),
        )

    @classmethod
    def from_mapping(
        cls,
        payload: Mapping[str, Any] | None,
        *,
        execution: ToolPolicyExecutionConfig,
    ) -> Self:
        section = dict(payload or {})
        _reject_unknown_keys(
            section,
            allowed_keys={
                "allowed_roots",
                "blocked_roots",
                "allow_absolute_paths",
            },
            section_name="paths",
        )

        return cls(
            allowed_roots=tuple(
                _coerce_string_list(
                    section.get("allowed_roots", ()),
                    field_name="paths.allowed_roots",
                )
            ),
            blocked_roots=tuple(
                _coerce_string_list(
                    section.get(
                        "blocked_roots",
                        (
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
                    ),
                    field_name="paths.blocked_roots",
                )
            ),
            allow_absolute_paths=_coerce_bool(
                section.get(
                    "allow_absolute_paths",
                    execution.allow_absolute_paths,
                ),
                field_name="paths.allow_absolute_paths",
            ),
        )

    def to_tool_path_policy(self) -> ToolPathPolicy:
        return ToolPathPolicy(
            allowed_roots=self.allowed_roots,
            blocked_roots=self.blocked_roots,
            allow_absolute_paths=self.allow_absolute_paths,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_roots": list(self.allowed_roots),
            "blocked_roots": list(self.blocked_roots),
            "allow_absolute_paths": self.allow_absolute_paths,
        }


@dataclass(frozen=True, slots=True)
class ToolPolicyDocument:
    """
    Parsed ``blackfox.policy.toml`` document.

    Supported TOML shape:

    [execution]
    allow_file_read = true
    allow_file_write = true
    allow_process_execution = true
    allow_network = false
    allow_system_mutation = false
    allow_absolute_paths = false
    max_repair_attempts = 3
    max_tool_timeout_seconds = 900

    [approval]
    require_for_delete = true
    require_for_network = true
    require_for_secret_access = true
    require_for_workspace_write = true
    require_for_process_execution = true
    review_high_risk = true
    block_critical_risk = true

    [paths]
    allowed_roots = ["src", "tests", "docs", "scripts", "examples", "artifacts"]
    blocked_roots = [".git", ".env", ".ssh", "secrets", "credentials"]
    allow_absolute_paths = false
    """

    execution: ToolPolicyExecutionConfig = field(
        default_factory=ToolPolicyExecutionConfig
    )
    approval: ToolPolicyApprovalConfig = field(default_factory=ToolPolicyApprovalConfig)
    paths: ToolPolicyPathConfig = field(default_factory=ToolPolicyPathConfig)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    source_path: Path | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", dict(self.metadata))
        if self.source_path is not None:
            object.__setattr__(self, "source_path", self.source_path.expanduser().resolve())

    @classmethod
    def from_toml_text(
        cls,
        text: str,
        *,
        source_path: Path | None = None,
    ) -> Self:
        try:
            payload = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise ToolPolicyDocumentError(f"Invalid blackfox.policy.toml: {exc}") from exc

        return cls.from_mapping(payload, source_path=source_path)

    @classmethod
    def from_path(cls, path: Path) -> Self:
        resolved = path.expanduser().resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"BlackFox policy file does not exist: {resolved}")
        if not resolved.is_file():
            raise ToolPolicyDocumentError(
                f"BlackFox policy path is not a file: {resolved}"
            )

        return cls.from_toml_text(
            resolved.read_text(encoding="utf-8"),
            source_path=resolved,
        )

    @classmethod
    def from_mapping(
        cls,
        payload: Mapping[str, Any],
        *,
        source_path: Path | None = None,
    ) -> Self:
        root = dict(payload)
        _reject_unknown_keys(
            root,
            allowed_keys={"execution", "approval", "paths", "metadata"},
            section_name="root",
        )

        execution_payload = _optional_mapping(root.get("execution"), section_name="execution")
        approval_payload = _optional_mapping(root.get("approval"), section_name="approval")
        paths_payload = _optional_mapping(root.get("paths"), section_name="paths")
        metadata_payload = _optional_mapping(root.get("metadata"), section_name="metadata")

        execution = ToolPolicyExecutionConfig.from_mapping(execution_payload)
        approval = ToolPolicyApprovalConfig.from_mapping(approval_payload)
        paths = ToolPolicyPathConfig.from_mapping(
            paths_payload,
            execution=execution,
        )

        return cls(
            execution=execution,
            approval=approval,
            paths=paths,
            metadata=dict(metadata_payload or {}),
            source_path=source_path,
        )

    def to_tool_policy_evaluator_config(self) -> ToolPolicyEvaluatorConfig:
        blocked_capabilities: list[ToolCapability] = []
        blocked_side_effects: list[ToolSideEffect] = []
        review_capabilities: list[ToolCapability] = []
        review_side_effects: list[ToolSideEffect] = []

        if not self.execution.allow_file_read:
            blocked_capabilities.extend(
                [
                    ToolCapability.FILE_READ,
                    ToolCapability.DIRECTORY_LIST,
                ]
            )
            blocked_side_effects.append(ToolSideEffect.READ_WORKSPACE)

        if not self.execution.allow_file_write:
            blocked_capabilities.extend(
                [
                    ToolCapability.FILE_WRITE,
                    ToolCapability.PATCH_APPLY,
                ]
            )
            blocked_side_effects.append(ToolSideEffect.WRITE_WORKSPACE)

        if not self.execution.allow_process_execution:
            blocked_capabilities.extend(
                [
                    ToolCapability.COMMAND_EXECUTION,
                    ToolCapability.TEST_EXECUTION,
                ]
            )
            blocked_side_effects.append(ToolSideEffect.RUN_PROCESS)

        if self.approval.require_for_workspace_write:
            review_capabilities.extend(
                [
                    ToolCapability.FILE_WRITE,
                    ToolCapability.PATCH_APPLY,
                ]
            )
            review_side_effects.append(ToolSideEffect.WRITE_WORKSPACE)

        if self.approval.require_for_process_execution:
            review_capabilities.extend(
                [
                    ToolCapability.COMMAND_EXECUTION,
                    ToolCapability.TEST_EXECUTION,
                ]
            )
            review_side_effects.append(ToolSideEffect.RUN_PROCESS)

        if self.approval.require_for_network:
            review_side_effects.append(ToolSideEffect.ACCESS_NETWORK)

        return ToolPolicyEvaluatorConfig(
            allow_network_access=self.execution.allow_network,
            allow_system_mutation=self.execution.allow_system_mutation,
            allow_absolute_paths=self.execution.allow_absolute_paths
            or self.paths.allow_absolute_paths,
            block_on_critical_risk=self.approval.block_critical_risk,
            review_high_risk=self.approval.review_high_risk,
            review_workspace_writes=self.approval.require_for_workspace_write,
            review_process_execution=self.approval.require_for_process_execution,
            review_sensitive_paths=self.approval.require_for_secret_access,
            blocked_capabilities=tuple(_dedupe(blocked_capabilities)),
            blocked_side_effects=tuple(_dedupe(blocked_side_effects)),
            review_capabilities=tuple(_dedupe(review_capabilities)),
            review_side_effects=tuple(_dedupe(review_side_effects)),
        )

    def to_repair_loop_config(self) -> RepairLoopConfig:
        return self.execution.to_repair_loop_config()

    def to_tool_path_policy(self) -> ToolPathPolicy:
        return self.paths.to_tool_path_policy()

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution": self.execution.to_dict(),
            "approval": self.approval.to_dict(),
            "paths": self.paths.to_dict(),
            "metadata": dict(self.metadata),
            "source_path": str(self.source_path) if self.source_path is not None else None,
        }


def _optional_mapping(value: Any, *, section_name: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ToolPolicyDocumentError(f"[{section_name}] must be a TOML table.")
    return dict(value)


def _reject_unknown_keys(
    payload: Mapping[str, Any],
    *,
    allowed_keys: set[str],
    section_name: str,
) -> None:
    unknown_keys = tuple(sorted(set(payload) - allowed_keys))
    if unknown_keys:
        joined = ", ".join(unknown_keys)
        raise ToolPolicyDocumentError(
            f"Unknown key(s) in blackfox.policy.toml [{section_name}]: {joined}."
        )


def _coerce_bool(value: Any, *, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ToolPolicyDocumentError(f"{field_name} must be a boolean.")
    return value


def _coerce_int(value: Any, *, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ToolPolicyDocumentError(f"{field_name} must be an integer.")
    return value


def _coerce_float(value: Any, *, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ToolPolicyDocumentError(f"{field_name} must be a number.")
    return float(value)


def _coerce_string_list(value: Any, *, field_name: str) -> list[str]:
    if isinstance(value, str):
        raise ToolPolicyDocumentError(f"{field_name} must be a list of strings.")
    if not isinstance(value, Iterable):
        raise ToolPolicyDocumentError(f"{field_name} must be a list of strings.")

    values: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ToolPolicyDocumentError(f"{field_name} must contain only strings.")
        values.append(item)

    return values


def _normalize_root_tuple(
    values: Iterable[str],
    *,
    field_name: str,
) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for raw_value in values:
        cleaned = raw_value.strip().replace("\\", "/")
        if not cleaned:
            continue
        if cleaned.startswith(("/", "~")):
            raise ToolPolicyDocumentError(
                f"{field_name} entries must be relative paths: {raw_value!r}."
            )
        if ".." in cleaned.split("/"):
            raise ToolPolicyDocumentError(
                f"{field_name} entries must not contain traversal: {raw_value!r}."
            )
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _dedupe(values: Iterable[Any]) -> tuple[Any, ...]:
    deduped: list[Any] = []
    seen: set[Any] = set()

    for value in values:
        if value in seen:
            continue
        deduped.append(value)
        seen.add(value)

    return tuple(deduped)
