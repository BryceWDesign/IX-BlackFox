from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any, Self, TypeVar

_TOOL_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_.:-]{2,127}$")

EnumT = TypeVar("EnumT", bound=StrEnum)


class ToolCapability(StrEnum):
    """
    Coarse capability categories exposed by governed BlackFox tools.

    These categories are intentionally small and auditable. They describe what
    a tool can do before policy, approval, or runtime execution is considered.
    """

    FILE_READ = auto()
    FILE_WRITE = auto()
    DIRECTORY_LIST = auto()
    PATCH_PLAN = auto()
    PATCH_APPLY = auto()
    COMMAND_EXECUTION = auto()
    TEST_EXECUTION = auto()
    STATIC_ANALYSIS = auto()
    REPORT_GENERATION = auto()
    POLICY_INSPECTION = auto()
    ARTIFACT_EXPORT = auto()


class ToolSideEffect(StrEnum):
    """
    Side-effect class declared by a tool manifest.

    The manifest declares possible effects. Later gateway/policy layers decide
    whether a specific invocation is allowed, requires review, or is blocked.
    """

    NONE = auto()
    READ_WORKSPACE = auto()
    WRITE_WORKSPACE = auto()
    RUN_PROCESS = auto()
    ACCESS_NETWORK = auto()
    MUTATE_SYSTEM = auto()


class ToolApprovalMode(StrEnum):
    """
    Default human-review posture declared by a tool.
    """

    NEVER = auto()
    POLICY = auto()
    ALWAYS = auto()


@dataclass(frozen=True, slots=True)
class ToolPathPolicy:
    """
    Declarative path scope for tools that touch a workspace.

    This is a manifest-level declaration, not the final path-enforcement engine.
    Enforcement is added by the governed tool gateway so every invocation can be
    checked against both manifest constraints and operator policy.
    """

    allowed_roots: tuple[str, ...] = field(default_factory=tuple)
    blocked_roots: tuple[str, ...] = field(default_factory=tuple)
    allow_absolute_paths: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "allowed_roots",
            _normalize_string_tuple(self.allowed_roots, field_name="allowed_roots"),
        )
        object.__setattr__(
            self,
            "blocked_roots",
            _normalize_string_tuple(self.blocked_roots, field_name="blocked_roots"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_roots": list(self.allowed_roots),
            "blocked_roots": list(self.blocked_roots),
            "allow_absolute_paths": self.allow_absolute_paths,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            allowed_roots=_coerce_string_tuple(
                payload.get("allowed_roots", ()),
                field_name="allowed_roots",
            ),
            blocked_roots=_coerce_string_tuple(
                payload.get("blocked_roots", ()),
                field_name="blocked_roots",
            ),
            allow_absolute_paths=bool(payload.get("allow_absolute_paths", False)),
        )


@dataclass(frozen=True, slots=True)
class ToolManifest:
    """
    Immutable declaration of a governed tool.

    A manifest says what a tool is allowed to claim about itself. It does not by
    itself grant execution permission. Every later invocation must still pass
    gateway policy, approval rules, and receipt capture.
    """

    tool_id: str
    name: str
    version: str
    summary: str
    capabilities: tuple[ToolCapability, ...]
    side_effects: tuple[ToolSideEffect, ...] = (ToolSideEffect.NONE,)
    approval_mode: ToolApprovalMode = ToolApprovalMode.POLICY
    input_schema: Mapping[str, Any] = field(default_factory=dict)
    output_schema: Mapping[str, Any] = field(default_factory=dict)
    default_timeout_seconds: float | None = None
    path_policy: ToolPathPolicy | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized_tool_id = self.tool_id.strip()
        if not _TOOL_ID_PATTERN.fullmatch(normalized_tool_id):
            raise ValueError(
                "Tool manifest tool_id must match "
                f"{_TOOL_ID_PATTERN.pattern!r}; got {self.tool_id!r}."
            )

        normalized_name = self.name.strip()
        normalized_version = self.version.strip()
        normalized_summary = self.summary.strip()

        if not normalized_name:
            raise ValueError("Tool manifest name must not be empty.")
        if not normalized_version:
            raise ValueError("Tool manifest version must not be empty.")
        if not normalized_summary:
            raise ValueError("Tool manifest summary must not be empty.")
        if not self.capabilities:
            raise ValueError("Tool manifest must declare at least one capability.")

        normalized_capabilities = _normalize_enum_tuple(
            self.capabilities,
            enum_type=ToolCapability,
            field_name="capabilities",
        )
        normalized_side_effects = _normalize_enum_tuple(
            self.side_effects,
            enum_type=ToolSideEffect,
            field_name="side_effects",
        )

        if ToolSideEffect.NONE in normalized_side_effects and len(normalized_side_effects) > 1:
            raise ValueError(
                "ToolSideEffect.NONE cannot be combined with real side effects."
            )

        object.__setattr__(self, "tool_id", normalized_tool_id)
        object.__setattr__(self, "name", normalized_name)
        object.__setattr__(self, "version", normalized_version)
        object.__setattr__(self, "summary", normalized_summary)
        object.__setattr__(self, "capabilities", normalized_capabilities)
        object.__setattr__(self, "side_effects", normalized_side_effects)
        object.__setattr__(self, "input_schema", dict(self.input_schema))
        object.__setattr__(self, "output_schema", dict(self.output_schema))
        object.__setattr__(
            self,
            "tags",
            _normalize_string_tuple(self.tags, field_name="tags"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.default_timeout_seconds is not None and self.default_timeout_seconds <= 0:
            raise ValueError("Tool manifest default_timeout_seconds must be positive.")

    @property
    def has_side_effects(self) -> bool:
        return any(
            side_effect is not ToolSideEffect.NONE for side_effect in self.side_effects
        )

    @property
    def requires_approval_by_default(self) -> bool:
        return self.approval_mode is ToolApprovalMode.ALWAYS

    def supports(self, capability: ToolCapability) -> bool:
        return capability in self.capabilities

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "name": self.name,
            "version": self.version,
            "summary": self.summary,
            "capabilities": [capability.value for capability in self.capabilities],
            "side_effects": [side_effect.value for side_effect in self.side_effects],
            "approval_mode": self.approval_mode.value,
            "input_schema": dict(self.input_schema),
            "output_schema": dict(self.output_schema),
            "default_timeout_seconds": self.default_timeout_seconds,
            "path_policy": self.path_policy.to_dict() if self.path_policy else None,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        path_policy_payload = payload.get("path_policy")
        path_policy = (
            ToolPathPolicy.from_dict(path_policy_payload)
            if isinstance(path_policy_payload, Mapping)
            else None
        )

        return cls(
            tool_id=_require_text(payload, "tool_id"),
            name=_require_text(payload, "name"),
            version=_require_text(payload, "version"),
            summary=_require_text(payload, "summary"),
            capabilities=tuple(
                ToolCapability(value)
                for value in _coerce_string_tuple(
                    payload.get("capabilities", ()),
                    field_name="capabilities",
                )
            ),
            side_effects=tuple(
                ToolSideEffect(value)
                for value in _coerce_string_tuple(
                    payload.get("side_effects", (ToolSideEffect.NONE.value,)),
                    field_name="side_effects",
                )
            ),
            approval_mode=ToolApprovalMode(
                payload.get("approval_mode", ToolApprovalMode.POLICY.value)
            ),
            input_schema=_coerce_mapping(
                payload.get("input_schema", {}),
                field_name="input_schema",
            ),
            output_schema=_coerce_mapping(
                payload.get("output_schema", {}),
                field_name="output_schema",
            ),
            default_timeout_seconds=_coerce_optional_float(
                payload.get("default_timeout_seconds")
            ),
            path_policy=path_policy,
            tags=_coerce_string_tuple(payload.get("tags", ()), field_name="tags"),
            metadata=_coerce_mapping(
                payload.get("metadata", {}),
                field_name="metadata",
            ),
        )


@dataclass(slots=True)
class ToolManifestRegistry:
    """
    In-memory registry of tool manifests keyed by stable tool_id.
    """

    _manifests: dict[str, ToolManifest] = field(default_factory=dict)

    def register(self, manifest: ToolManifest, *, replace_existing: bool = False) -> None:
        if manifest.tool_id in self._manifests and not replace_existing:
            raise ValueError(f"Tool manifest already registered: {manifest.tool_id!r}.")
        self._manifests[manifest.tool_id] = manifest

    def contains(self, tool_id: str) -> bool:
        return tool_id in self._manifests

    def get(self, tool_id: str) -> ToolManifest:
        try:
            return self._manifests[tool_id]
        except KeyError as exc:
            raise KeyError(f"Unknown tool manifest: {tool_id!r}.") from exc

    def list_tool_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._manifests))

    def list_manifests(self) -> tuple[ToolManifest, ...]:
        return tuple(self._manifests[tool_id] for tool_id in self.list_tool_ids())

    def find_by_capability(self, capability: ToolCapability) -> tuple[ToolManifest, ...]:
        return tuple(
            manifest
            for manifest in self.list_manifests()
            if manifest.supports(capability)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifests": [manifest.to_dict() for manifest in self.list_manifests()],
        }


def _normalize_string_tuple(values: Iterable[str], *, field_name: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        if not isinstance(value, str):
            raise TypeError(f"{field_name} must contain only strings.")
        cleaned = value.strip()
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _normalize_enum_tuple(
    values: Iterable[EnumT],
    *,
    enum_type: type[EnumT],
    field_name: str,
) -> tuple[EnumT, ...]:
    normalized: list[EnumT] = []
    seen: set[EnumT] = set()

    for value in values:
        if not isinstance(value, enum_type):
            raise TypeError(f"{field_name} must contain only {enum_type.__name__} values.")
        if value not in seen:
            normalized.append(value)
            seen.add(value)

    if not normalized:
        raise ValueError(f"{field_name} must not be empty.")

    return tuple(normalized)


def _coerce_string_tuple(value: Any, *, field_name: str) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, Iterable):
        raise TypeError(f"{field_name} must be a string or iterable of strings.")

    coerced: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"{field_name} must contain only strings.")
        coerced.append(item)
    return tuple(coerced)


def _coerce_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")
    return dict(value)


def _coerce_optional_float(value: Any) -> float | None:
    if value is None:
        return None
    return float(value)


def _require_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise TypeError(f"Tool manifest field {key!r} must be a string.")
    return value
