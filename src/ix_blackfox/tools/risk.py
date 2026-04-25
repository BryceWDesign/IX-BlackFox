from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any, Self

from ix_blackfox.tools.contracts import ToolInvocationRequest
from ix_blackfox.tools.manifest import (
    ToolApprovalMode,
    ToolCapability,
    ToolManifest,
    ToolSideEffect,
)


class ToolRiskLevel(StrEnum):
    """
    Normalized risk level for one governed tool invocation.

    The level describes execution risk before final policy/approval decisions.
    It is intentionally deterministic so receipts and tests can reproduce the
    same classification for the same manifest and request.
    """

    NEGLIGIBLE = auto()
    LOW = auto()
    MODERATE = auto()
    HIGH = auto()
    CRITICAL = auto()


@dataclass(frozen=True, slots=True)
class ToolRiskSignal:
    """
    One explainable reason contributing to a tool risk assessment.
    """

    code: str
    weight: int
    summary: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _normalize_token(self.code, label="code"))
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.weight < 0:
            raise ValueError("ToolRiskSignal weight must not be negative.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "weight": self.weight,
            "summary": self.summary,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            code=_require_text(payload, "code"),
            weight=int(payload.get("weight", 0)),
            summary=_require_text(payload, "summary"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class ToolRiskAssessment:
    """
    Deterministic risk assessment for one tool invocation.
    """

    tool_id: str
    invocation_id: str
    level: ToolRiskLevel
    score: int
    signals: tuple[ToolRiskSignal, ...] = field(default_factory=tuple)
    approval_recommended: bool = False
    block_recommended: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tool_id", _normalize_token(self.tool_id, label="tool_id"))
        object.__setattr__(
            self,
            "invocation_id",
            _normalize_token(self.invocation_id, label="invocation_id"),
        )
        object.__setattr__(self, "signals", tuple(self.signals))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.score < 0:
            raise ValueError("ToolRiskAssessment score must not be negative.")

    @property
    def signal_codes(self) -> tuple[str, ...]:
        return tuple(signal.code for signal in self.signals)

    @property
    def is_operator_sensitive(self) -> bool:
        return self.approval_recommended or self.block_recommended

    def has_signal(self, code: str) -> bool:
        normalized_code = _normalize_token(code, label="code")
        return normalized_code in self.signal_codes

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "invocation_id": self.invocation_id,
            "level": self.level.value,
            "score": self.score,
            "signals": [signal.to_dict() for signal in self.signals],
            "approval_recommended": self.approval_recommended,
            "block_recommended": self.block_recommended,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_signals = payload.get("signals", ())
        if not isinstance(raw_signals, Iterable) or isinstance(raw_signals, str):
            raise TypeError("signals must be an iterable of mappings.")

        signals: list[ToolRiskSignal] = []
        for raw_signal in raw_signals:
            if not isinstance(raw_signal, Mapping):
                raise TypeError("signals must contain only mappings.")
            signals.append(ToolRiskSignal.from_dict(raw_signal))

        return cls(
            tool_id=_require_text(payload, "tool_id"),
            invocation_id=_require_text(payload, "invocation_id"),
            level=ToolRiskLevel(_require_text(payload, "level")),
            score=int(payload.get("score", 0)),
            signals=tuple(signals),
            approval_recommended=bool(payload.get("approval_recommended", False)),
            block_recommended=bool(payload.get("block_recommended", False)),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class ToolRiskClassifier:
    """
    Deterministic risk classifier for governed tool invocations.

    The classifier intentionally avoids model calls. It gives the gateway a
    reproducible baseline for whether a tool invocation is low risk, should be
    reviewed, or should be blocked before execution.
    """

    destructive_argument_keys: tuple[str, ...] = (
        "delete",
        "remove",
        "rm",
        "rmdir",
        "unlink",
        "overwrite",
        "force",
        "recursive",
        "chmod",
        "chown",
        "format",
        "wipe",
        "drop",
        "truncate",
    )
    sensitive_path_fragments: tuple[str, ...] = (
        ".env",
        ".git",
        ".ssh",
        "id_rsa",
        "id_ed25519",
        "secret",
        "secrets",
        "credential",
        "credentials",
        "token",
        "tokens",
        "private_key",
        "api_key",
    )

    def assess(
        self,
        *,
        manifest: ToolManifest,
        request: ToolInvocationRequest,
    ) -> ToolRiskAssessment:
        """
        Classify one invocation from its manifest and request arguments.
        """
        signals: list[ToolRiskSignal] = []

        if not manifest.supports(request.capability):
            signals.append(
                ToolRiskSignal(
                    code="unsupported-capability",
                    weight=100,
                    summary="Request capability is not declared by the tool manifest.",
                    metadata={
                        "requested_capability": request.capability.value,
                        "declared_capabilities": [
                            capability.value for capability in manifest.capabilities
                        ],
                    },
                )
            )

        signals.extend(self._signals_for_side_effects(manifest.side_effects))
        signals.extend(self._signals_for_capabilities(manifest.capabilities))
        signals.extend(self._signals_for_approval_mode(manifest.approval_mode))
        signals.extend(self._signals_for_arguments(request.arguments))

        score = sum(signal.weight for signal in signals)
        level = _level_from_score(score)
        approval_recommended = (
            manifest.approval_mode is ToolApprovalMode.ALWAYS
            or level in {ToolRiskLevel.HIGH, ToolRiskLevel.CRITICAL}
            or any(
                signal.code
                in {
                    "workspace-write",
                    "process-execution",
                    "network-access",
                    "system-mutation",
                    "destructive-argument",
                    "sensitive-path-reference",
                    "path-traversal-reference",
                    "absolute-path-reference",
                }
                for signal in signals
            )
        )
        block_recommended = any(
            signal.code
            in {
                "unsupported-capability",
                "system-mutation",
                "path-traversal-reference",
            }
            for signal in signals
        )

        return ToolRiskAssessment(
            tool_id=manifest.tool_id,
            invocation_id=request.invocation_id,
            level=level,
            score=score,
            signals=tuple(signals),
            approval_recommended=approval_recommended,
            block_recommended=block_recommended,
            metadata={
                "capability": request.capability.value,
                "approval_mode": manifest.approval_mode.value,
                "side_effects": [
                    side_effect.value for side_effect in manifest.side_effects
                ],
            },
        )

    def _signals_for_side_effects(
        self,
        side_effects: tuple[ToolSideEffect, ...],
    ) -> tuple[ToolRiskSignal, ...]:
        signals: list[ToolRiskSignal] = []

        for side_effect in side_effects:
            if side_effect is ToolSideEffect.NONE:
                signals.append(
                    ToolRiskSignal(
                        code="no-side-effect",
                        weight=0,
                        summary="Tool declares no side effects.",
                    )
                )
            elif side_effect is ToolSideEffect.READ_WORKSPACE:
                signals.append(
                    ToolRiskSignal(
                        code="workspace-read",
                        weight=10,
                        summary="Tool can read workspace content.",
                    )
                )
            elif side_effect is ToolSideEffect.WRITE_WORKSPACE:
                signals.append(
                    ToolRiskSignal(
                        code="workspace-write",
                        weight=35,
                        summary="Tool can write inside a workspace.",
                    )
                )
            elif side_effect is ToolSideEffect.RUN_PROCESS:
                signals.append(
                    ToolRiskSignal(
                        code="process-execution",
                        weight=45,
                        summary="Tool can start a local process.",
                    )
                )
            elif side_effect is ToolSideEffect.ACCESS_NETWORK:
                signals.append(
                    ToolRiskSignal(
                        code="network-access",
                        weight=60,
                        summary="Tool can access the network.",
                    )
                )
            elif side_effect is ToolSideEffect.MUTATE_SYSTEM:
                signals.append(
                    ToolRiskSignal(
                        code="system-mutation",
                        weight=90,
                        summary="Tool can mutate host system state.",
                    )
                )

        return tuple(signals)

    def _signals_for_capabilities(
        self,
        capabilities: tuple[ToolCapability, ...],
    ) -> tuple[ToolRiskSignal, ...]:
        signals: list[ToolRiskSignal] = []

        if ToolCapability.FILE_WRITE in capabilities:
            signals.append(
                ToolRiskSignal(
                    code="file-write-capability",
                    weight=20,
                    summary="Tool declares file write capability.",
                )
            )

        if ToolCapability.PATCH_APPLY in capabilities:
            signals.append(
                ToolRiskSignal(
                    code="patch-apply-capability",
                    weight=25,
                    summary="Tool can apply source changes.",
                )
            )

        if ToolCapability.COMMAND_EXECUTION in capabilities:
            signals.append(
                ToolRiskSignal(
                    code="command-execution-capability",
                    weight=35,
                    summary="Tool can execute commands.",
                )
            )

        if ToolCapability.TEST_EXECUTION in capabilities:
            signals.append(
                ToolRiskSignal(
                    code="test-execution-capability",
                    weight=20,
                    summary="Tool can execute tests or test-like processes.",
                )
            )

        return tuple(signals)

    def _signals_for_approval_mode(
        self,
        approval_mode: ToolApprovalMode,
    ) -> tuple[ToolRiskSignal, ...]:
        if approval_mode is ToolApprovalMode.ALWAYS:
            return (
                ToolRiskSignal(
                    code="manifest-requires-approval",
                    weight=15,
                    summary="Tool manifest requires approval by default.",
                ),
            )

        return ()

    def _signals_for_arguments(
        self,
        arguments: Mapping[str, Any],
    ) -> tuple[ToolRiskSignal, ...]:
        flattened = tuple(_flatten_argument_items(arguments))
        signals: list[ToolRiskSignal] = []

        for key, value in flattened:
            key_lower = key.lower()
            value_text = str(value).strip()
            value_lower = value_text.lower()

            if key_lower in self.destructive_argument_keys and _truthy(value):
                signals.append(
                    ToolRiskSignal(
                        code="destructive-argument",
                        weight=40,
                        summary="Invocation arguments request a destructive behavior.",
                        metadata={"argument": key, "value": value_text},
                    )
                )

            if ".." in value_text.replace("\\", "/").split("/"):
                signals.append(
                    ToolRiskSignal(
                        code="path-traversal-reference",
                        weight=100,
                        summary="Invocation arguments include a path traversal reference.",
                        metadata={"argument": key, "value": value_text},
                    )
                )

            if value_text.startswith(("/", "\\", "~")) or _looks_like_windows_absolute_path(
                value_text
            ):
                signals.append(
                    ToolRiskSignal(
                        code="absolute-path-reference",
                        weight=30,
                        summary="Invocation arguments include an absolute path reference.",
                        metadata={"argument": key, "value": value_text},
                    )
                )

            for fragment in self.sensitive_path_fragments:
                if fragment in value_lower:
                    signals.append(
                        ToolRiskSignal(
                            code="sensitive-path-reference",
                            weight=50,
                            summary=(
                                "Invocation arguments reference a sensitive path or "
                                "credential-like name."
                            ),
                            metadata={
                                "argument": key,
                                "matched_fragment": fragment,
                                "value": value_text,
                            },
                        )
                    )
                    break

        return tuple(_dedupe_signals(signals))


def _level_from_score(score: int) -> ToolRiskLevel:
    if score <= 0:
        return ToolRiskLevel.NEGLIGIBLE
    if score <= 24:
        return ToolRiskLevel.LOW
    if score <= 59:
        return ToolRiskLevel.MODERATE
    if score <= 99:
        return ToolRiskLevel.HIGH
    return ToolRiskLevel.CRITICAL


def _flatten_argument_items(
    value: Any,
    *,
    prefix: str = "",
) -> Iterable[tuple[str, Any]]:
    if isinstance(value, Mapping):
        for key, nested_value in value.items():
            key_text = str(key)
            nested_prefix = f"{prefix}.{key_text}" if prefix else key_text
            yield from _flatten_argument_items(nested_value, prefix=nested_prefix)
        return

    if isinstance(value, (list, tuple, set, frozenset)):
        for index, nested_value in enumerate(value):
            nested_prefix = f"{prefix}[{index}]" if prefix else f"[{index}]"
            yield from _flatten_argument_items(nested_value, prefix=nested_prefix)
        return

    yield prefix or "value", value


def _dedupe_signals(signals: Iterable[ToolRiskSignal]) -> tuple[ToolRiskSignal, ...]:
    deduped: list[ToolRiskSignal] = []
    seen: set[tuple[str, str]] = set()

    for signal in signals:
        key = (signal.code, repr(sorted(signal.metadata.items())))
        if key in seen:
            continue
        deduped.append(signal)
        seen.add(key)

    return tuple(deduped)


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False

    normalized = str(value).strip().lower()
    return normalized in {"1", "true", "yes", "y", "on", "force", "recursive"}


def _looks_like_windows_absolute_path(value: str) -> bool:
    if len(value) < 3:
        return False
    return value[1:3] in {":\\", ":/"} and value[0].isalpha()


def _normalize_token(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _coerce_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")
    return dict(value)


def _require_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string.")
    return value
