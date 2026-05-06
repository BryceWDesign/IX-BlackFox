from __future__ import annotations

import re
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

_WINDOWS_ABSOLUTE_PATH = re.compile(r"^[a-zA-Z]:[\\/]")


class ToolRiskLevel(StrEnum):
    """
    Normalized execution-risk level for one governed tool invocation.
    """

    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


class ToolRiskFactor(StrEnum):
    """
    Coarse risk factors retained for older policy-ledger integrations.
    """

    APPROVAL_REQUIRED = auto()
    WORKSPACE_READ = auto()
    FILESYSTEM_WRITE = auto()
    PATCH_APPLY = auto()
    PROCESS_EXECUTION = auto()
    NETWORK_ACCESS = auto()
    EXTERNAL_SIDE_EFFECT = auto()
    DESTRUCTIVE_OPERATION = auto()
    SECRET_ACCESS = auto()
    LARGE_ARGUMENT_PAYLOAD = auto()
    PATH_TRAVERSAL_SIGNAL = auto()
    ABSOLUTE_PATH_SIGNAL = auto()
    SENSITIVE_PATH_SIGNAL = auto()
    OVERRIDE_REQUESTED = auto()
    UNSUPPORTED_CAPABILITY = auto()
    UNKNOWN_TOOL = auto()


@dataclass(frozen=True, slots=True)
class ToolRiskSignal:
    """
    One explainable risk signal raised by the classifier.
    """

    code: str
    score: int
    summary: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _normalize_signal_code(self.code))
        object.__setattr__(self, "summary", _normalize_text(self.summary, "summary"))
        object.__setattr__(self, "metadata", dict(self.metadata))
        if self.score < 0:
            raise ValueError("Tool risk signal score must be non-negative.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "score": self.score,
            "summary": self.summary,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            code=_require_text(payload, "code"),
            score=int(payload.get("score", 0)),
            summary=_require_text(payload, "summary"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class ToolRiskAssessment:
    """
    Deterministic risk assessment for a governed tool invocation.
    """

    tool_name: str
    level: ToolRiskLevel
    score: int
    signals: tuple[ToolRiskSignal, ...] = field(default_factory=tuple)
    factors: tuple[ToolRiskFactor, ...] = field(default_factory=tuple)
    rationale: str = "Tool risk assessment completed."
    requires_human_review: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.score < 0:
            raise ValueError("Tool risk score must be non-negative.")
        object.__setattr__(
            self,
            "tool_name",
            _normalize_identifier(self.tool_name, label="tool_name"),
        )
        object.__setattr__(self, "signals", _dedupe_signals(self.signals))
        object.__setattr__(self, "factors", tuple(dict.fromkeys(self.factors)))
        object.__setattr__(self, "rationale", _normalize_text(self.rationale, "rationale"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def tool_id(self) -> str:
        return self.tool_name

    @property
    def signal_codes(self) -> tuple[str, ...]:
        return tuple(signal.code for signal in self.signals)

    @property
    def approval_recommended(self) -> bool:
        return self.requires_human_review or self.level in {
            ToolRiskLevel.HIGH,
            ToolRiskLevel.CRITICAL,
        }

    @property
    def block_recommended(self) -> bool:
        return self.level is ToolRiskLevel.CRITICAL or any(
            self.has_signal(code)
            for code in (
                "path-traversal-reference",
                "unknown-tool",
                "unsupported-capability",
            )
        )

    def has_signal(self, code: str) -> bool:
        return _normalize_signal_code(code) in self.signal_codes

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "tool_id": self.tool_id,
            "level": self.level.value,
            "score": self.score,
            "signals": [signal.to_dict() for signal in self.signals],
            "signal_codes": list(self.signal_codes),
            "factors": [factor.value for factor in self.factors],
            "rationale": self.rationale,
            "requires_human_review": self.requires_human_review,
            "approval_recommended": self.approval_recommended,
            "block_recommended": self.block_recommended,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_signals = payload.get("signals", ())
        if not isinstance(raw_signals, Iterable) or isinstance(raw_signals, str):
            raise TypeError("Tool risk assessment signals must be an iterable.")
        signals: list[ToolRiskSignal] = []
        for raw_signal in raw_signals:
            if not isinstance(raw_signal, Mapping):
                raise TypeError("Tool risk assessment signals must contain mappings.")
            signals.append(ToolRiskSignal.from_dict(raw_signal))

        raw_factors = payload.get("factors", ())
        if not isinstance(raw_factors, Iterable) or isinstance(raw_factors, str):
            raise TypeError("Tool risk assessment factors must be an iterable.")
        factors = tuple(ToolRiskFactor(str(raw_factor)) for raw_factor in raw_factors)

        tool_name = payload.get("tool_name", payload.get("tool_id"))
        if not isinstance(tool_name, str):
            raise TypeError("Tool risk assessment tool_name must be a string.")

        return cls(
            tool_name=tool_name,
            level=ToolRiskLevel(_require_text(payload, "level")),
            score=int(payload.get("score", 0)),
            signals=tuple(signals),
            factors=factors,
            rationale=str(payload.get("rationale", "Tool risk assessment restored.")),
            requires_human_review=bool(payload.get("requires_human_review", False)),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


class ToolRiskClassifier:
    """
    Deterministic classifier for governed tool invocation risk.

    It uses only manifest declarations and request payloads. It does not execute
    tools, inspect the host system, or trust a model-authored argument simply
    because a tool is registered.
    """

    _SIDE_EFFECT_RULES: Mapping[
        ToolSideEffect,
        tuple[str, int, str, ToolRiskFactor | None],
    ] = {
        ToolSideEffect.NONE: ("no-side-effect", 0, "The tool declares no side effect.", None),
        ToolSideEffect.READ_WORKSPACE: (
            "workspace-read",
            5,
            "The tool can read files or directories from the workspace.",
            ToolRiskFactor.WORKSPACE_READ,
        ),
        ToolSideEffect.WRITE_WORKSPACE: (
            "workspace-write",
            20,
            "The tool can write or mutate workspace files.",
            ToolRiskFactor.FILESYSTEM_WRITE,
        ),
        ToolSideEffect.RUN_PROCESS: (
            "process-execution",
            35,
            "The tool can execute a local process.",
            ToolRiskFactor.PROCESS_EXECUTION,
        ),
        ToolSideEffect.ACCESS_NETWORK: (
            "network-access",
            35,
            "The tool can access the network.",
            ToolRiskFactor.NETWORK_ACCESS,
        ),
        ToolSideEffect.MUTATE_SYSTEM: (
            "system-mutation",
            80,
            "The tool can mutate host or system state outside the workspace.",
            ToolRiskFactor.EXTERNAL_SIDE_EFFECT,
        ),
    }
    _CAPABILITY_RULES: Mapping[
        ToolCapability,
        tuple[str, int, str, ToolRiskFactor | None],
    ] = {
        ToolCapability.FILE_READ: (
            "file-read-capability",
            5,
            "The tool declares file-read capability.",
            ToolRiskFactor.WORKSPACE_READ,
        ),
        ToolCapability.FILE_WRITE: (
            "file-write-capability",
            15,
            "The tool declares file-write capability.",
            ToolRiskFactor.FILESYSTEM_WRITE,
        ),
        ToolCapability.PATCH_APPLY: (
            "patch-apply-capability",
            20,
            "The tool declares patch-application capability.",
            ToolRiskFactor.PATCH_APPLY,
        ),
        ToolCapability.COMMAND_EXECUTION: (
            "process-execution-capability",
            20,
            "The tool declares command-execution capability.",
            ToolRiskFactor.PROCESS_EXECUTION,
        ),
        ToolCapability.TEST_EXECUTION: (
            "test-execution-capability",
            20,
            "The tool declares test-execution capability.",
            ToolRiskFactor.PROCESS_EXECUTION,
        ),
        ToolCapability.ARTIFACT_EXPORT: (
            "artifact-export-capability",
            5,
            "The tool can emit exported artifacts.",
            ToolRiskFactor.EXTERNAL_SIDE_EFFECT,
        ),
    }
    _REVIEW_SIGNAL_CODES = frozenset(
        {
            "destructive-operation-reference",
            "network-access",
            "override-requested",
            "patch-apply-capability",
            "process-execution",
            "process-execution-capability",
            "sensitive-path-reference",
            "system-mutation",
            "test-execution-capability",
            "workspace-write",
        }
    )

    def assess(
        self,
        *,
        request: ToolInvocationRequest,
        manifest: ToolManifest | None,
    ) -> ToolRiskAssessment:
        signals: list[ToolRiskSignal] = []
        factors: list[ToolRiskFactor] = []
        metadata = _request_metadata(request)
        score = 0

        if manifest is None:
            score += _append_signal(
                signals,
                code="unknown-tool",
                signal_score=100,
                summary="No manifest was available for the requested tool.",
            )
            factors.append(ToolRiskFactor.UNKNOWN_TOOL)
            metadata["known_tool"] = False
            return self._assessment(request, None, score, signals, factors, metadata)

        metadata.update(
            {
                "known_tool": True,
                "manifest_version": manifest.version,
                "declared_capabilities": [
                    capability.value for capability in manifest.capabilities
                ],
                "declared_side_effects": [
                    side_effect.value for side_effect in manifest.side_effects
                ],
                "approval_mode": manifest.approval_mode.value,
            }
        )

        if not manifest.supports(request.capability):
            score += _append_signal(
                signals,
                code="unsupported-capability",
                signal_score=100,
                summary="The request capability is not declared by the tool manifest.",
                metadata={
                    "requested_capability": request.capability.value,
                    "declared_capabilities": [
                        capability.value for capability in manifest.capabilities
                    ],
                },
            )
            factors.append(ToolRiskFactor.UNSUPPORTED_CAPABILITY)

        for side_effect in manifest.side_effects:
            score += self._score_declared_rule(
                side_effect,
                rules=self._SIDE_EFFECT_RULES,
                signals=signals,
                factors=factors,
            )

        for capability in manifest.capabilities:
            score += self._score_declared_rule(
                capability,
                rules=self._CAPABILITY_RULES,
                signals=signals,
                factors=factors,
            )

        if manifest.approval_mode is ToolApprovalMode.ALWAYS:
            score += _append_signal(
                signals,
                code="manifest-approval-required",
                signal_score=15,
                summary="The tool manifest requires human approval by default.",
            )
            factors.append(ToolRiskFactor.APPROVAL_REQUIRED)

        argument_score, argument_factors = _score_arguments(request.arguments, signals)
        score += argument_score
        factors.extend(argument_factors)

        return self._assessment(request, manifest, score, signals, factors, metadata)

    def _score_declared_rule(
        self,
        value: ToolSideEffect | ToolCapability,
        *,
        rules: Mapping[
            ToolSideEffect | ToolCapability,
            tuple[str, int, str, ToolRiskFactor | None],
        ],
        signals: list[ToolRiskSignal],
        factors: list[ToolRiskFactor],
    ) -> int:
        rule = rules.get(value)
        if rule is None:
            return 0
        code, signal_score, summary, factor = rule
        if code != "no-side-effect":
            score = _append_signal(
                signals,
                code=code,
                signal_score=signal_score,
                summary=summary,
            )
        else:
            score = 0
        if factor is not None:
            factors.append(factor)
        return score

    def _assessment(
        self,
        request: ToolInvocationRequest,
        manifest: ToolManifest | None,
        score: int,
        signals: Iterable[ToolRiskSignal],
        factors: Iterable[ToolRiskFactor],
        metadata: Mapping[str, Any],
    ) -> ToolRiskAssessment:
        unique_signals = _dedupe_signals(signals)
        unique_factors = tuple(dict.fromkeys(factors))
        level = _level_from_score(score)
        requires_human_review = (
            level in {ToolRiskLevel.HIGH, ToolRiskLevel.CRITICAL}
            or (manifest is not None and manifest.approval_mode is ToolApprovalMode.ALWAYS)
            or any(signal.code in self._REVIEW_SIGNAL_CODES for signal in unique_signals)
        )
        signal_text = ", ".join(signal.code for signal in unique_signals)
        if not signal_text:
            signal_text = "no elevated signals"
        return ToolRiskAssessment(
            tool_name=request.tool_id,
            level=level,
            score=score,
            signals=unique_signals,
            factors=unique_factors,
            rationale=(
                f"Tool '{request.tool_id}' assessed at {level.value} risk "
                f"with score {score}. Signals: {signal_text}."
            ),
            requires_human_review=requires_human_review,
            metadata=metadata,
        )


class ToolRiskEvaluator(ToolRiskClassifier):
    """
    Backward-compatible name for the deterministic tool risk classifier.
    """


@dataclass(frozen=True, slots=True)
class ToolRiskPolicy:
    """
    Policy threshold for tool invocation authorization.
    """

    max_auto_level: ToolRiskLevel = ToolRiskLevel.LOW
    require_review_for_factors: tuple[ToolRiskFactor, ...] = (
        ToolRiskFactor.FILESYSTEM_WRITE,
        ToolRiskFactor.PATCH_APPLY,
        ToolRiskFactor.PROCESS_EXECUTION,
        ToolRiskFactor.NETWORK_ACCESS,
        ToolRiskFactor.SECRET_ACCESS,
        ToolRiskFactor.DESTRUCTIVE_OPERATION,
        ToolRiskFactor.SENSITIVE_PATH_SIGNAL,
        ToolRiskFactor.OVERRIDE_REQUESTED,
    )
    block_factors: tuple[ToolRiskFactor, ...] = (
        ToolRiskFactor.UNKNOWN_TOOL,
        ToolRiskFactor.UNSUPPORTED_CAPABILITY,
        ToolRiskFactor.PATH_TRAVERSAL_SIGNAL,
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "require_review_for_factors",
            tuple(self.require_review_for_factors),
        )
        object.__setattr__(self, "block_factors", tuple(self.block_factors))


class ToolRiskDecisionKind(StrEnum):
    """
    Deterministic decision for one tool invocation risk assessment.
    """

    ALLOW = auto()
    REQUIRE_REVIEW = auto()
    BLOCK = auto()


@dataclass(frozen=True, slots=True)
class ToolRiskDecision:
    """
    Decision produced from a risk assessment and risk policy.
    """

    decision: ToolRiskDecisionKind
    reason: str
    assessment: ToolRiskAssessment

    @property
    def allowed(self) -> bool:
        return self.decision is ToolRiskDecisionKind.ALLOW

    @property
    def requires_review(self) -> bool:
        return self.decision is ToolRiskDecisionKind.REQUIRE_REVIEW

    @property
    def blocked(self) -> bool:
        return self.decision is ToolRiskDecisionKind.BLOCK


class ToolRiskPolicyEngine:
    """
    Apply deterministic risk policy to tool risk assessments.
    """

    _LEVEL_ORDER: dict[ToolRiskLevel, int] = {
        ToolRiskLevel.LOW: 1,
        ToolRiskLevel.MEDIUM: 2,
        ToolRiskLevel.HIGH: 3,
        ToolRiskLevel.CRITICAL: 4,
    }

    def __init__(self, *, policy: ToolRiskPolicy | None = None) -> None:
        self._policy = policy or ToolRiskPolicy()

    def decide(self, assessment: ToolRiskAssessment) -> ToolRiskDecision:
        factor_set = set(assessment.factors)
        blocked_matches = factor_set.intersection(self._policy.block_factors)
        if blocked_matches:
            return ToolRiskDecision(
                decision=ToolRiskDecisionKind.BLOCK,
                reason=(
                    "Tool invocation blocked because risk assessment includes "
                    "blocked factors: "
                    f"{', '.join(sorted(factor.value for factor in blocked_matches))}."
                ),
                assessment=assessment,
            )

        if self._LEVEL_ORDER[assessment.level] > self._LEVEL_ORDER[
            self._policy.max_auto_level
        ]:
            return ToolRiskDecision(
                decision=ToolRiskDecisionKind.REQUIRE_REVIEW,
                reason=(
                    f"Tool invocation requires review because risk level "
                    f"{assessment.level.value} exceeds automatic threshold "
                    f"{self._policy.max_auto_level.value}."
                ),
                assessment=assessment,
            )

        review_matches = factor_set.intersection(self._policy.require_review_for_factors)
        if review_matches:
            return ToolRiskDecision(
                decision=ToolRiskDecisionKind.REQUIRE_REVIEW,
                reason=(
                    "Tool invocation requires review because risk assessment "
                    "includes review factors: "
                    f"{', '.join(sorted(factor.value for factor in review_matches))}."
                ),
                assessment=assessment,
            )

        if assessment.requires_human_review:
            return ToolRiskDecision(
                decision=ToolRiskDecisionKind.REQUIRE_REVIEW,
                reason="Tool manifest or assessment requires human review.",
                assessment=assessment,
            )

        return ToolRiskDecision(
            decision=ToolRiskDecisionKind.ALLOW,
            reason="Tool invocation risk is within automatic execution threshold.",
            assessment=assessment,
        )


class ToolRiskLedger:
    """
    Append-only in-memory ledger of tool risk decisions.
    """

    def __init__(self) -> None:
        self._decisions: list[ToolRiskDecision] = []

    def append(self, decision: ToolRiskDecision) -> ToolRiskDecision:
        self._decisions.append(decision)
        return decision

    def decisions(self) -> tuple[ToolRiskDecision, ...]:
        return tuple(self._decisions)

    def by_tool(self, tool_name: str) -> tuple[ToolRiskDecision, ...]:
        normalized = _normalize_identifier(tool_name, label="tool_name")
        return tuple(
            decision
            for decision in self._decisions
            if decision.assessment.tool_name == normalized
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "decisions": [
                {
                    "decision": decision.decision.value,
                    "reason": decision.reason,
                    "assessment": decision.assessment.to_dict(),
                }
                for decision in self._decisions
            ]
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        ledger = cls()
        raw_decisions = payload.get("decisions", ())
        if not isinstance(raw_decisions, Iterable) or isinstance(raw_decisions, str):
            raise TypeError("Tool risk ledger decisions must be iterable.")

        for raw_decision in raw_decisions:
            if not isinstance(raw_decision, Mapping):
                raise TypeError("Tool risk ledger decisions must contain mappings.")
            raw_assessment = raw_decision.get("assessment")
            if not isinstance(raw_assessment, Mapping):
                raise TypeError("Tool risk decision assessment must be a mapping.")
            ledger.append(
                ToolRiskDecision(
                    decision=ToolRiskDecisionKind(_require_text(raw_decision, "decision")),
                    reason=_require_text(raw_decision, "reason"),
                    assessment=ToolRiskAssessment.from_dict(raw_assessment),
                )
            )

        return ledger


def _score_arguments(
    arguments: Mapping[str, Any],
    signals: list[ToolRiskSignal],
) -> tuple[int, tuple[ToolRiskFactor, ...]]:
    factors: list[ToolRiskFactor] = []
    score = 0
    serialized = repr(dict(arguments))

    if len(serialized) > 8000:
        score += _append_signal(
            signals,
            code="large-argument-payload",
            signal_score=10,
            summary="The invocation arguments contain a large serialized payload.",
            metadata={"serialized_length": len(serialized)},
        )
        factors.append(ToolRiskFactor.LARGE_ARGUMENT_PAYLOAD)
    if _contains_path_traversal_signal(arguments):
        score += _append_signal(
            signals,
            code="path-traversal-reference",
            signal_score=100,
            summary="The invocation arguments reference path traversal.",
        )
        factors.append(ToolRiskFactor.PATH_TRAVERSAL_SIGNAL)
    if _contains_absolute_path_signal(arguments):
        score += _append_signal(
            signals,
            code="absolute-path-reference",
            signal_score=60,
            summary="The invocation arguments reference an absolute path.",
        )
        factors.append(ToolRiskFactor.ABSOLUTE_PATH_SIGNAL)
    if _contains_sensitive_path_signal(arguments):
        score += _append_signal(
            signals,
            code="sensitive-path-reference",
            signal_score=25,
            summary="The invocation arguments reference a sensitive path or secret-like name.",
        )
        factors.append(ToolRiskFactor.SENSITIVE_PATH_SIGNAL)
    if _contains_destructive_signal(arguments):
        score += _append_signal(
            signals,
            code="destructive-operation-reference",
            signal_score=35,
            summary="The invocation arguments contain destructive operation language.",
        )
        factors.append(ToolRiskFactor.DESTRUCTIVE_OPERATION)
    if _contains_override_signal(arguments):
        score += _append_signal(
            signals,
            code="override-requested",
            signal_score=20,
            summary="The invocation arguments appear to request policy bypass or override.",
        )
        factors.append(ToolRiskFactor.OVERRIDE_REQUESTED)

    return score, tuple(dict.fromkeys(factors))


def _append_signal(
    signals: list[ToolRiskSignal],
    *,
    code: str,
    signal_score: int,
    summary: str,
    metadata: Mapping[str, Any] | None = None,
) -> int:
    normalized_code = _normalize_signal_code(code)
    if any(signal.code == normalized_code for signal in signals):
        return 0
    signals.append(
        ToolRiskSignal(
            code=normalized_code,
            score=signal_score,
            summary=summary,
            metadata=dict(metadata or {}),
        )
    )
    return signal_score


def _level_from_score(score: int) -> ToolRiskLevel:
    if score >= 100:
        return ToolRiskLevel.CRITICAL
    if score >= 60:
        return ToolRiskLevel.HIGH
    if score >= 25:
        return ToolRiskLevel.MEDIUM
    return ToolRiskLevel.LOW


def _request_metadata(request: ToolInvocationRequest) -> dict[str, Any]:
    return {
        "invocation_id": request.invocation_id,
        "tool_id": request.tool_id,
        "requested_capability": request.capability.value,
        "argument_keys": sorted(request.arguments.keys()),
    }


def _contains_path_traversal_signal(arguments: Mapping[str, Any]) -> bool:
    for value in _walk_argument_values(arguments):
        if isinstance(value, str):
            normalized = value.strip().replace("\\", "/")
            if normalized == ".." or normalized.startswith("../"):
                return True
            if "/../" in normalized or normalized.endswith("/..") or "/.." in normalized:
                return True
    return False


def _contains_absolute_path_signal(arguments: Mapping[str, Any]) -> bool:
    for value in _walk_argument_values(arguments):
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith("/") or _WINDOWS_ABSOLUTE_PATH.match(stripped):
                return True
    return False


def _contains_sensitive_path_signal(arguments: Mapping[str, Any]) -> bool:
    sensitive_terms = (
        ".env",
        "secret",
        "secrets",
        "credential",
        "credentials",
        "private_key",
        "ssh_key",
        "api_key",
        "access_token",
        "refresh_token",
    )
    for value in _walk_argument_values(arguments):
        if isinstance(value, str):
            normalized = value.strip().lower().replace("\\", "/")
            if any(term in normalized for term in sensitive_terms):
                return True
    return False


def _contains_destructive_signal(arguments: Mapping[str, Any]) -> bool:
    destructive_terms = (
        "delete",
        "remove",
        "rm ",
        "rmdir",
        "drop table",
        "truncate table",
        "format",
        "wipe",
    )
    for value in _walk_argument_values(arguments):
        if isinstance(value, str):
            normalized = value.strip().lower()
            if any(term in normalized for term in destructive_terms):
                return True
    return False


def _contains_override_signal(arguments: Mapping[str, Any]) -> bool:
    override_terms = (
        "force",
        "override",
        "bypass",
        "ignore_policy",
        "skip_policy",
        "unsafe",
    )
    for key, value in _walk_argument_items(arguments):
        normalized_key = key.strip().lower()
        if any(term in normalized_key for term in override_terms):
            return True
        if isinstance(value, str):
            normalized_value = value.strip().lower()
            if any(term in normalized_value for term in override_terms):
                return True
    return False


def _walk_argument_values(value: Any) -> Iterable[Any]:
    if isinstance(value, Mapping):
        for nested_value in value.values():
            yield from _walk_argument_values(nested_value)
    elif isinstance(value, list | tuple | set):
        for item in value:
            yield from _walk_argument_values(item)
    else:
        yield value


def _walk_argument_items(value: Mapping[str, Any]) -> Iterable[tuple[str, Any]]:
    for key, nested_value in value.items():
        yield str(key), nested_value
        if isinstance(nested_value, Mapping):
            yield from _walk_argument_items(nested_value)
        elif isinstance(nested_value, list | tuple | set):
            for item in nested_value:
                if isinstance(item, Mapping):
                    yield from _walk_argument_items(item)


def _dedupe_signals(signals: Iterable[ToolRiskSignal]) -> tuple[ToolRiskSignal, ...]:
    deduped: list[ToolRiskSignal] = []
    seen: set[str] = set()
    for signal in signals:
        if signal.code not in seen:
            deduped.append(signal)
            seen.add(signal.code)
    return tuple(deduped)


def _normalize_signal_code(value: str) -> str:
    cleaned = value.strip().lower().replace("_", "-").replace(" ", "-")
    if not cleaned:
        raise ValueError("Tool risk signal code must not be empty.")
    return cleaned


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_text(value: str, label: str) -> str:
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
