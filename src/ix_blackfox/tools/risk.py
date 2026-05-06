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

    The level describes execution risk, not model confidence.
    """

    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


class ToolRiskFactor(StrEnum):
    """
    Specific factors that contributed to a tool risk score.
    """

    MANIFEST_HIGH_RISK = auto()
    MANIFEST_CRITICAL_RISK = auto()
    APPROVAL_REQUIRED = auto()
    FILESYSTEM_WRITE = auto()
    PATCH_APPLY = auto()
    PROCESS_EXECUTION = auto()
    NETWORK_ACCESS = auto()
    EXTERNAL_SIDE_EFFECT = auto()
    DESTRUCTIVE_OPERATION = auto()
    SECRET_ACCESS = auto()
    LARGE_ARGUMENT_PAYLOAD = auto()
    PATH_TRAVERSAL_SIGNAL = auto()
    OVERRIDE_REQUESTED = auto()
    UNKNOWN_TOOL = auto()


@dataclass(frozen=True, slots=True)
class ToolRiskAssessment:
    """
    Deterministic risk assessment for a tool invocation.
    """

    tool_name: str
    level: ToolRiskLevel
    score: int
    factors: tuple[ToolRiskFactor, ...]
    rationale: str
    requires_human_review: bool
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.score < 0:
            raise ValueError("Tool risk score must be non-negative.")
        if not self.tool_name.strip():
            raise ValueError("Tool risk tool_name must not be empty.")

        object.__setattr__(self, "tool_name", self.tool_name.strip())
        object.__setattr__(self, "factors", tuple(dict.fromkeys(self.factors)))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "level": self.level.value,
            "score": self.score,
            "factors": [factor.value for factor in self.factors],
            "rationale": self.rationale,
            "requires_human_review": self.requires_human_review,
            "metadata": dict(self.metadata),
        }


class ToolRiskEvaluator:
    """
    Deterministic tool-risk evaluator.

    This is the bridge between declarative tool manifests and runtime
    governance. It does not trust tool arguments simply because the tool
    is registered; request payloads can still raise risk.
    """

    _SIDE_EFFECT_FACTORS: dict[ToolSideEffect, ToolRiskFactor] = {
        ToolSideEffect.FILESYSTEM_WRITE: ToolRiskFactor.FILESYSTEM_WRITE,
        ToolSideEffect.NETWORK_ACCESS: ToolRiskFactor.NETWORK_ACCESS,
        ToolSideEffect.PROCESS_EXECUTION: ToolRiskFactor.PROCESS_EXECUTION,
        ToolSideEffect.SYSTEM_STATE_CHANGE: ToolRiskFactor.EXTERNAL_SIDE_EFFECT,
        ToolSideEffect.ARTIFACT_WRITE: ToolRiskFactor.FILESYSTEM_WRITE,
    }

    _CAPABILITY_FACTORS: dict[ToolCapability, ToolRiskFactor] = {
        ToolCapability.FILE_WRITE: ToolRiskFactor.FILESYSTEM_WRITE,
        ToolCapability.PATCH_APPLY: ToolRiskFactor.PATCH_APPLY,
        ToolCapability.PROCESS_EXECUTION: ToolRiskFactor.PROCESS_EXECUTION,
        ToolCapability.NETWORK_REQUEST: ToolRiskFactor.NETWORK_ACCESS,
        ToolCapability.SECRET_READ: ToolRiskFactor.SECRET_ACCESS,
    }

    def assess(
        self,
        *,
        request: ToolInvocationRequest,
        manifest: ToolManifest | None,
    ) -> ToolRiskAssessment:
        """
        Assess risk for one tool invocation request.
        """
        factors: list[ToolRiskFactor] = []
        score = 0
        metadata: dict[str, Any] = {
            "invocation_id": request.invocation_id,
            "argument_keys": sorted(request.arguments.keys()),
        }

        if manifest is None:
            factors.append(ToolRiskFactor.UNKNOWN_TOOL)
            score += 90
            metadata["known_tool"] = False
            return ToolRiskAssessment(
                tool_name=request.tool_name,
                level=ToolRiskLevel.CRITICAL,
                score=score,
                factors=tuple(factors),
                rationale="Tool is not registered; invocation is treated as critical risk.",
                requires_human_review=True,
                metadata=metadata,
            )

        metadata["known_tool"] = True
        metadata["manifest_version"] = manifest.version

        manifest_score, manifest_factors = self._score_manifest(manifest)
        score += manifest_score
        factors.extend(manifest_factors)

        argument_score, argument_factors = self._score_arguments(request.arguments)
        score += argument_score
        factors.extend(argument_factors)

        level = self._level_from_score(score)
        requires_human_review = (
            manifest.approval_mode in {ToolApprovalMode.REQUIRED, ToolApprovalMode.ALWAYS_REQUIRED}
            or level in {ToolRiskLevel.HIGH, ToolRiskLevel.CRITICAL}
        )
        rationale = self._build_rationale(
            manifest=manifest,
            score=score,
            level=level,
            factors=tuple(dict.fromkeys(factors)),
        )

        return ToolRiskAssessment(
            tool_name=request.tool_name,
            level=level,
            score=score,
            factors=tuple(factors),
            rationale=rationale,
            requires_human_review=requires_human_review,
            metadata=metadata,
        )

    def _score_manifest(
        self,
        manifest: ToolManifest,
    ) -> tuple[int, tuple[ToolRiskFactor, ...]]:
        score = 0
        factors: list[ToolRiskFactor] = []

        if manifest.risk_level.value == "high":
            score += 45
            factors.append(ToolRiskFactor.MANIFEST_HIGH_RISK)
        elif manifest.risk_level.value == "critical":
            score += 80
            factors.append(ToolRiskFactor.MANIFEST_CRITICAL_RISK)
        elif manifest.risk_level.value == "medium":
            score += 20
        else:
            score += 5

        if manifest.approval_mode in {
            ToolApprovalMode.REQUIRED,
            ToolApprovalMode.ALWAYS_REQUIRED,
        }:
            score += 20
            factors.append(ToolRiskFactor.APPROVAL_REQUIRED)

        for side_effect in manifest.side_effects:
            factor = self._SIDE_EFFECT_FACTORS.get(side_effect)
            if factor is not None:
                factors.append(factor)
                score += self._score_factor(factor)

        for capability in manifest.capabilities:
            factor = self._CAPABILITY_FACTORS.get(capability)
            if factor is not None:
                factors.append(factor)
                score += self._score_factor(factor)

        return score, tuple(dict.fromkeys(factors))

    def _score_arguments(
        self,
        arguments: Mapping[str, Any],
    ) -> tuple[int, tuple[ToolRiskFactor, ...]]:
        factors: list[ToolRiskFactor] = []
        score = 0

        serialized = repr(dict(arguments))
        if len(serialized) > 8000:
            score += 10
            factors.append(ToolRiskFactor.LARGE_ARGUMENT_PAYLOAD)

        if _contains_path_traversal_signal(arguments):
            score += 40
            factors.append(ToolRiskFactor.PATH_TRAVERSAL_SIGNAL)

        if _contains_destructive_signal(arguments):
            score += 35
            factors.append(ToolRiskFactor.DESTRUCTIVE_OPERATION)

        if _contains_override_signal(arguments):
            score += 20
            factors.append(ToolRiskFactor.OVERRIDE_REQUESTED)

        return score, tuple(dict.fromkeys(factors))

    def _score_factor(self, factor: ToolRiskFactor) -> int:
        return {
            ToolRiskFactor.FILESYSTEM_WRITE: 15,
            ToolRiskFactor.PATCH_APPLY: 20,
            ToolRiskFactor.PROCESS_EXECUTION: 35,
            ToolRiskFactor.NETWORK_ACCESS: 20,
            ToolRiskFactor.EXTERNAL_SIDE_EFFECT: 25,
            ToolRiskFactor.SECRET_ACCESS: 45,
            ToolRiskFactor.DESTRUCTIVE_OPERATION: 35,
            ToolRiskFactor.PATH_TRAVERSAL_SIGNAL: 40,
            ToolRiskFactor.OVERRIDE_REQUESTED: 20,
        }.get(factor, 10)

    def _level_from_score(self, score: int) -> ToolRiskLevel:
        if score >= 100:
            return ToolRiskLevel.CRITICAL
        if score >= 60:
            return ToolRiskLevel.HIGH
        if score >= 25:
            return ToolRiskLevel.MEDIUM
        return ToolRiskLevel.LOW

    def _build_rationale(
        self,
        *,
        manifest: ToolManifest,
        score: int,
        level: ToolRiskLevel,
        factors: tuple[ToolRiskFactor, ...],
    ) -> str:
        factor_text = (
            ", ".join(factor.value for factor in factors)
            if factors
            else "no elevated factors"
        )
        return (
            f"Tool '{manifest.name}' assessed at {level.value} risk "
            f"with score {score}. Factors: {factor_text}."
        )


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
        ToolRiskFactor.PATH_TRAVERSAL_SIGNAL,
        ToolRiskFactor.OVERRIDE_REQUESTED,
    )
    block_factors: tuple[ToolRiskFactor, ...] = (
        ToolRiskFactor.UNKNOWN_TOOL,
        ToolRiskFactor.PATH_TRAVERSAL_SIGNAL,
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "require_review_for_factors", tuple(self.require_review_for_factors))
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
        """
        Decide whether the invocation may proceed, requires review, or is blocked.
        """
        factor_set = set(assessment.factors)
        block_factors = set(self._policy.block_factors)
        review_factors = set(self._policy.require_review_for_factors)

        if factor_set.intersection(block_factors):
            return ToolRiskDecision(
                decision=ToolRiskDecisionKind.BLOCK,
                reason=(
                    "Tool invocation blocked because risk assessment includes blocked factors: "
                    f"{', '.join(sorted(factor.value for factor in factor_set.intersection(block_factors)))}."
                ),
                assessment=assessment,
            )

        if self._LEVEL_ORDER[assessment.level] > self._LEVEL_ORDER[self._policy.max_auto_level]:
            return ToolRiskDecision(
                decision=ToolRiskDecisionKind.REQUIRE_REVIEW,
                reason=(
                    f"Tool invocation requires review because risk level {assessment.level.value} "
                    f"exceeds automatic threshold {self._policy.max_auto_level.value}."
                ),
                assessment=assessment,
            )

        if factor_set.intersection(review_factors):
            return ToolRiskDecision(
                decision=ToolRiskDecisionKind.REQUIRE_REVIEW,
                reason=(
                    "Tool invocation requires review because risk assessment includes review factors: "
                    f"{', '.join(sorted(factor.value for factor in factor_set.intersection(review_factors)))}."
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

    This is deliberately lightweight but gives the runtime an auditable
    structure for later receipt persistence.
    """

    def __init__(self) -> None:
        self._decisions: list[ToolRiskDecision] = []

    def append(self, decision: ToolRiskDecision) -> ToolRiskDecision:
        self._decisions.append(decision)
        return decision

    def decisions(self) -> tuple[ToolRiskDecision, ...]:
        return tuple(self._decisions)

    def by_tool(self, tool_name: str) -> tuple[ToolRiskDecision, ...]:
        normalized = tool_name.strip()
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
        if not isinstance(raw_decisions, Iterable):
            raise TypeError("Tool risk ledger decisions must be iterable.")

        for raw_decision in raw_decisions:
            if not isinstance(raw_decision, Mapping):
                raise TypeError("Tool risk ledger decisions must contain mappings.")
            raw_assessment = raw_decision.get("assessment")
            if not isinstance(raw_assessment, Mapping):
                raise TypeError("Tool risk decision assessment must be a mapping.")

            assessment = ToolRiskAssessment(
                tool_name=str(raw_assessment["tool_name"]),
                level=ToolRiskLevel(str(raw_assessment["level"])),
                score=int(raw_assessment["score"]),
                factors=tuple(
                    ToolRiskFactor(str(value))
                    for value in raw_assessment.get("factors", ())
                ),
                rationale=str(raw_assessment["rationale"]),
                requires_human_review=bool(raw_assessment["requires_human_review"]),
                metadata=(
                    dict(raw_assessment["metadata"])
                    if isinstance(raw_assessment.get("metadata"), Mapping)
                    else {}
                ),
            )
            ledger.append(
                ToolRiskDecision(
                    decision=ToolRiskDecisionKind(str(raw_decision["decision"])),
                    reason=str(raw_decision["reason"]),
                    assessment=assessment,
                )
            )

        return ledger


def _contains_path_traversal_signal(arguments: Mapping[str, Any]) -> bool:
    for value in _walk_argument_values(arguments):
        if not isinstance(value, str):
            continue

        normalized = value.replace("\\", "/")
        if "../" in normalized or normalized.startswith("../") or "/.." in normalized:
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
        normalized_key = str(key).strip().lower()
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
