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
from ix_blackfox.tools.risk import (
    ToolRiskAssessment,
    ToolRiskClassifier,
    ToolRiskLevel,
)


class ToolPolicyDecision(StrEnum):
    """
    Final policy decision for one governed tool invocation.
    """

    ALLOW = auto()
    REVIEW_REQUIRED = auto()
    BLOCK = auto()


@dataclass(frozen=True, slots=True)
class ToolPolicyReason:
    """
    One explainable reason behind a governed tool policy decision.
    """

    code: str
    decision: ToolPolicyDecision
    summary: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _normalize_token(self.code, label="code"))
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "decision": self.decision.value,
            "summary": self.summary,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            code=_require_text(payload, "code"),
            decision=ToolPolicyDecision(_require_text(payload, "decision")),
            summary=_require_text(payload, "summary"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class ToolPolicyEvaluation:
    """
    Deterministic policy evaluation for one tool invocation.
    """

    tool_id: str
    invocation_id: str
    decision: ToolPolicyDecision
    risk_assessment: ToolRiskAssessment
    reasons: tuple[ToolPolicyReason, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tool_id", _normalize_token(self.tool_id, label="tool_id"))
        object.__setattr__(
            self,
            "invocation_id",
            _normalize_token(self.invocation_id, label="invocation_id"),
        )
        object.__setattr__(self, "reasons", tuple(self.reasons))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def is_allowed(self) -> bool:
        return self.decision is ToolPolicyDecision.ALLOW

    @property
    def requires_review(self) -> bool:
        return self.decision is ToolPolicyDecision.REVIEW_REQUIRED

    @property
    def is_blocked(self) -> bool:
        return self.decision is ToolPolicyDecision.BLOCK

    @property
    def reason_codes(self) -> tuple[str, ...]:
        return tuple(reason.code for reason in self.reasons)

    def has_reason(self, code: str) -> bool:
        normalized_code = _normalize_token(code, label="code")
        return normalized_code in self.reason_codes

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "invocation_id": self.invocation_id,
            "decision": self.decision.value,
            "risk_assessment": self.risk_assessment.to_dict(),
            "reasons": [reason.to_dict() for reason in self.reasons],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_reasons = payload.get("reasons", ())
        if not isinstance(raw_reasons, Iterable) or isinstance(raw_reasons, str):
            raise TypeError("reasons must be an iterable of mappings.")

        reasons: list[ToolPolicyReason] = []
        for raw_reason in raw_reasons:
            if not isinstance(raw_reason, Mapping):
                raise TypeError("reasons must contain only mappings.")
            reasons.append(ToolPolicyReason.from_dict(raw_reason))

        raw_risk_assessment = payload.get("risk_assessment")
        if not isinstance(raw_risk_assessment, Mapping):
            raise TypeError("risk_assessment must be a mapping.")

        return cls(
            tool_id=_require_text(payload, "tool_id"),
            invocation_id=_require_text(payload, "invocation_id"),
            decision=ToolPolicyDecision(_require_text(payload, "decision")),
            risk_assessment=ToolRiskAssessment.from_dict(raw_risk_assessment),
            reasons=tuple(reasons),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class ToolPolicyEvaluatorConfig:
    """
    Conservative policy defaults for governed tool execution.

    The defaults are intentionally strict:
    - network access is blocked
    - host/system mutation is blocked
    - path traversal is blocked
    - absolute paths are blocked
    - workspace writes and process execution require review
    """

    allow_network_access: bool = False
    allow_system_mutation: bool = False
    allow_absolute_paths: bool = False
    block_on_critical_risk: bool = True
    review_high_risk: bool = True
    review_workspace_writes: bool = True
    review_process_execution: bool = True
    review_sensitive_paths: bool = True
    blocked_capabilities: tuple[ToolCapability, ...] = field(default_factory=tuple)
    blocked_side_effects: tuple[ToolSideEffect, ...] = field(default_factory=tuple)
    review_capabilities: tuple[ToolCapability, ...] = (
        ToolCapability.FILE_WRITE,
        ToolCapability.PATCH_APPLY,
        ToolCapability.COMMAND_EXECUTION,
        ToolCapability.TEST_EXECUTION,
    )
    review_side_effects: tuple[ToolSideEffect, ...] = (
        ToolSideEffect.WRITE_WORKSPACE,
        ToolSideEffect.RUN_PROCESS,
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "blocked_capabilities",
            _dedupe_enum_tuple(
                self.blocked_capabilities,
                enum_type=ToolCapability,
                field_name="blocked_capabilities",
            ),
        )
        object.__setattr__(
            self,
            "blocked_side_effects",
            _dedupe_enum_tuple(
                self.blocked_side_effects,
                enum_type=ToolSideEffect,
                field_name="blocked_side_effects",
            ),
        )
        object.__setattr__(
            self,
            "review_capabilities",
            _dedupe_enum_tuple(
                self.review_capabilities,
                enum_type=ToolCapability,
                field_name="review_capabilities",
            ),
        )
        object.__setattr__(
            self,
            "review_side_effects",
            _dedupe_enum_tuple(
                self.review_side_effects,
                enum_type=ToolSideEffect,
                field_name="review_side_effects",
            ),
        )


@dataclass(frozen=True, slots=True)
class ToolPolicyEvaluator:
    """
    Deterministic allow/review/block evaluator for governed tools.

    This layer does not execute tools. It turns the declared manifest, requested
    capability, invocation arguments, and deterministic risk signals into an
    auditable policy decision.
    """

    config: ToolPolicyEvaluatorConfig = field(default_factory=ToolPolicyEvaluatorConfig)
    risk_classifier: ToolRiskClassifier = field(default_factory=ToolRiskClassifier)

    def evaluate(
        self,
        *,
        manifest: ToolManifest,
        request: ToolInvocationRequest,
        risk_assessment: ToolRiskAssessment | None = None,
    ) -> ToolPolicyEvaluation:
        assessment = risk_assessment or self.risk_classifier.assess(
            manifest=manifest,
            request=request,
        )
        reasons = self._build_reasons(
            manifest=manifest,
            request=request,
            risk_assessment=assessment,
        )
        decision = _strongest_decision(reason.decision for reason in reasons)

        if not reasons:
            reasons = (
                ToolPolicyReason(
                    code="policy-allow-default",
                    decision=ToolPolicyDecision.ALLOW,
                    summary=(
                        "Tool invocation passed manifest, risk, and policy checks."
                    ),
                    metadata={
                        "risk_level": assessment.level.value,
                        "risk_score": assessment.score,
                    },
                ),
            )
            decision = ToolPolicyDecision.ALLOW

        return ToolPolicyEvaluation(
            tool_id=manifest.tool_id,
            invocation_id=request.invocation_id,
            decision=decision,
            risk_assessment=assessment,
            reasons=tuple(reasons),
            metadata={
                "capability": request.capability.value,
                "approval_mode": manifest.approval_mode.value,
                "risk_level": assessment.level.value,
                "risk_score": assessment.score,
            },
        )

    def _build_reasons(
        self,
        *,
        manifest: ToolManifest,
        request: ToolInvocationRequest,
        risk_assessment: ToolRiskAssessment,
    ) -> tuple[ToolPolicyReason, ...]:
        reasons: list[ToolPolicyReason] = []

        if manifest.tool_id != request.tool_id:
            reasons.append(
                ToolPolicyReason(
                    code="tool-id-mismatch",
                    decision=ToolPolicyDecision.BLOCK,
                    summary="Request tool_id does not match the selected manifest.",
                    metadata={
                        "manifest_tool_id": manifest.tool_id,
                        "request_tool_id": request.tool_id,
                    },
                )
            )

        if not manifest.supports(request.capability):
            reasons.append(
                ToolPolicyReason(
                    code="unsupported-capability",
                    decision=ToolPolicyDecision.BLOCK,
                    summary="Request capability is not declared by the manifest.",
                    metadata={
                        "requested_capability": request.capability.value,
                        "declared_capabilities": [
                            capability.value for capability in manifest.capabilities
                        ],
                    },
                )
            )

        reasons.extend(self._capability_reasons(manifest))
        reasons.extend(self._side_effect_reasons(manifest))
        reasons.extend(self._risk_reasons(risk_assessment))
        reasons.extend(self._approval_mode_reasons(manifest))
        reasons.extend(self._path_signal_reasons(risk_assessment))

        return tuple(_dedupe_reasons(reasons))

    def _capability_reasons(
        self,
        manifest: ToolManifest,
    ) -> tuple[ToolPolicyReason, ...]:
        reasons: list[ToolPolicyReason] = []

        for capability in manifest.capabilities:
            if capability in self.config.blocked_capabilities:
                reasons.append(
                    ToolPolicyReason(
                        code="capability-blocked",
                        decision=ToolPolicyDecision.BLOCK,
                        summary="Tool declares a capability blocked by policy.",
                        metadata={"capability": capability.value},
                    )
                )
            elif capability in self.config.review_capabilities:
                reasons.append(
                    ToolPolicyReason(
                        code="capability-review-required",
                        decision=ToolPolicyDecision.REVIEW_REQUIRED,
                        summary="Tool declares a capability that requires review.",
                        metadata={"capability": capability.value},
                    )
                )

        return tuple(reasons)

    def _side_effect_reasons(
        self,
        manifest: ToolManifest,
    ) -> tuple[ToolPolicyReason, ...]:
        reasons: list[ToolPolicyReason] = []

        for side_effect in manifest.side_effects:
            if side_effect in self.config.blocked_side_effects:
                reasons.append(
                    ToolPolicyReason(
                        code="side-effect-blocked",
                        decision=ToolPolicyDecision.BLOCK,
                        summary="Tool declares a side effect blocked by policy.",
                        metadata={"side_effect": side_effect.value},
                    )
                )

            if side_effect is ToolSideEffect.ACCESS_NETWORK and not self.config.allow_network_access:
                reasons.append(
                    ToolPolicyReason(
                        code="network-access-blocked",
                        decision=ToolPolicyDecision.BLOCK,
                        summary="Network access is disabled by tool policy.",
                        metadata={"side_effect": side_effect.value},
                    )
                )

            if side_effect is ToolSideEffect.MUTATE_SYSTEM and not self.config.allow_system_mutation:
                reasons.append(
                    ToolPolicyReason(
                        code="system-mutation-blocked",
                        decision=ToolPolicyDecision.BLOCK,
                        summary="Host/system mutation is disabled by tool policy.",
                        metadata={"side_effect": side_effect.value},
                    )
                )

            if side_effect in self.config.review_side_effects:
                reasons.append(
                    ToolPolicyReason(
                        code="side-effect-review-required",
                        decision=ToolPolicyDecision.REVIEW_REQUIRED,
                        summary="Tool declares a side effect that requires review.",
                        metadata={"side_effect": side_effect.value},
                    )
                )

            if side_effect is ToolSideEffect.WRITE_WORKSPACE and self.config.review_workspace_writes:
                reasons.append(
                    ToolPolicyReason(
                        code="workspace-write-review-required",
                        decision=ToolPolicyDecision.REVIEW_REQUIRED,
                        summary="Workspace writes require review by default.",
                        metadata={"side_effect": side_effect.value},
                    )
                )

            if side_effect is ToolSideEffect.RUN_PROCESS and self.config.review_process_execution:
                reasons.append(
                    ToolPolicyReason(
                        code="process-execution-review-required",
                        decision=ToolPolicyDecision.REVIEW_REQUIRED,
                        summary="Local process execution requires review by default.",
                        metadata={"side_effect": side_effect.value},
                    )
                )

        return tuple(reasons)

    def _risk_reasons(
        self,
        risk_assessment: ToolRiskAssessment,
    ) -> tuple[ToolPolicyReason, ...]:
        reasons: list[ToolPolicyReason] = []

        if risk_assessment.block_recommended:
            reasons.append(
                ToolPolicyReason(
                    code="risk-block-recommended",
                    decision=ToolPolicyDecision.BLOCK,
                    summary="Risk classifier recommended blocking this invocation.",
                    metadata={
                        "risk_level": risk_assessment.level.value,
                        "risk_score": risk_assessment.score,
                        "risk_signals": list(risk_assessment.signal_codes),
                    },
                )
            )

        if (
            self.config.block_on_critical_risk
            and risk_assessment.level is ToolRiskLevel.CRITICAL
        ):
            reasons.append(
                ToolPolicyReason(
                    code="critical-risk-blocked",
                    decision=ToolPolicyDecision.BLOCK,
                    summary="Critical-risk tool invocations are blocked by policy.",
                    metadata={
                        "risk_level": risk_assessment.level.value,
                        "risk_score": risk_assessment.score,
                    },
                )
            )

        if risk_assessment.approval_recommended:
            reasons.append(
                ToolPolicyReason(
                    code="risk-review-recommended",
                    decision=ToolPolicyDecision.REVIEW_REQUIRED,
                    summary="Risk classifier recommended operator review.",
                    metadata={
                        "risk_level": risk_assessment.level.value,
                        "risk_score": risk_assessment.score,
                        "risk_signals": list(risk_assessment.signal_codes),
                    },
                )
            )

        if self.config.review_high_risk and risk_assessment.level is ToolRiskLevel.HIGH:
            reasons.append(
                ToolPolicyReason(
                    code="high-risk-review-required",
                    decision=ToolPolicyDecision.REVIEW_REQUIRED,
                    summary="High-risk tool invocations require review.",
                    metadata={
                        "risk_level": risk_assessment.level.value,
                        "risk_score": risk_assessment.score,
                    },
                )
            )

        return tuple(reasons)

    def _approval_mode_reasons(
        self,
        manifest: ToolManifest,
    ) -> tuple[ToolPolicyReason, ...]:
        if manifest.approval_mode is ToolApprovalMode.ALWAYS:
            return (
                ToolPolicyReason(
                    code="manifest-approval-required",
                    decision=ToolPolicyDecision.REVIEW_REQUIRED,
                    summary="Tool manifest requires approval before execution.",
                    metadata={"approval_mode": manifest.approval_mode.value},
                ),
            )

        return ()

    def _path_signal_reasons(
        self,
        risk_assessment: ToolRiskAssessment,
    ) -> tuple[ToolPolicyReason, ...]:
        reasons: list[ToolPolicyReason] = []

        if risk_assessment.has_signal("path-traversal-reference"):
            reasons.append(
                ToolPolicyReason(
                    code="path-traversal-blocked",
                    decision=ToolPolicyDecision.BLOCK,
                    summary="Path traversal references are blocked by policy.",
                )
            )

        if (
            risk_assessment.has_signal("absolute-path-reference")
            and not self.config.allow_absolute_paths
        ):
            reasons.append(
                ToolPolicyReason(
                    code="absolute-path-blocked",
                    decision=ToolPolicyDecision.BLOCK,
                    summary="Absolute path references are blocked by policy.",
                )
            )

        if (
            risk_assessment.has_signal("sensitive-path-reference")
            and self.config.review_sensitive_paths
        ):
            reasons.append(
                ToolPolicyReason(
                    code="sensitive-path-review-required",
                    decision=ToolPolicyDecision.REVIEW_REQUIRED,
                    summary="Sensitive path or credential-like references require review.",
                )
            )

        return tuple(reasons)


def _strongest_decision(decisions: Iterable[ToolPolicyDecision]) -> ToolPolicyDecision:
    strongest = ToolPolicyDecision.ALLOW

    for decision in decisions:
        if decision is ToolPolicyDecision.BLOCK:
            return ToolPolicyDecision.BLOCK
        if decision is ToolPolicyDecision.REVIEW_REQUIRED:
            strongest = ToolPolicyDecision.REVIEW_REQUIRED

    return strongest


def _dedupe_reasons(reasons: Iterable[ToolPolicyReason]) -> tuple[ToolPolicyReason, ...]:
    deduped: list[ToolPolicyReason] = []
    seen: set[tuple[str, ToolPolicyDecision, str]] = set()

    for reason in reasons:
        key = (reason.code, reason.decision, repr(sorted(reason.metadata.items())))
        if key in seen:
            continue
        deduped.append(reason)
        seen.add(key)

    return tuple(deduped)


def _dedupe_enum_tuple(
    values: Iterable[Any],
    *,
    enum_type: type[Any],
    field_name: str,
) -> tuple[Any, ...]:
    deduped: list[Any] = []
    seen: set[Any] = set()

    for value in values:
        if not isinstance(value, enum_type):
            raise TypeError(f"{field_name} must contain only {enum_type.__name__}.")
        if value not in seen:
            deduped.append(value)
            seen.add(value)

    return tuple(deduped)


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
