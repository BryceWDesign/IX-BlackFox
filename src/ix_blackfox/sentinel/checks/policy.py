from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ix_blackfox.sentinel.core import (
    SentinelCheck,
    SentinelContext,
    SentinelIssue,
    SentinelSeverity,
)


@dataclass(frozen=True, slots=True)
class PolicyObservation:
    """
    One normalized policy observation for guardrail analysis.

    Attributes
    ----------
    action:
        Logical action name under review.
    decision:
        Policy decision such as allowed, blocked, denied, or review_required.
    executed:
        Whether the action actually ran.
    approved:
        Whether an explicit approval signal was present.
    source:
        Optional source label for diagnostics.
    reason:
        Optional human-readable policy reason.
    """

    action: str
    decision: str
    executed: bool
    approved: bool = False
    source: str | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        normalized_action = _normalize_identifier(self.action, label="action")
        normalized_decision = _normalize_identifier(self.decision, label="decision")
        normalized_source = _normalize_optional_text(self.source)
        normalized_reason = _normalize_optional_text(self.reason)

        object.__setattr__(self, "action", normalized_action)
        object.__setattr__(self, "decision", normalized_decision)
        object.__setattr__(self, "source", normalized_source)
        object.__setattr__(self, "reason", normalized_reason)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> PolicyObservation:
        """
        Build a policy observation from a mapping payload.
        """
        try:
            action = str(raw["action"])
            decision = str(raw["decision"])
            executed = bool(raw["executed"])
        except KeyError as exc:
            raise ValueError(
                f"Policy observation is missing required field {exc!s}."
            ) from exc

        approved = bool(raw.get("approved", False))
        source_raw = raw.get("source")
        reason_raw = raw.get("reason")

        return cls(
            action=action,
            decision=decision,
            executed=executed,
            approved=approved,
            source=None if source_raw is None else str(source_raw),
            reason=None if reason_raw is None else str(reason_raw),
        )


class PolicyGuardrailCheck(SentinelCheck):
    """
    Built-in check that detects policy-boundary violations.

    Expected context metadata format:
    {
        "policy_observations": [
            {
                "action": "...",
                "decision": "allowed|blocked|denied|review_required",
                "executed": true|false,
                "approved": true|false,
                "source": "...",
                "reason": "..."
            },
            ...
        ]
    }
    """

    def __init__(
        self,
        *,
        blocked_actions: tuple[str, ...] = (),
        high_risk_actions: tuple[str, ...] = (),
    ) -> None:
        self._blocked_actions = _normalize_identifiers(
            blocked_actions,
            label="blocked action",
        )
        self._high_risk_actions = _normalize_identifiers(
            high_risk_actions,
            label="high-risk action",
        )

    @property
    def check_name(self) -> str:
        return "policy_guardrail"

    def evaluate(self, context: SentinelContext) -> tuple[SentinelIssue, ...]:
        """
        Evaluate policy observations and emit guardrail issues.
        """
        raw_observations = context.metadata.get("policy_observations", ())

        try:
            observations = self._coerce_observations(raw_observations)
        except ValueError as exc:
            return (
                SentinelIssue(
                    code="policy.invalid_observation",
                    severity=SentinelSeverity.ERROR,
                    summary="Invalid policy observation payload.",
                    source=self.check_name,
                    details=str(exc),
                ),
            )

        issues: list[SentinelIssue] = []

        for observation in observations:
            if observation.executed and observation.decision in {"blocked", "denied"}:
                issues.append(
                    SentinelIssue(
                        code="policy.execution_after_denial",
                        severity=SentinelSeverity.CRITICAL,
                        summary=(
                            f"Action '{observation.action}' executed after "
                            f"policy denial."
                        ),
                        source=self.check_name,
                        details=_build_details(observation),
                        data=_observation_data(observation),
                    )
                )
                continue

            if observation.executed and observation.action in self._blocked_actions:
                issues.append(
                    SentinelIssue(
                        code="policy.blocked_action_executed",
                        severity=SentinelSeverity.CRITICAL,
                        summary=(
                            f"Blocked action '{observation.action}' was executed."
                        ),
                        source=self.check_name,
                        details=_build_details(observation),
                        data=_observation_data(observation),
                    )
                )
                continue

            if (
                observation.executed
                and observation.action in self._high_risk_actions
                and not observation.approved
            ):
                issues.append(
                    SentinelIssue(
                        code="policy.high_risk_without_approval",
                        severity=SentinelSeverity.WARNING,
                        summary=(
                            f"High-risk action '{observation.action}' executed "
                            f"without approval."
                        ),
                        source=self.check_name,
                        details=_build_details(observation),
                        data=_observation_data(observation),
                    )
                )
                continue

            if (
                observation.decision == "review_required"
                and observation.executed
                and not observation.approved
            ):
                issues.append(
                    SentinelIssue(
                        code="policy.review_required_bypassed",
                        severity=SentinelSeverity.ERROR,
                        summary=(
                            f"Review-required action '{observation.action}' "
                            f"executed without approval."
                        ),
                        source=self.check_name,
                        details=_build_details(observation),
                        data=_observation_data(observation),
                    )
                )

        return tuple(issues)

    def _coerce_observations(
        self,
        raw_observations: Any,
    ) -> tuple[PolicyObservation, ...]:
        if not isinstance(raw_observations, Sequence) or isinstance(
            raw_observations,
            str | bytes | bytearray,
        ):
            raise ValueError(
                "Policy observations must be a sequence of mappings or observations."
            )

        normalized: list[PolicyObservation] = []
        for raw in raw_observations:
            if isinstance(raw, PolicyObservation):
                normalized.append(raw)
            elif isinstance(raw, Mapping):
                normalized.append(PolicyObservation.from_mapping(raw))
            else:
                raise ValueError(
                    "Each policy observation must be a mapping or PolicyObservation."
                )

        return tuple(normalized)


def _observation_data(observation: PolicyObservation) -> dict[str, Any]:
    return {
        "action": observation.action,
        "decision": observation.decision,
        "executed": observation.executed,
        "approved": observation.approved,
        "source": observation.source,
        "reason": observation.reason,
    }


def _build_details(observation: PolicyObservation) -> str:
    parts = [
        f"decision={observation.decision}",
        f"executed={observation.executed}",
        f"approved={observation.approved}",
    ]
    if observation.source is not None:
        parts.append(f"source={observation.source}")
    if observation.reason is not None:
        parts.append(f"reason={observation.reason}")
    return ", ".join(parts) + "."


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError(f"Policy observation {label} must not be empty.")
    return cleaned


def _normalize_identifiers(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = _normalize_identifier(value, label=label)
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None
