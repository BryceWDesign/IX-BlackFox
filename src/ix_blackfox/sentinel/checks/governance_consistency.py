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
class GovernanceObservation:
    """
    One normalized governance observation for consistency analysis.

    Attributes
    ----------
    action:
        Logical governed action name under review.
    decision:
        Governance decision such as allow, require_review, or block.
    executed:
        Whether the governed action actually executed.
    approval_required:
        Whether the action was marked as requiring approval.
    approval_satisfied:
        Whether approval was actually satisfied before execution.
    source:
        Optional source label for diagnostics.
    reason:
        Optional human-readable governance reason.
    """

    action: str
    decision: str
    executed: bool
    approval_required: bool = False
    approval_satisfied: bool = False
    source: str | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "action",
            _normalize_identifier(self.action, label="action"),
        )
        object.__setattr__(
            self,
            "decision",
            _normalize_identifier(self.decision, label="decision"),
        )
        object.__setattr__(self, "source", _normalize_optional_text(self.source))
        object.__setattr__(self, "reason", _normalize_optional_text(self.reason))

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> GovernanceObservation:
        """
        Build a governance observation from a mapping payload.
        """
        try:
            action = str(raw["action"])
            decision = str(raw["decision"])
            executed = bool(raw["executed"])
        except KeyError as exc:
            raise ValueError(
                f"Governance observation is missing required field {exc!s}."
            ) from exc

        return cls(
            action=action,
            decision=decision,
            executed=executed,
            approval_required=bool(raw.get("approval_required", False)),
            approval_satisfied=bool(raw.get("approval_satisfied", False)),
            source=None if raw.get("source") is None else str(raw.get("source")),
            reason=None if raw.get("reason") is None else str(raw.get("reason")),
        )


class GovernanceConsistencyCheck(SentinelCheck):
    """
    Built-in check that detects governance decision inconsistencies.

    Expected context metadata format:
    {
        "governance_observations": [
            {
                "action": "...",
                "decision": "allow|require_review|block|blocked|denied",
                "executed": true|false,
                "approval_required": true|false,
                "approval_satisfied": true|false,
                "source": "...",
                "reason": "..."
            },
            ...
        ]
    }
    """

    @property
    def check_name(self) -> str:
        return "governance_consistency"

    def evaluate(self, context: SentinelContext) -> tuple[SentinelIssue, ...]:
        """
        Evaluate governance observations and emit consistency issues.
        """
        raw_observations = context.metadata.get("governance_observations", ())

        try:
            observations = self._coerce_observations(raw_observations)
        except ValueError as exc:
            return (
                SentinelIssue(
                    code="governance.invalid_observation",
                    severity=SentinelSeverity.ERROR,
                    summary="Invalid governance observation payload.",
                    source=self.check_name,
                    details=str(exc),
                ),
            )

        issues: list[SentinelIssue] = []

        for observation in observations:
            if observation.executed and observation.decision in {
                "block",
                "blocked",
                "denied",
            }:
                issues.append(
                    SentinelIssue(
                        code="governance.blocked_execution",
                        severity=SentinelSeverity.CRITICAL,
                        summary=(
                            f"Governed action '{observation.action}' executed "
                            "despite a blocking decision."
                        ),
                        source=self.check_name,
                        details=_build_details(observation),
                        data=_observation_data(observation),
                    )
                )
                continue

            if (
                observation.executed
                and observation.decision == "require_review"
                and not observation.approval_satisfied
            ):
                issues.append(
                    SentinelIssue(
                        code="governance.review_gate_bypassed",
                        severity=SentinelSeverity.ERROR,
                        summary=(
                            f"Review-gated action '{observation.action}' executed "
                            "without satisfied approval."
                        ),
                        source=self.check_name,
                        details=_build_details(observation),
                        data=_observation_data(observation),
                    )
                )
                continue

            if (
                observation.decision == "require_review"
                and not observation.approval_required
            ):
                issues.append(
                    SentinelIssue(
                        code="governance.review_flag_missing",
                        severity=SentinelSeverity.WARNING,
                        summary=(
                            f"Governed action '{observation.action}' requires review "
                            "but was not marked as approval-required."
                        ),
                        source=self.check_name,
                        details=_build_details(observation),
                        data=_observation_data(observation),
                    )
                )
                continue

            if observation.decision == "allow" and observation.approval_required:
                issues.append(
                    SentinelIssue(
                        code="governance.approval_state_inconsistent",
                        severity=SentinelSeverity.WARNING,
                        summary=(
                            f"Governed action '{observation.action}' was allowed "
                            "while also marked approval-required."
                        ),
                        source=self.check_name,
                        details=_build_details(observation),
                        data=_observation_data(observation),
                    )
                )
                continue

            if observation.approval_satisfied and not observation.approval_required:
                issues.append(
                    SentinelIssue(
                        code="governance.unexpected_approval_state",
                        severity=SentinelSeverity.WARNING,
                        summary=(
                            f"Governed action '{observation.action}' reported "
                            "satisfied approval without requiring approval."
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
    ) -> tuple[GovernanceObservation, ...]:
        if not isinstance(raw_observations, Sequence) or isinstance(
            raw_observations,
            str | bytes | bytearray,
        ):
            raise ValueError(
                "Governance observations must be a sequence of mappings or observations."
            )

        normalized: list[GovernanceObservation] = []
        for raw in raw_observations:
            if isinstance(raw, GovernanceObservation):
                normalized.append(raw)
            elif isinstance(raw, Mapping):
                normalized.append(GovernanceObservation.from_mapping(raw))
            else:
                raise ValueError(
                    "Each governance observation must be a mapping or GovernanceObservation."
                )

        return tuple(normalized)


def _observation_data(observation: GovernanceObservation) -> dict[str, Any]:
    return {
        "action": observation.action,
        "decision": observation.decision,
        "executed": observation.executed,
        "approval_required": observation.approval_required,
        "approval_satisfied": observation.approval_satisfied,
        "source": observation.source,
        "reason": observation.reason,
    }


def _build_details(observation: GovernanceObservation) -> str:
    parts = [
        f"decision={observation.decision}",
        f"executed={observation.executed}",
        f"approval_required={observation.approval_required}",
        f"approval_satisfied={observation.approval_satisfied}",
    ]
    if observation.source is not None:
        parts.append(f"source={observation.source}")
    if observation.reason is not None:
        parts.append(f"reason={observation.reason}")
    return ", ".join(parts)


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError(f"Governance {label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None
