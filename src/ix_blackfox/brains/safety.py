from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any
from uuid import uuid4


class SafeguardDisposition(StrEnum):
    """
    Advisory semantic-safety disposition emitted by the safeguard lane.
    """

    ALLOW = auto()
    REVIEW = auto()
    BLOCK = auto()


class SafeguardFindingSeverity(StrEnum):
    """
    Severity tier for one safeguard finding.

    These are advisory semantic-safety levels, not direct governance
    authority. Deterministic policy remains sovereign.
    """

    INFO = auto()
    LOW = auto()
    MODERATE = auto()
    HIGH = auto()
    CRITICAL = auto()


class SafeguardEvidenceKind(StrEnum):
    """
    Canonical evidence reference kinds for safeguard findings.
    """

    TEXT_SPAN = auto()
    LABEL_MATCH = auto()
    POLICY_TAG = auto()
    MODALITY_SIGNAL = auto()
    ATTACHMENT_REFERENCE = auto()
    PROVIDER_MESSAGE = auto()
    MODEL_RATIONALE = auto()
    STRUCTURED_SIGNAL = auto()


@dataclass(frozen=True, slots=True)
class SafeguardEvidenceRef:
    """
    One cited evidence reference attached to a safeguard finding.

    Attributes
    ----------
    kind:
        Canonical evidence-reference kind.
    value:
        Primary normalized evidence value.
    locator:
        Optional stable location reference such as a message id, path,
        field name, or attachment id.
    excerpt:
        Optional short quoted snippet.
    metadata:
        Optional structured supporting metadata.
    """

    kind: SafeguardEvidenceKind
    value: str
    locator: str | None = None
    excerpt: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _normalize_text(self.value, label="value"))
        object.__setattr__(self, "locator", _normalize_optional_locator(self.locator))
        object.__setattr__(self, "excerpt", _normalize_optional_text(self.excerpt))
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(frozen=True, slots=True)
class SafeguardFinding:
    """
    One structured safeguard finding.

    Attributes
    ----------
    finding_id:
        Stable finding identifier.
    code:
        Stable short safeguard finding code.
    severity:
        Advisory severity for the finding.
    summary:
        Human-readable finding summary.
    policy_tags:
        Normalized semantic policy tags attached to the finding.
    evidence:
        Evidence references supporting the finding.
    confidence:
        Confidence score from 0.0 to 1.0.
    uncertainty:
        Uncertainty score from 0.0 to 1.0.
    metadata:
        Optional structured metadata.
    """

    finding_id: str
    code: str
    severity: SafeguardFindingSeverity
    summary: str
    policy_tags: tuple[str, ...] = field(default_factory=tuple)
    evidence: tuple[SafeguardEvidenceRef, ...] = field(default_factory=tuple)
    confidence: float = 0.5
    uncertainty: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        code: str,
        severity: SafeguardFindingSeverity,
        summary: str,
        policy_tags: tuple[str, ...] | None = None,
        evidence: tuple[SafeguardEvidenceRef, ...] | None = None,
        confidence: float = 0.5,
        uncertainty: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> SafeguardFinding:
        """
        Construct a new safeguard finding with a generated identifier.
        """
        return cls(
            finding_id=f"safeguard-finding-{uuid4().hex}",
            code=code,
            severity=severity,
            summary=summary,
            policy_tags=tuple(policy_tags or ()),
            evidence=tuple(evidence or ()),
            confidence=confidence,
            uncertainty=uncertainty,
            metadata=dict(metadata or {}),
        )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "finding_id",
            _normalize_identifier(self.finding_id, label="finding_id"),
        )
        object.__setattr__(self, "code", _normalize_identifier(self.code, label="code"))
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "policy_tags", _normalize_identifiers(self.policy_tags))
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "confidence", _normalize_probability(self.confidence, label="confidence"))
        object.__setattr__(self, "uncertainty", _normalize_probability(self.uncertainty, label="uncertainty"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def requires_review(self) -> bool:
        """
        Return True when the finding is serious enough to recommend review.
        """
        return _severity_rank(self.severity) >= _severity_rank(
            SafeguardFindingSeverity.MODERATE
        )

    @property
    def recommends_block(self) -> bool:
        """
        Return True when the finding is serious enough to recommend block.
        """
        return _severity_rank(self.severity) >= _severity_rank(
            SafeguardFindingSeverity.HIGH
        )


@dataclass(frozen=True, slots=True)
class SafeguardAssessment:
    """
    Structured semantic-safety assessment for one safeguard invocation.

    Attributes
    ----------
    brain_name:
        Stable safeguard brain identifier.
    invocation_id:
        Stable invocation identifier.
    advisory_disposition:
        Advisory semantic-safety disposition.
    findings:
        Structured safeguard findings.
    metadata:
        Optional assessment metadata.
    """

    brain_name: str
    invocation_id: str
    advisory_disposition: SafeguardDisposition
    findings: tuple[SafeguardFinding, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_findings(
        cls,
        *,
        brain_name: str,
        invocation_id: str,
        findings: tuple[SafeguardFinding, ...],
        metadata: dict[str, Any] | None = None,
    ) -> SafeguardAssessment:
        """
        Build an assessment and infer disposition from the findings.
        """
        disposition = _disposition_from_findings(findings)
        return cls(
            brain_name=brain_name,
            invocation_id=invocation_id,
            advisory_disposition=disposition,
            findings=findings,
            metadata=dict(metadata or {}),
        )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "brain_name",
            _normalize_identifier(self.brain_name, label="brain_name"),
        )
        object.__setattr__(
            self,
            "invocation_id",
            _normalize_identifier(self.invocation_id, label="invocation_id"),
        )
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if not self.findings and self.advisory_disposition is not SafeguardDisposition.ALLOW:
            raise ValueError(
                "Assessments without findings must use advisory_disposition=ALLOW."
            )

    @property
    def highest_severity(self) -> SafeguardFindingSeverity | None:
        """
        Return the highest severity across all findings.
        """
        if not self.findings:
            return None
        return max(self.findings, key=lambda finding: _severity_rank(finding.severity)).severity

    def finding_codes(self) -> tuple[str, ...]:
        """
        Return finding codes in declaration order.
        """
        return tuple(finding.code for finding in self.findings)

    def policy_tags(self) -> tuple[str, ...]:
        """
        Return unique policy tags across all findings in stable order.
        """
        collected: list[str] = []
        seen: set[str] = set()

        for finding in self.findings:
            for tag in finding.policy_tags:
                if tag not in seen:
                    collected.append(tag)
                    seen.add(tag)

        return tuple(collected)


def _disposition_from_findings(
    findings: tuple[SafeguardFinding, ...],
) -> SafeguardDisposition:
    if not findings:
        return SafeguardDisposition.ALLOW

    highest = max(findings, key=lambda finding: _severity_rank(finding.severity))
    if highest.recommends_block:
        return SafeguardDisposition.BLOCK
    if highest.requires_review:
        return SafeguardDisposition.REVIEW
    return SafeguardDisposition.ALLOW


def _severity_rank(severity: SafeguardFindingSeverity) -> int:
    order = {
        SafeguardFindingSeverity.INFO: 1,
        SafeguardFindingSeverity.LOW: 2,
        SafeguardFindingSeverity.MODERATE: 3,
        SafeguardFindingSeverity.HIGH: 4,
        SafeguardFindingSeverity.CRITICAL: 5,
    }
    return order[severity]


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_identifiers(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = value.strip().lower().replace(" ", "-")
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _normalize_optional_locator(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().replace("\\", "/")
    return cleaned or None


def _normalize_probability(value: float, *, label: str) -> float:
    normalized = float(value)
    if not 0.0 <= normalized <= 1.0:
        raise ValueError(f"{label} must be between 0.0 and 1.0.")
    return normalized
