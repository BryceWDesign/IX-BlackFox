from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum, auto
from typing import Any, TypeVar

from ix_blackfox.agents.models import AgentKind
from ix_blackfox.operating.models import (
    normalize_identifier,
    normalize_relative_path,
    normalize_sha256,
    normalize_text,
)

WAVE12_ASSURANCE_SCHEMA_VERSION = "wave12.certification_ready_evidence.v1"
WAVE12_MANIFEST_SCHEMA_VERSION = "wave12.assurance_manifest.v1"
WAVE12_REVIEW_SCHEMA_VERSION = "wave12.authority_review.v1"

DEFAULT_PROHIBITED_ASSERTED_TERMS = (
    "certified",
    "certification",
    "formally compliant",
    "compliance achieved",
    "compliant",
    "ato granted",
    "cato granted",
    "fedramp authorized",
    "dod approved",
    "government approved",
    "aws approved",
    "production approved",
    "deployment approved",
    "procurement approved",
    "autonomous approval authority",
)

_EnumT = TypeVar("_EnumT", bound=StrEnum)


class AssuranceEvidenceSource(StrEnum):
    """Origin layer for evidence packaged by Wave 12."""

    WAVE5 = auto()
    WAVE6 = auto()
    WAVE7 = auto()
    WAVE8 = auto()
    WAVE9 = auto()
    WAVE10 = auto()
    WAVE11 = auto()
    WAVE12 = auto()
    EXTERNAL = auto()


class AssuranceEvidenceKind(StrEnum):
    """Evidence families understood by the Wave 12 profile evaluator."""

    POLICY_EVALUATION = auto()
    TEST_RESULT = auto()
    STATIC_ANALYSIS = auto()
    TYPE_CHECK = auto()
    SANDBOX_EVIDENCE = auto()
    REPOSITORY_INTELLIGENCE = auto()
    PROVENANCE = auto()
    AGENT_IDENTITY = auto()
    HUMAN_REVIEW = auto()
    SUPPLY_CHAIN_ATTESTATION = auto()
    SBOM = auto()
    VULNERABILITY_SCAN = auto()
    RISK_ASSESSMENT = auto()
    OTHER = auto()


class EvidenceVerificationState(StrEnum):
    """Verification strength recorded for one evidence artifact."""

    RECORDED = auto()
    INTEGRITY_VERIFIED = auto()
    EXTERNALLY_VERIFIED = auto()

    @property
    def rank(self) -> int:
        return {
            EvidenceVerificationState.RECORDED: 0,
            EvidenceVerificationState.INTEGRITY_VERIFIED: 1,
            EvidenceVerificationState.EXTERNALLY_VERIFIED: 2,
        }[self]

    def satisfies(self, required: EvidenceVerificationState) -> bool:
        return self.rank >= required.rank


class AuthorityReviewDecision(StrEnum):
    """Decision recorded by a reviewer over a Wave 12 manifest subject."""

    APPROVE_FOR_EXTERNAL_ASSESSMENT = auto()
    REQUEST_CHANGES = auto()
    REJECT = auto()
    ADVISORY_ONLY = auto()


class ReviewAuthenticationState(StrEnum):
    """Whether reviewer identity authentication was only recorded or verified."""

    RECORDED = auto()
    VERIFIED = auto()


@dataclass(frozen=True, slots=True)
class AssuranceSubject:
    """Repository revision and scope bound into an assurance package."""

    repository: str
    revision: str
    scope: str
    producer_agent_id: str
    generated_at: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "repository",
            normalize_text(self.repository, label="repository"),
        )
        object.__setattr__(
            self,
            "revision",
            normalize_text(self.revision, label="revision"),
        )
        object.__setattr__(self, "scope", normalize_text(self.scope, label="scope"))
        object.__setattr__(
            self,
            "producer_agent_id",
            normalize_identifier(self.producer_agent_id, label="producer_agent_id"),
        )
        object.__setattr__(
            self,
            "generated_at",
            normalize_timestamp(self.generated_at, label="generated_at"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "repository": self.repository,
            "revision": self.revision,
            "scope": self.scope,
            "producer_agent_id": self.producer_agent_id,
            "generated_at": self.generated_at,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class AssuranceEvidenceArtifact:
    """Content-addressed evidence descriptor stored in a Wave 12 package."""

    artifact_id: str
    source_wave: AssuranceEvidenceSource
    evidence_kind: AssuranceEvidenceKind
    path: str
    sha256: str
    size_bytes: int
    media_type: str
    producer: str
    verification_state: EvidenceVerificationState
    schema_version: str = ""
    required: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "artifact_id",
            normalize_identifier(self.artifact_id, label="artifact_id"),
        )
        normalized_path = normalize_relative_path(self.path)
        if not normalized_path.startswith("evidence/"):
            raise ValueError("Wave 12 evidence paths must be beneath evidence/.")
        object.__setattr__(self, "path", normalized_path)
        object.__setattr__(self, "sha256", normalize_sha256(self.sha256))
        if self.size_bytes < 0:
            raise ValueError("size_bytes must not be negative.")
        object.__setattr__(
            self,
            "media_type",
            normalize_media_type(self.media_type),
        )
        object.__setattr__(
            self,
            "producer",
            normalize_text(self.producer, label="producer"),
        )
        object.__setattr__(
            self,
            "schema_version",
            normalize_optional_text(self.schema_version, label="schema_version"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def integrity_verified(self) -> bool:
        return self.verification_state.satisfies(
            EvidenceVerificationState.INTEGRITY_VERIFIED
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "source_wave": self.source_wave.value,
            "evidence_kind": self.evidence_kind.value,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
            "producer": self.producer,
            "verification_state": self.verification_state.value,
            "integrity_verified": self.integrity_verified,
            "schema_version": self.schema_version,
            "required": self.required,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class AssuranceControl:
    """One evidence requirement in an assurance profile."""

    control_id: str
    framework: str
    reference_id: str
    title: str
    evidence_kinds: tuple[AssuranceEvidenceKind, ...]
    statement: str
    reference_uri: str
    minimum_verification: EvidenceVerificationState = (
        EvidenceVerificationState.INTEGRITY_VERIFIED
    )
    requires_human_review: bool = False
    mandatory: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "control_id",
            normalize_identifier(self.control_id, label="control_id"),
        )
        object.__setattr__(
            self,
            "framework",
            normalize_text(self.framework, label="framework"),
        )
        object.__setattr__(
            self,
            "reference_id",
            normalize_text(self.reference_id, label="reference_id"),
        )
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        evidence_kinds = unique_sorted_enums(self.evidence_kinds)
        if not evidence_kinds:
            raise ValueError("AssuranceControl evidence_kinds must not be empty.")
        object.__setattr__(self, "evidence_kinds", evidence_kinds)
        object.__setattr__(
            self,
            "statement",
            normalize_text(self.statement, label="statement"),
        )
        object.__setattr__(self, "reference_uri", normalize_https_uri(self.reference_uri))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "framework": self.framework,
            "reference_id": self.reference_id,
            "title": self.title,
            "evidence_kinds": [kind.value for kind in self.evidence_kinds],
            "statement": self.statement,
            "reference_uri": self.reference_uri,
            "minimum_verification": self.minimum_verification.value,
            "requires_human_review": self.requires_human_review,
            "mandatory": self.mandatory,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class AssuranceProfile:
    """Versioned control profile evaluated by Wave 12."""

    profile_id: str
    version: str
    title: str
    controls: tuple[AssuranceControl, ...]
    description: str
    claim_boundary: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "profile_id",
            normalize_identifier(self.profile_id, label="profile_id"),
        )
        object.__setattr__(
            self,
            "version",
            normalize_text(self.version, label="version"),
        )
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        controls = tuple(sorted(self.controls, key=lambda item: item.control_id))
        if not controls:
            raise ValueError("AssuranceProfile controls must not be empty.")
        control_ids = [control.control_id for control in controls]
        if len(control_ids) != len(set(control_ids)):
            raise ValueError("AssuranceProfile control_id values must be unique.")
        object.__setattr__(self, "controls", controls)
        object.__setattr__(
            self,
            "description",
            normalize_text(self.description, label="description"),
        )
        object.__setattr__(
            self,
            "claim_boundary",
            normalize_text(self.claim_boundary, label="claim_boundary"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "profile_id": self.profile_id,
            "version": self.version,
            "title": self.title,
            "description": self.description,
            "claim_boundary": self.claim_boundary,
            "controls": [control.to_dict() for control in self.controls],
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class AssuranceClaimSet:
    """Bounded claims and explicit non-claims emitted with a Wave 12 package."""

    asserted_claims: tuple[str, ...]
    non_claims: tuple[str, ...]
    prohibited_asserted_terms: tuple[str, ...] = DEFAULT_PROHIBITED_ASSERTED_TERMS

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "asserted_claims",
            normalize_text_tuple(self.asserted_claims, label="asserted_claims"),
        )
        if not self.asserted_claims:
            raise ValueError("AssuranceClaimSet asserted_claims must not be empty.")
        object.__setattr__(
            self,
            "non_claims",
            normalize_text_tuple(self.non_claims, label="non_claims"),
        )
        if not self.non_claims:
            raise ValueError("AssuranceClaimSet non_claims must not be empty.")
        object.__setattr__(
            self,
            "prohibited_asserted_terms",
            normalize_lower_text_tuple(
                (*self.prohibited_asserted_terms, *DEFAULT_PROHIBITED_ASSERTED_TERMS),
                label="prohibited_asserted_terms",
            ),
        )

    @property
    def prohibited_hits(self) -> tuple[str, ...]:
        hits = {
            term
            for claim in self.asserted_claims
            for term in self.prohibited_asserted_terms
            if term in claim.lower()
        }
        return tuple(sorted(hits))

    def to_dict(self) -> dict[str, Any]:
        return {
            "asserted_claims": list(self.asserted_claims),
            "non_claims": list(self.non_claims),
            "prohibited_asserted_terms": list(self.prohibited_asserted_terms),
            "prohibited_hits": list(self.prohibited_hits),
        }


@dataclass(frozen=True, slots=True)
class AuthorityReview:
    """Reviewer decision bound to a manifest and profile digest."""

    review_id: str
    reviewer_agent_id: str
    reviewer_kind: AgentKind
    decision: AuthorityReviewDecision
    subject_digest: str
    profile_digest: str
    reviewed_at: str
    authentication_state: ReviewAuthenticationState
    verification_artifact_ids: tuple[str, ...] = ()
    notes: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "review_id",
            normalize_identifier(self.review_id, label="review_id"),
        )
        object.__setattr__(
            self,
            "reviewer_agent_id",
            normalize_identifier(self.reviewer_agent_id, label="reviewer_agent_id"),
        )
        object.__setattr__(self, "subject_digest", normalize_sha256(self.subject_digest))
        object.__setattr__(self, "profile_digest", normalize_sha256(self.profile_digest))
        object.__setattr__(
            self,
            "reviewed_at",
            normalize_timestamp(self.reviewed_at, label="reviewed_at"),
        )
        object.__setattr__(
            self,
            "verification_artifact_ids",
            normalize_identifier_tuple(
                self.verification_artifact_ids,
                label="verification_artifact_ids",
            ),
        )
        if (
            self.authentication_state is ReviewAuthenticationState.VERIFIED
            and not self.verification_artifact_ids
        ):
            raise ValueError(
                "Verified authority reviews require verification_artifact_ids."
            )
        object.__setattr__(
            self,
            "notes",
            normalize_optional_text(self.notes, label="notes"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def authoritative_human_approval(self) -> bool:
        return (
            self.reviewer_kind is AgentKind.HUMAN_OPERATOR
            and self.decision is AuthorityReviewDecision.APPROVE_FOR_EXTERNAL_ASSESSMENT
            and self.authentication_state is ReviewAuthenticationState.VERIFIED
        )

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": WAVE12_REVIEW_SCHEMA_VERSION,
            "review_id": self.review_id,
            "reviewer_agent_id": self.reviewer_agent_id,
            "reviewer_kind": self.reviewer_kind.value,
            "decision": self.decision.value,
            "subject_digest": self.subject_digest,
            "profile_digest": self.profile_digest,
            "reviewed_at": self.reviewed_at,
            "authentication_state": self.authentication_state.value,
            "verification_artifact_ids": list(self.verification_artifact_ids),
            "authoritative_human_approval": self.authoritative_human_approval,
            "notes": self.notes,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class AssuranceManifest:
    """Deterministic Wave 12 evidence-package manifest."""

    manifest_id: str
    subject: AssuranceSubject
    profile: AssuranceProfile
    evidence: tuple[AssuranceEvidenceArtifact, ...]
    claims: AssuranceClaimSet
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "manifest_id",
            normalize_identifier(self.manifest_id, label="manifest_id"),
        )
        evidence = tuple(sorted(self.evidence, key=lambda item: item.artifact_id))
        if not evidence:
            raise ValueError("AssuranceManifest evidence must not be empty.")
        artifact_ids = [artifact.artifact_id for artifact in evidence]
        paths = [artifact.path for artifact in evidence]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError("AssuranceManifest artifact_id values must be unique.")
        if len(paths) != len(set(paths)):
            raise ValueError("AssuranceManifest evidence paths must be unique.")
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def evidence_by_id(self) -> Mapping[str, AssuranceEvidenceArtifact]:
        return {artifact.artifact_id: artifact for artifact in self.evidence}

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": WAVE12_MANIFEST_SCHEMA_VERSION,
            "wave_schema_version": WAVE12_ASSURANCE_SCHEMA_VERSION,
            "manifest_id": self.manifest_id,
            "subject": self.subject.to_dict(),
            "profile": self.profile.to_dict(),
            "evidence": [artifact.to_dict() for artifact in self.evidence],
            "claims": self.claims.to_dict(),
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["manifest_digest"] = self.digest
        return payload


def default_wave12_claims() -> AssuranceClaimSet:
    """Return the strongest claims the offline Wave 12 package may make."""

    return AssuranceClaimSet(
        asserted_claims=(
            "The listed evidence files are content-addressed and independently re-verifiable for the bound repository revision.",
            "The package exposes missing evidence, review state, and unsupported assurance claims through deterministic findings.",
        ),
        non_claims=(
            "The package does not grant certification, accreditation, compliance approval, ATO, cATO, procurement approval, deployment approval, or production authority.",
            "Recorded evidence integrity does not prove that the underlying software, model, workflow, or organization is correct, safe, secure, or compliant.",
            "A model, tool, CI runner, or system service cannot satisfy the authoritative human-review requirement.",
        ),
    )


def digest_payload(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def normalize_optional_text(value: str, *, label: str) -> str:
    if not value.strip():
        return ""
    return normalize_text(value, label=label)


def normalize_text_tuple(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    normalized = {normalize_text(value, label=label) for value in values}
    return tuple(sorted(normalized))


def normalize_lower_text_tuple(
    values: Sequence[str],
    *,
    label: str,
) -> tuple[str, ...]:
    return tuple(sorted({normalize_text(value, label=label).lower() for value in values}))


def normalize_identifier_tuple(
    values: Sequence[str],
    *,
    label: str,
) -> tuple[str, ...]:
    return tuple(sorted({normalize_identifier(value, label=label) for value in values}))


def normalize_media_type(value: str) -> str:
    cleaned = value.strip().lower()
    if "/" not in cleaned or any(char.isspace() for char in cleaned):
        raise ValueError("media_type must be a normalized type/subtype value.")
    return cleaned


def normalize_https_uri(value: str) -> str:
    cleaned = value.strip()
    if not cleaned.startswith("https://"):
        raise ValueError("reference_uri must use https://.")
    return cleaned


def normalize_timestamp(value: str, *, label: str) -> str:
    cleaned = value.strip().replace("Z", "+00:00")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone offset.")
    return parsed.isoformat()


def unique_sorted_enums(values: Sequence[_EnumT]) -> tuple[_EnumT, ...]:
    by_value = {value.value: value for value in values}
    return tuple(by_value[key] for key in sorted(by_value))
