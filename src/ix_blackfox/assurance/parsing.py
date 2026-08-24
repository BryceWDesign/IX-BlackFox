from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ix_blackfox.agents.models import AgentKind
from ix_blackfox.assurance.models import (
    AssuranceClaimSet,
    AssuranceControl,
    AssuranceEvidenceArtifact,
    AssuranceEvidenceKind,
    AssuranceEvidenceSource,
    AssuranceManifest,
    AssuranceProfile,
    AssuranceSubject,
    AuthorityReview,
    AuthorityReviewDecision,
    EvidenceVerificationState,
    ReviewAuthenticationState,
)


def parse_assurance_manifest(payload: Mapping[str, Any]) -> AssuranceManifest:
    """Parse and canonicalize a serialized Wave 12 manifest.

    Equality with ``to_dict`` is intentional. It rejects missing, extra,
    reordered-set, derived-field, and weakened-policy representations rather
    than silently accepting a lossy interpretation of the signed subject.
    """

    subject_payload = _mapping_field(payload, "subject")
    subject = AssuranceSubject(
        repository=_string_field(subject_payload, "repository"),
        revision=_string_field(subject_payload, "revision"),
        scope=_string_field(subject_payload, "scope"),
        producer_agent_id=_string_field(subject_payload, "producer_agent_id"),
        generated_at=_string_field(subject_payload, "generated_at"),
        metadata=_mapping_field(subject_payload, "metadata"),
    )
    _string_field(subject_payload, "digest")

    profile_payload = _mapping_field(payload, "profile")
    controls = tuple(
        _parse_control(item, index)
        for index, item in enumerate(_object_list_field(profile_payload, "controls"))
    )
    profile = AssuranceProfile(
        profile_id=_string_field(profile_payload, "profile_id"),
        version=_string_field(profile_payload, "version"),
        title=_string_field(profile_payload, "title"),
        controls=controls,
        description=_string_field(profile_payload, "description"),
        claim_boundary=_string_field(profile_payload, "claim_boundary"),
        metadata=_mapping_field(profile_payload, "metadata"),
    )
    _string_field(profile_payload, "digest")

    evidence = tuple(
        _parse_evidence(item, index)
        for index, item in enumerate(_object_list_field(payload, "evidence"))
    )
    claims_payload = _mapping_field(payload, "claims")
    claims = AssuranceClaimSet(
        asserted_claims=_string_tuple_field(claims_payload, "asserted_claims"),
        non_claims=_string_tuple_field(claims_payload, "non_claims"),
        prohibited_asserted_terms=_string_tuple_field(
            claims_payload,
            "prohibited_asserted_terms",
        ),
    )
    _string_tuple_field(claims_payload, "prohibited_hits")

    _string_field(payload, "schema_version")
    _string_field(payload, "wave_schema_version")
    _string_field(payload, "manifest_digest")
    manifest = AssuranceManifest(
        manifest_id=_string_field(payload, "manifest_id"),
        subject=subject,
        profile=profile,
        evidence=evidence,
        claims=claims,
        metadata=_mapping_field(payload, "metadata"),
    )
    if manifest.to_dict() != dict(payload):
        raise ValueError(
            "Serialized manifest is not the canonical Wave 12 manifest form."
        )
    return manifest


def parse_authority_reviews(
    payload: Mapping[str, Any],
) -> tuple[AuthorityReview, ...]:
    """Parse canonical authority reviews from a serialized review set."""

    reviews = tuple(
        _parse_authority_review(item, index)
        for index, item in enumerate(_object_list_field(payload, "reviews"))
    )
    review_ids = [review.review_id for review in reviews]
    if len(review_ids) != len(set(review_ids)):
        raise ValueError("Serialized authority review ids must be unique.")
    return tuple(sorted(reviews, key=lambda review: review.review_id))


def _parse_control(payload: Mapping[str, Any], index: int) -> AssuranceControl:
    label = f"profile.controls[{index}]"
    return AssuranceControl(
        control_id=_string_field(payload, "control_id", parent=label),
        framework=_string_field(payload, "framework", parent=label),
        reference_id=_string_field(payload, "reference_id", parent=label),
        title=_string_field(payload, "title", parent=label),
        evidence_kinds=tuple(
            AssuranceEvidenceKind(value)
            for value in _string_tuple_field(
                payload,
                "evidence_kinds",
                parent=label,
            )
        ),
        statement=_string_field(payload, "statement", parent=label),
        reference_uri=_string_field(payload, "reference_uri", parent=label),
        minimum_verification=EvidenceVerificationState(
            _string_field(payload, "minimum_verification", parent=label)
        ),
        requires_human_review=_bool_field(
            payload,
            "requires_human_review",
            parent=label,
        ),
        mandatory=_bool_field(payload, "mandatory", parent=label),
        metadata=_mapping_field(payload, "metadata", parent=label),
    )


def _parse_evidence(
    payload: Mapping[str, Any],
    index: int,
) -> AssuranceEvidenceArtifact:
    label = f"evidence[{index}]"
    _bool_field(payload, "integrity_verified", parent=label)
    return AssuranceEvidenceArtifact(
        artifact_id=_string_field(payload, "artifact_id", parent=label),
        source_wave=AssuranceEvidenceSource(
            _string_field(payload, "source_wave", parent=label)
        ),
        evidence_kind=AssuranceEvidenceKind(
            _string_field(payload, "evidence_kind", parent=label)
        ),
        path=_string_field(payload, "path", parent=label),
        sha256=_string_field(payload, "sha256", parent=label),
        size_bytes=_integer_field(payload, "size_bytes", parent=label),
        media_type=_string_field(payload, "media_type", parent=label),
        producer=_string_field(payload, "producer", parent=label),
        verification_state=EvidenceVerificationState(
            _string_field(payload, "verification_state", parent=label)
        ),
        schema_version=_string_field(payload, "schema_version", parent=label),
        required=_bool_field(payload, "required", parent=label),
        metadata=_mapping_field(payload, "metadata", parent=label),
    )


def _parse_authority_review(
    payload: Mapping[str, Any],
    index: int,
) -> AuthorityReview:
    label = f"reviews[{index}]"
    _string_field(payload, "schema_version", parent=label)
    _bool_field(payload, "authoritative_human_approval", parent=label)
    _string_field(payload, "digest", parent=label)
    review = AuthorityReview(
        review_id=_string_field(payload, "review_id", parent=label),
        reviewer_agent_id=_string_field(
            payload,
            "reviewer_agent_id",
            parent=label,
        ),
        reviewer_kind=AgentKind(
            _string_field(payload, "reviewer_kind", parent=label)
        ),
        decision=AuthorityReviewDecision(
            _string_field(payload, "decision", parent=label)
        ),
        subject_digest=_string_field(payload, "subject_digest", parent=label),
        profile_digest=_string_field(payload, "profile_digest", parent=label),
        reviewed_at=_string_field(payload, "reviewed_at", parent=label),
        authentication_state=ReviewAuthenticationState(
            _string_field(payload, "authentication_state", parent=label)
        ),
        verification_artifact_ids=_string_tuple_field(
            payload,
            "verification_artifact_ids",
            parent=label,
        ),
        notes=_string_field(payload, "notes", parent=label),
        metadata=_mapping_field(payload, "metadata", parent=label),
    )
    if review.to_dict() != dict(payload):
        raise ValueError(f"Serialized {label} is not canonical.")
    return review


def _mapping_field(
    payload: Mapping[str, Any],
    name: str,
    *,
    parent: str = "document",
) -> Mapping[str, Any]:
    value = payload.get(name)
    if not isinstance(value, dict):
        raise ValueError(f"{parent}.{name} must be an object.")
    return value


def _object_list_field(
    payload: Mapping[str, Any],
    name: str,
    *,
    parent: str = "document",
) -> tuple[Mapping[str, Any], ...]:
    value = payload.get(name)
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError(f"{parent}.{name} must be a list of objects.")
    return tuple(value)


def _string_field(
    payload: Mapping[str, Any],
    name: str,
    *,
    parent: str = "document",
) -> str:
    value = payload.get(name)
    if not isinstance(value, str):
        raise ValueError(f"{parent}.{name} must be a string.")
    return value


def _string_tuple_field(
    payload: Mapping[str, Any],
    name: str,
    *,
    parent: str = "document",
) -> tuple[str, ...]:
    value = payload.get(name)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{parent}.{name} must be a list of strings.")
    return tuple(value)


def _bool_field(
    payload: Mapping[str, Any],
    name: str,
    *,
    parent: str = "document",
) -> bool:
    value = payload.get(name)
    if type(value) is not bool:
        raise ValueError(f"{parent}.{name} must be a boolean.")
    return value


def _integer_field(
    payload: Mapping[str, Any],
    name: str,
    *,
    parent: str = "document",
) -> int:
    value = payload.get(name)
    if type(value) is not int:
        raise ValueError(f"{parent}.{name} must be an integer.")
    return value
