from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ix_blackfox.review_board.models import (
    EvidenceChallenge,
    EvidenceChallengeStatus,
    HumanReview,
    HumanReviewDecision,
    MachineAdvisory,
    MachineRecommendation,
    ReviewAuthenticationState,
    ReviewBoardEvaluation,
    ReviewBoardFinding,
    ReviewBoardFindingCode,
    ReviewBoardPolicy,
    ReviewBoardStatus,
    ReviewBoardSubject,
    ReviewRole,
)
from ix_blackfox.review_board.package import build_review_case


def parse_review_case(
    payload: Mapping[str, Any],
) -> tuple[ReviewBoardSubject, ReviewBoardPolicy]:
    """Parse the canonical Wave 13 subject/policy case envelope."""

    subject = parse_review_board_subject(_mapping_field(payload, "subject"))
    policy = parse_review_board_policy(_mapping_field(payload, "policy"))
    expected = build_review_case(subject, policy)
    if expected != dict(payload):
        raise ValueError("Serialized review case is not canonical.")
    return subject, policy


def parse_review_board_subject(payload: Mapping[str, Any]) -> ReviewBoardSubject:
    """Parse and canonicalize a serialized Wave 13 subject."""

    subject = ReviewBoardSubject(
        repository=_string_field(payload, "repository"),
        revision=_string_field(payload, "revision"),
        scope=_string_field(payload, "scope"),
        producer_agent_id=_string_field(payload, "producer_agent_id"),
        wave12_archive_sha256=_string_field(payload, "wave12_archive_sha256"),
        wave12_manifest_digest=_string_field(payload, "wave12_manifest_digest"),
        wave12_profile_digest=_string_field(payload, "wave12_profile_digest"),
        admitted_at=_string_field(payload, "admitted_at"),
        metadata=_mapping_field(payload, "metadata"),
    )
    _string_field(payload, "schema_version")
    _string_field(payload, "digest")
    if subject.to_dict() != dict(payload):
        raise ValueError("Serialized review-board subject is not canonical.")
    return subject


def parse_review_board_policy(payload: Mapping[str, Any]) -> ReviewBoardPolicy:
    """Parse and canonicalize a serialized Wave 13 policy."""

    policy = ReviewBoardPolicy(
        policy_id=_string_field(payload, "policy_id"),
        version=_string_field(payload, "version"),
        supported_roles=tuple(
            ReviewRole(value)
            for value in _string_tuple_field(payload, "supported_roles")
        ),
        required_roles=tuple(
            ReviewRole(value)
            for value in _string_tuple_field(payload, "required_roles")
        ),
        minimum_human_approvals=_integer_field(payload, "minimum_human_approvals"),
        require_distinct_reviewers=_bool_field(payload, "require_distinct_reviewers"),
        require_each_required_role=_bool_field(payload, "require_each_required_role"),
        require_external_identity_verification=_bool_field(
            payload,
            "require_external_identity_verification",
        ),
        block_on_authenticated_reject=_bool_field(
            payload,
            "block_on_authenticated_reject",
        ),
        block_on_authenticated_request_changes=_bool_field(
            payload,
            "block_on_authenticated_request_changes",
        ),
        block_on_open_challenge=_bool_field(payload, "block_on_open_challenge"),
        prevent_subject_producer_self_approval=_bool_field(
            payload,
            "prevent_subject_producer_self_approval",
        ),
        metadata=_mapping_field(payload, "metadata"),
    )
    _string_field(payload, "schema_version")
    _string_field(payload, "digest")
    if policy.to_dict() != dict(payload):
        raise ValueError("Serialized review-board policy is not canonical.")
    return policy


def parse_machine_advisories(payload: Mapping[str, Any]) -> tuple[MachineAdvisory, ...]:
    """Parse canonical machine advisories from a serialized advisory set."""

    advisories = tuple(
        _parse_machine_advisory(item, index)
        for index, item in enumerate(_object_list_field(payload, "advisories"))
    )
    _require_unique([item.advisory_id for item in advisories], "machine advisory")
    return tuple(sorted(advisories, key=lambda item: item.advisory_id))


def parse_human_reviews(payload: Mapping[str, Any]) -> tuple[HumanReview, ...]:
    """Parse canonical human reviews from a serialized review set."""

    reviews = tuple(
        _parse_human_review(item, index)
        for index, item in enumerate(_object_list_field(payload, "reviews"))
    )
    _require_unique([item.review_id for item in reviews], "human review")
    return tuple(sorted(reviews, key=lambda item: item.review_id))


def parse_evidence_challenges(
    payload: Mapping[str, Any],
) -> tuple[EvidenceChallenge, ...]:
    """Parse canonical evidence challenges from a serialized challenge set."""

    challenges = tuple(
        _parse_evidence_challenge(item, index)
        for index, item in enumerate(_object_list_field(payload, "challenges"))
    )
    _require_unique([item.challenge_id for item in challenges], "evidence challenge")
    return tuple(sorted(challenges, key=lambda item: item.challenge_id))


def parse_review_board_evaluation(
    payload: Mapping[str, Any],
) -> ReviewBoardEvaluation:
    """Parse and canonicalize a serialized review-board evaluation."""

    findings = tuple(
        _parse_finding(item, index)
        for index, item in enumerate(_object_list_field(payload, "findings"))
    )
    evaluation = ReviewBoardEvaluation(
        subject_digest=_string_field(payload, "subject_digest"),
        policy_digest=_string_field(payload, "policy_digest"),
        status=ReviewBoardStatus(_string_field(payload, "status")),
        findings=findings,
        qualifying_review_ids=_string_tuple_field(payload, "qualifying_review_ids"),
        qualifying_reviewer_ids=_string_tuple_field(
            payload,
            "qualifying_reviewer_ids",
        ),
        approved_roles=tuple(
            ReviewRole(value)
            for value in _string_tuple_field(payload, "approved_roles")
        ),
        missing_required_roles=tuple(
            ReviewRole(value)
            for value in _string_tuple_field(payload, "missing_required_roles")
        ),
        machine_advisory_count=_integer_field(payload, "machine_advisory_count"),
        human_review_count=_integer_field(payload, "human_review_count"),
        external_verification_count=_integer_field(
            payload,
            "external_verification_count",
        ),
        external_verification_context_digest=_string_field(
            payload,
            "external_verification_context_digest",
        ),
        open_challenge_count=_integer_field(payload, "open_challenge_count"),
        metadata=_mapping_field(payload, "metadata"),
    )
    _string_field(payload, "schema_version")
    _bool_field(payload, "approved_for_next_gate")
    _integer_field(payload, "blocking_finding_count")
    _string_field(payload, "scope_note")
    _string_field(payload, "digest")
    if evaluation.to_dict() != dict(payload):
        raise ValueError("Serialized review-board evaluation is not canonical.")
    return evaluation


def _parse_machine_advisory(
    payload: Mapping[str, Any],
    index: int,
) -> MachineAdvisory:
    label = f"advisories[{index}]"
    advisory = MachineAdvisory(
        advisory_id=_string_field(payload, "advisory_id", parent=label),
        producer_agent_id=_string_field(
            payload,
            "producer_agent_id",
            parent=label,
        ),
        recommendation=MachineRecommendation(
            _string_field(payload, "recommendation", parent=label)
        ),
        subject_digest=_string_field(payload, "subject_digest", parent=label),
        policy_digest=_string_field(payload, "policy_digest", parent=label),
        produced_at=_string_field(payload, "produced_at", parent=label),
        summary=_string_field(payload, "summary", parent=label),
        findings=_string_tuple_field(payload, "findings", parent=label),
        evidence_refs=_string_tuple_field(payload, "evidence_refs", parent=label),
        metadata=_mapping_field(payload, "metadata", parent=label),
    )
    _string_field(payload, "schema_version", parent=label)
    _bool_field(payload, "authoritative", parent=label)
    _integer_field(payload, "vote_weight", parent=label)
    _string_field(payload, "digest", parent=label)
    if advisory.to_dict() != dict(payload):
        raise ValueError(f"Serialized {label} is not canonical.")
    return advisory


def _parse_human_review(payload: Mapping[str, Any], index: int) -> HumanReview:
    label = f"reviews[{index}]"
    review = HumanReview(
        review_id=_string_field(payload, "review_id", parent=label),
        reviewer_id=_string_field(payload, "reviewer_id", parent=label),
        role=ReviewRole(_string_field(payload, "role", parent=label)),
        decision=HumanReviewDecision(
            _string_field(payload, "decision", parent=label)
        ),
        subject_digest=_string_field(payload, "subject_digest", parent=label),
        policy_digest=_string_field(payload, "policy_digest", parent=label),
        reviewed_at=_string_field(payload, "reviewed_at", parent=label),
        authentication_state=ReviewAuthenticationState(
            _string_field(payload, "authentication_state", parent=label)
        ),
        rationale=_string_field(payload, "rationale", parent=label),
        identity_verification_ref=_string_field(
            payload,
            "identity_verification_ref",
            parent=label,
        ),
        identity_verification_sha256=_string_field(
            payload,
            "identity_verification_sha256",
            parent=label,
        ),
        authority_verification_ref=_string_field(
            payload,
            "authority_verification_ref",
            parent=label,
        ),
        authority_verification_sha256=_string_field(
            payload,
            "authority_verification_sha256",
            parent=label,
        ),
        conflict_declared=_bool_field(payload, "conflict_declared", parent=label),
        recused=_bool_field(payload, "recused", parent=label),
        evidence_refs=_string_tuple_field(payload, "evidence_refs", parent=label),
        metadata=_mapping_field(payload, "metadata", parent=label),
    )
    _string_field(payload, "schema_version", parent=label)
    _string_field(payload, "digest", parent=label)
    if review.to_dict() != dict(payload):
        raise ValueError(f"Serialized {label} is not canonical.")
    return review


def _parse_evidence_challenge(
    payload: Mapping[str, Any],
    index: int,
) -> EvidenceChallenge:
    label = f"challenges[{index}]"
    challenge = EvidenceChallenge(
        challenge_id=_string_field(payload, "challenge_id", parent=label),
        raised_by=_string_field(payload, "raised_by", parent=label),
        role=ReviewRole(_string_field(payload, "role", parent=label)),
        subject_digest=_string_field(payload, "subject_digest", parent=label),
        raised_at=_string_field(payload, "raised_at", parent=label),
        status=EvidenceChallengeStatus(
            _string_field(payload, "status", parent=label)
        ),
        summary=_string_field(payload, "summary", parent=label),
        evidence_refs=_string_tuple_field(payload, "evidence_refs", parent=label),
        resolution_note=_string_field(payload, "resolution_note", parent=label),
        metadata=_mapping_field(payload, "metadata", parent=label),
    )
    _string_field(payload, "schema_version", parent=label)
    _string_field(payload, "digest", parent=label)
    if challenge.to_dict() != dict(payload):
        raise ValueError(f"Serialized {label} is not canonical.")
    return challenge


def _parse_finding(payload: Mapping[str, Any], index: int) -> ReviewBoardFinding:
    label = f"findings[{index}]"
    role_value = _string_field(payload, "role", parent=label)
    finding = ReviewBoardFinding(
        code=ReviewBoardFindingCode(_string_field(payload, "code", parent=label)),
        summary=_string_field(payload, "summary", parent=label),
        blocking=_bool_field(payload, "blocking", parent=label),
        role=ReviewRole(role_value) if role_value else None,
        object_id=_string_field(payload, "object_id", parent=label),
        metadata=_mapping_field(payload, "metadata", parent=label),
    )
    if finding.to_dict() != dict(payload):
        raise ValueError(f"Serialized {label} is not canonical.")
    return finding


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


def _require_unique(values: list[str], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"Serialized {label} ids must be unique.")
