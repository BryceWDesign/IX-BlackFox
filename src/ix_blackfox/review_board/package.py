from __future__ import annotations

import hashlib
import stat
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ix_blackfox.assurance.package import canonical_json_bytes
from ix_blackfox.operating.models import digest_payload
from ix_blackfox.review_board.admission import admit_wave12_package
from ix_blackfox.review_board.models import (
    EvidenceChallenge,
    ExternalHumanReviewVerification,
    HumanReview,
    MachineAdvisory,
    ReviewBoardEvaluation,
    ReviewBoardPolicy,
    ReviewBoardSubject,
)
from ix_blackfox.review_board.policy import evaluate_review_board

WAVE13_CASE_SCHEMA_VERSION = "wave13.review_case.v1"
WAVE13_ADVISORY_SET_SCHEMA_VERSION = "wave13.machine_advisory_set.v1"
WAVE13_HUMAN_REVIEW_SET_SCHEMA_VERSION = "wave13.human_review_set.v1"
WAVE13_CHALLENGE_SET_SCHEMA_VERSION = "wave13.evidence_challenge_set.v1"
WAVE13_LEDGER_SCHEMA_VERSION = "wave13.review_ledger.v1"
WAVE13_BUNDLE_INDEX_SCHEMA_VERSION = "wave13.review_board_bundle_index.v1"

UPSTREAM_WAVE12_ENTRY = "upstream/wave12-certification-ready-evidence.zip"
_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


@dataclass(frozen=True, slots=True)
class ReviewBoardPackageBuildResult:
    """Digests and disposition produced by a deterministic Wave 13 package build."""

    output_path: str
    archive_sha256: str
    archive_size_bytes: int
    subject_digest: str
    policy_digest: str
    evaluation_digest: str
    ledger_digest: str
    bundle_index_digest: str
    status: str
    entry_count: int
    evaluation: ReviewBoardEvaluation
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "output_path": self.output_path,
            "archive_sha256": self.archive_sha256,
            "archive_size_bytes": self.archive_size_bytes,
            "subject_digest": self.subject_digest,
            "policy_digest": self.policy_digest,
            "evaluation_digest": self.evaluation_digest,
            "ledger_digest": self.ledger_digest,
            "bundle_index_digest": self.bundle_index_digest,
            "status": self.status,
            "entry_count": self.entry_count,
            "external_verification_count": self.evaluation.external_verification_count,
            "external_verification_context_digest": (
                self.evaluation.external_verification_context_digest
            ),
            "metadata": dict(self.metadata),
            "scope_note": (
                "The package records and verifies review-board evidence. Its status is "
                "not deployment, production, certification, procurement, or operational authority."
            ),
        }


def build_review_board_package(
    *,
    output_path: Path,
    wave12_package_path: Path,
    subject: ReviewBoardSubject,
    policy: ReviewBoardPolicy,
    machine_advisories: Sequence[MachineAdvisory] = (),
    human_reviews: Sequence[HumanReview] = (),
    external_verifications: Sequence[ExternalHumanReviewVerification] = (),
    challenges: Sequence[EvidenceChallenge] = (),
    metadata: Mapping[str, Any] | None = None,
) -> ReviewBoardPackageBuildResult:
    """Build a deterministic Wave 13 review package around a verified Wave 12 archive."""

    admitted = admit_wave12_package(
        wave12_package_path,
        admitted_at=subject.admitted_at,
    )
    if admitted.subject != subject:
        raise ValueError(
            "Wave 13 subject does not exactly match the independently admitted Wave 12 package."
        )

    advisories = tuple(sorted(machine_advisories, key=lambda item: item.advisory_id))
    reviews = tuple(sorted(human_reviews, key=lambda item: item.review_id))
    verifications = tuple(
        sorted(external_verifications, key=lambda item: item.review_id)
    )
    normalized_challenges = tuple(sorted(challenges, key=lambda item: item.challenge_id))
    evaluation = evaluate_review_board(
        subject=subject,
        policy=policy,
        machine_advisories=advisories,
        human_reviews=reviews,
        external_verifications=verifications,
        challenges=normalized_challenges,
        metadata={"producer": "ix-blackfox-wave13-policy-engine"},
    )

    entries: dict[str, bytes] = {
        "review-case.json": canonical_json_bytes(build_review_case(subject, policy)),
        "machine-advisories.json": canonical_json_bytes(
            build_machine_advisory_set(subject, policy, advisories)
        ),
        "human-reviews.json": canonical_json_bytes(
            build_human_review_set(subject, policy, reviews)
        ),
        "evidence-challenges.json": canonical_json_bytes(
            build_challenge_set(subject, normalized_challenges)
        ),
        "board-evaluation.json": canonical_json_bytes(evaluation.to_dict()),
        UPSTREAM_WAVE12_ENTRY: wave12_package_path.read_bytes(),
    }
    ledger = build_review_ledger(
        subject=subject,
        policy=policy,
        advisories=advisories,
        reviews=reviews,
        challenges=normalized_challenges,
        evaluation=evaluation,
    )
    entries["review-ledger.json"] = canonical_json_bytes(ledger)
    bundle_index = build_review_bundle_index(
        subject=subject,
        policy=policy,
        evaluation=evaluation,
        ledger=ledger,
        entries=entries,
        metadata=metadata,
    )
    entries["bundle-index.json"] = canonical_json_bytes(bundle_index)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.is_symlink():
        raise ValueError("Review-board package output must not be a symlink.")
    with zipfile.ZipFile(
        output_path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for name in sorted(entries):
            archive.writestr(_zip_info(name), entries[name])

    archive_bytes = output_path.read_bytes()
    return ReviewBoardPackageBuildResult(
        output_path=str(output_path),
        archive_sha256=hashlib.sha256(archive_bytes).hexdigest(),
        archive_size_bytes=len(archive_bytes),
        subject_digest=subject.digest,
        policy_digest=policy.digest,
        evaluation_digest=evaluation.digest,
        ledger_digest=str(ledger["digest"]),
        bundle_index_digest=str(bundle_index["bundle_index_digest"]),
        status=evaluation.status.value,
        entry_count=len(entries),
        evaluation=evaluation,
        metadata={} if metadata is None else dict(metadata),
    )


def build_review_case(
    subject: ReviewBoardSubject,
    policy: ReviewBoardPolicy,
) -> dict[str, Any]:
    """Build the canonical subject/policy envelope for one board case."""

    payload: dict[str, Any] = {
        "schema_version": WAVE13_CASE_SCHEMA_VERSION,
        "subject": subject.to_dict(),
        "policy": policy.to_dict(),
        "subject_digest": subject.digest,
        "policy_digest": policy.digest,
        "machine_authority": False,
        "human_authority_required": True,
        "scope_note": (
            "Machine recommendations are advisory only. Human board approval is a gate "
            "for the next governed step and is not deployment authority."
        ),
    }
    payload["digest"] = digest_payload(payload)
    return payload


def build_machine_advisory_set(
    subject: ReviewBoardSubject,
    policy: ReviewBoardPolicy,
    advisories: Sequence[MachineAdvisory],
) -> dict[str, Any]:
    """Build canonical machine advisories with an explicit zero-authority boundary."""

    normalized = tuple(sorted(advisories, key=lambda item: item.advisory_id))
    payload: dict[str, Any] = {
        "schema_version": WAVE13_ADVISORY_SET_SCHEMA_VERSION,
        "subject_digest": subject.digest,
        "policy_digest": policy.digest,
        "advisory_count": len(normalized),
        "authoritative_vote_count": 0,
        "advisories": [item.to_dict() for item in normalized],
        "scope_note": (
            "Machine advisories remain visible evidence but contribute zero votes and "
            "cannot satisfy any human review role or quorum requirement."
        ),
    }
    payload["digest"] = digest_payload(payload)
    return payload


def build_human_review_set(
    subject: ReviewBoardSubject,
    policy: ReviewBoardPolicy,
    reviews: Sequence[HumanReview],
) -> dict[str, Any]:
    """Build canonical human review records bound to subject and policy digests."""

    normalized = tuple(sorted(reviews, key=lambda item: item.review_id))
    payload: dict[str, Any] = {
        "schema_version": WAVE13_HUMAN_REVIEW_SET_SCHEMA_VERSION,
        "subject_digest": subject.digest,
        "policy_digest": policy.digest,
        "review_count": len(normalized),
        "reviews": [item.to_dict() for item in normalized],
        "scope_note": (
            "External identity verification state is supplied by an integration boundary. "
            "BlackFox preserves the reference and digest but is not itself an identity provider."
        ),
    }
    payload["digest"] = digest_payload(payload)
    return payload


def build_challenge_set(
    subject: ReviewBoardSubject,
    challenges: Sequence[EvidenceChallenge],
) -> dict[str, Any]:
    """Build canonical evidence challenges and preserve unresolved dissent."""

    normalized = tuple(sorted(challenges, key=lambda item: item.challenge_id))
    payload: dict[str, Any] = {
        "schema_version": WAVE13_CHALLENGE_SET_SCHEMA_VERSION,
        "subject_digest": subject.digest,
        "challenge_count": len(normalized),
        "challenges": [item.to_dict() for item in normalized],
        "scope_note": (
            "Open evidence challenges are preserved rather than erased by machine or "
            "majority recommendation. The active policy decides whether they block."
        ),
    }
    payload["digest"] = digest_payload(payload)
    return payload


def build_review_ledger(
    *,
    subject: ReviewBoardSubject,
    policy: ReviewBoardPolicy,
    advisories: Sequence[MachineAdvisory],
    reviews: Sequence[HumanReview],
    challenges: Sequence[EvidenceChallenge],
    evaluation: ReviewBoardEvaluation,
) -> dict[str, Any]:
    """Build a deterministic package-internal hash chain over the review sequence."""

    event_specs: list[tuple[str, str, str]] = [
        ("subject_admitted", subject.digest, subject.digest),
        ("policy_bound", policy.policy_id, policy.digest),
    ]
    event_specs.extend(
        ("machine_advisory_recorded", item.advisory_id, item.digest)
        for item in sorted(advisories, key=lambda value: value.advisory_id)
    )
    event_specs.extend(
        ("human_review_recorded", item.review_id, item.digest)
        for item in sorted(reviews, key=lambda value: value.review_id)
    )
    event_specs.extend(
        ("evidence_challenge_recorded", item.challenge_id, item.digest)
        for item in sorted(challenges, key=lambda value: value.challenge_id)
    )
    event_specs.append(("board_evaluated", evaluation.status.value, evaluation.digest))

    events: list[dict[str, Any]] = []
    previous_hash = ""
    for sequence, (event_type, object_id, object_digest) in enumerate(event_specs, start=1):
        event: dict[str, Any] = {
            "sequence": sequence,
            "event_type": event_type,
            "object_id": object_id,
            "object_digest": object_digest,
            "previous_hash": previous_hash,
        }
        event_hash = digest_payload(event)
        event["event_hash"] = event_hash
        events.append(event)
        previous_hash = event_hash

    payload: dict[str, Any] = {
        "schema_version": WAVE13_LEDGER_SCHEMA_VERSION,
        "subject_digest": subject.digest,
        "policy_digest": policy.digest,
        "event_count": len(events),
        "head_hash": previous_hash,
        "events": events,
        "scope_note": (
            "This package-internal hash chain detects mutation and reordering within the "
            "serialized review record. It is not an external transparency log or trusted timestamp."
        ),
    }
    payload["digest"] = digest_payload(payload)
    return payload


def build_review_bundle_index(
    *,
    subject: ReviewBoardSubject,
    policy: ReviewBoardPolicy,
    evaluation: ReviewBoardEvaluation,
    ledger: Mapping[str, Any],
    entries: Mapping[str, bytes],
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a non-self-referential byte inventory for the Wave 13 package."""

    indexed_entries = [
        {
            "path": name,
            "sha256": hashlib.sha256(body).hexdigest(),
            "size_bytes": len(body),
            "media_type": (
                "application/zip" if name == UPSTREAM_WAVE12_ENTRY else "application/json"
            ),
        }
        for name, body in sorted(entries.items())
    ]
    payload: dict[str, Any] = {
        "schema_version": WAVE13_BUNDLE_INDEX_SCHEMA_VERSION,
        "subject_digest": subject.digest,
        "policy_digest": policy.digest,
        "evaluation_digest": evaluation.digest,
        "status": evaluation.status.value,
        "ledger_digest": str(ledger["digest"]),
        "upstream_wave12_sha256": subject.wave12_archive_sha256,
        "entry_count_excluding_index": len(indexed_entries),
        "entries": indexed_entries,
        "metadata": {} if metadata is None else dict(metadata),
        "scope_note": (
            "The bundle index is a deterministic byte-integrity inventory, not a signature, "
            "trusted timestamp, certification, or authorization."
        ),
    }
    payload["bundle_index_digest"] = digest_payload(payload)
    return payload


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(filename=name, date_time=_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.flag_bits = 0
    return info
