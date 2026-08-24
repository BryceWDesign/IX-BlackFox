from __future__ import annotations

import hashlib
import json
import stat
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ix_blackfox.assurance.crosswalk import AssuranceCrosswalkReport
from ix_blackfox.assurance.evidence import CollectedEvidence
from ix_blackfox.assurance.models import (
    AssuranceManifest,
    AuthorityReview,
    digest_payload,
)
from ix_blackfox.assurance.report import AssuranceReadinessReport

WAVE12_BUNDLE_INDEX_SCHEMA_VERSION = "wave12.assurance_bundle_index.v1"
WAVE12_IN_TOTO_PREDICATE_TYPE = (
    "https://github.com/BryceWDesign/IX-BlackFox/"
    "blob/main/docs/wave12-certification-ready-evidence.md#predicate-v1"
)

_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


@dataclass(frozen=True, slots=True)
class AssurancePackageBuildResult:
    """Content digests produced by one deterministic package build."""

    output_path: str
    archive_sha256: str
    archive_size_bytes: int
    manifest_digest: str
    crosswalk_digest: str
    readiness_digest: str
    bundle_index_digest: str
    entry_count: int
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "output_path": self.output_path,
            "archive_sha256": self.archive_sha256,
            "archive_size_bytes": self.archive_size_bytes,
            "manifest_digest": self.manifest_digest,
            "crosswalk_digest": self.crosswalk_digest,
            "readiness_digest": self.readiness_digest,
            "bundle_index_digest": self.bundle_index_digest,
            "entry_count": self.entry_count,
            "metadata": dict(self.metadata),
            "scope_note": (
                "Archive and entry digests prove byte integrity only. They do not "
                "authenticate an organization, certify a system, or grant authority."
            ),
        }


def build_assurance_package(
    *,
    output_path: Path,
    manifest: AssuranceManifest,
    crosswalk: AssuranceCrosswalkReport,
    readiness: AssuranceReadinessReport,
    evidence: Sequence[CollectedEvidence],
    reviews: Sequence[AuthorityReview] = (),
    metadata: Mapping[str, Any] | None = None,
) -> AssurancePackageBuildResult:
    """Write a deterministic, content-indexed Wave 12 ZIP package."""

    normalized_evidence = tuple(
        sorted(evidence, key=lambda item: item.artifact.artifact_id)
    )
    normalized_reviews = tuple(sorted(reviews, key=lambda item: item.review_id))
    _validate_build_inputs(
        manifest=manifest,
        crosswalk=crosswalk,
        readiness=readiness,
        evidence=normalized_evidence,
        reviews=normalized_reviews,
    )

    entries: dict[str, bytes] = {
        "manifest.json": canonical_json_bytes(manifest.to_dict()),
        "crosswalk.json": canonical_json_bytes(crosswalk.to_dict()),
        "readiness-report.json": canonical_json_bytes(readiness.to_dict()),
        "authority-reviews.json": canonical_json_bytes(
            build_authority_review_set(manifest, normalized_reviews)
        ),
    }
    for item in normalized_evidence:
        entries[item.artifact.path] = item.body

    entries["in-toto-statement.json"] = canonical_json_bytes(
        build_in_toto_statement(
            manifest=manifest,
            crosswalk=crosswalk,
            readiness=readiness,
            package_entries=entries,
        )
    )
    bundle_index = build_bundle_index(
        manifest=manifest,
        crosswalk=crosswalk,
        readiness=readiness,
        entries=entries,
        evidence=normalized_evidence,
        metadata=metadata,
    )
    bundle_index_bytes = canonical_json_bytes(bundle_index)
    entries["bundle-index.json"] = bundle_index_bytes

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.is_symlink():
        raise ValueError("Assurance package output must not be a symlink.")
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
    return AssurancePackageBuildResult(
        output_path=str(output_path),
        archive_sha256=hashlib.sha256(archive_bytes).hexdigest(),
        archive_size_bytes=len(archive_bytes),
        manifest_digest=manifest.digest,
        crosswalk_digest=crosswalk.digest,
        readiness_digest=readiness.digest,
        bundle_index_digest=str(bundle_index["bundle_index_digest"]),
        entry_count=len(entries),
        metadata={} if metadata is None else dict(metadata),
    )


def build_bundle_index(
    *,
    manifest: AssuranceManifest,
    crosswalk: AssuranceCrosswalkReport,
    readiness: AssuranceReadinessReport,
    entries: Mapping[str, bytes],
    evidence: Sequence[CollectedEvidence],
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the non-self-referential byte index stored in the package."""

    media_types = {
        item.artifact.path: item.artifact.media_type for item in evidence
    }
    indexed_entries = [
        {
            "path": name,
            "sha256": hashlib.sha256(body).hexdigest(),
            "size_bytes": len(body),
            "media_type": media_types.get(name, "application/json"),
        }
        for name, body in sorted(entries.items())
    ]
    payload: dict[str, Any] = {
        "schema_version": WAVE12_BUNDLE_INDEX_SCHEMA_VERSION,
        "manifest_digest": manifest.digest,
        "subject_digest": manifest.subject.digest,
        "profile_digest": manifest.profile.digest,
        "crosswalk_digest": crosswalk.digest,
        "readiness_digest": readiness.digest,
        "readiness_status": readiness.status.value,
        "entry_count_excluding_index": len(indexed_entries),
        "entries": indexed_entries,
        "metadata": {} if metadata is None else dict(metadata),
        "scope_note": (
            "The bundle index is a deterministic byte-integrity inventory. It is "
            "not a digital signature, trusted timestamp, certification, or external attestation."
        ),
    }
    payload["bundle_index_digest"] = digest_payload(payload)
    return payload


def build_in_toto_statement(
    *,
    manifest: AssuranceManifest,
    crosswalk: AssuranceCrosswalkReport,
    readiness: AssuranceReadinessReport,
    package_entries: Mapping[str, bytes],
) -> dict[str, Any]:
    """Build an unsigned in-toto Statement v1 with a BlackFox predicate.

    The statement deliberately remains unsigned. Authentication belongs to an
    external signer or attestation service and must not be fabricated locally.
    """

    subjects = [
        {
            "name": name,
            "digest": {"sha256": hashlib.sha256(body).hexdigest()},
        }
        for name, body in sorted(package_entries.items())
    ]
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": WAVE12_IN_TOTO_PREDICATE_TYPE,
        "predicate": {
            "schemaVersion": "wave12.in_toto_predicate.v1",
            "repository": manifest.subject.repository,
            "revision": manifest.subject.revision,
            "manifestDigest": manifest.digest,
            "profileDigest": manifest.profile.digest,
            "crosswalkDigest": crosswalk.digest,
            "readinessDigest": readiness.digest,
            "readinessStatus": readiness.status.value,
            "authenticated": False,
            "scopeNote": (
                "This is an unsigned in-toto Statement carrying a BlackFox "
                "predicate. It is not a signed attestation, SLSA level claim, "
                "certification, or authorization."
            ),
        },
    }


def canonical_json_bytes(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def build_authority_review_set(
    manifest: AssuranceManifest,
    reviews: Sequence[AuthorityReview],
) -> dict[str, Any]:
    """Build the canonical review set bound to a manifest and profile."""

    normalized_reviews = tuple(sorted(reviews, key=lambda item: item.review_id))
    payload: dict[str, Any] = {
        "schema_version": "wave12.authority_review_set.v1",
        "manifest_digest": manifest.digest,
        "profile_digest": manifest.profile.digest,
        "review_count": len(normalized_reviews),
        "authoritative_human_approval_count": sum(
            review.authoritative_human_approval for review in normalized_reviews
        ),
        "reviews": [review.to_dict() for review in normalized_reviews],
        "scope_note": (
            "Only a separately authenticated human approval bound to the manifest "
            "and profile can advance a package to ready-for-external-assessment."
        ),
    }
    payload["digest"] = digest_payload(payload)
    return payload


def _validate_build_inputs(
    *,
    manifest: AssuranceManifest,
    crosswalk: AssuranceCrosswalkReport,
    readiness: AssuranceReadinessReport,
    evidence: tuple[CollectedEvidence, ...],
    reviews: tuple[AuthorityReview, ...],
) -> None:
    if crosswalk.subject_digest != manifest.subject.digest:
        raise ValueError("Crosswalk subject digest does not match the manifest.")
    if crosswalk.profile_digest != manifest.profile.digest:
        raise ValueError("Crosswalk profile digest does not match the manifest.")
    if readiness.manifest_digest != manifest.digest:
        raise ValueError("Readiness report manifest digest does not match.")
    if readiness.crosswalk_digest != crosswalk.digest:
        raise ValueError("Readiness report crosswalk digest does not match.")
    if readiness.profile_digest != manifest.profile.digest:
        raise ValueError("Readiness report profile digest does not match.")
    if readiness.reviews != reviews:
        raise ValueError("Readiness report reviews do not match package reviews.")

    manifest_by_id = manifest.evidence_by_id
    collected_by_id = {item.artifact.artifact_id: item for item in evidence}
    if set(manifest_by_id) != set(collected_by_id):
        raise ValueError("Collected evidence does not match the manifest inventory.")
    for artifact_id, descriptor in manifest_by_id.items():
        collected = collected_by_id[artifact_id]
        if descriptor != collected.artifact:
            raise ValueError(
                f"Collected evidence descriptor differs for artifact {artifact_id}."
            )


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(filename=name, date_time=_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.flag_bits = 0
    return info
