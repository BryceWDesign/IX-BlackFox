from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass
from pathlib import Path

from ix_blackfox.assurance.models import AssuranceManifest
from ix_blackfox.assurance.parsing import parse_assurance_manifest
from ix_blackfox.assurance.verify import (
    AssurancePackageVerification,
    verify_assurance_package,
)
from ix_blackfox.review_board.models import ReviewBoardSubject


@dataclass(frozen=True, slots=True)
class Wave12Admission:
    """Verified Wave 12 package admitted as the immutable subject of Wave 13."""

    subject: ReviewBoardSubject
    manifest: AssuranceManifest
    verification: AssurancePackageVerification


def admit_wave12_package(
    archive_path: Path,
    *,
    admitted_at: str,
) -> Wave12Admission:
    """Independently verify and bind one Wave 12 package into a Wave 13 subject."""

    verification = verify_assurance_package(
        archive_path,
        metadata={"consumer": "wave13-review-board"},
    )
    if not verification.passed:
        raise ValueError("Wave 13 requires an independently verified Wave 12 package.")

    try:
        with zipfile.ZipFile(archive_path, mode="r") as archive:
            raw_manifest = archive.read("manifest.json")
    except (OSError, KeyError, zipfile.BadZipFile) as exc:
        raise ValueError("Verified Wave 12 package manifest could not be reopened.") from exc

    try:
        payload = json.loads(raw_manifest.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Wave 12 manifest is not valid UTF-8 JSON.") from exc
    if not isinstance(payload, dict):
        raise ValueError("Wave 12 manifest root must be a JSON object.")
    manifest = parse_assurance_manifest(payload)

    subject = ReviewBoardSubject(
        repository=manifest.subject.repository,
        revision=manifest.subject.revision,
        scope=(
            "Wave 13 role-based human-machine review of the admitted Wave 12 "
            f"assurance subject: {manifest.subject.scope}"
        ),
        producer_agent_id=manifest.subject.producer_agent_id,
        wave12_archive_sha256=verification.archive_sha256,
        wave12_manifest_digest=manifest.digest,
        wave12_profile_digest=manifest.profile.digest,
        admitted_at=admitted_at,
        metadata={
            "wave12_readiness_status": verification.readiness_status,
            "wave12_bundle_index_digest": verification.bundle_index_digest,
            "wave12_subject_digest": manifest.subject.digest,
            "wave12_verification_passed": True,
        },
    )
    return Wave12Admission(
        subject=subject,
        manifest=manifest,
        verification=verification,
    )
