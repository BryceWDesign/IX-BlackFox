from __future__ import annotations

import hashlib
import json
import stat
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum, auto
from pathlib import Path, PurePosixPath
from typing import Any

from ix_blackfox.assurance.crosswalk import build_assurance_crosswalk
from ix_blackfox.assurance.evidence import CollectedEvidence
from ix_blackfox.assurance.models import digest_payload
from ix_blackfox.assurance.package import (
    WAVE12_BUNDLE_INDEX_SCHEMA_VERSION,
    WAVE12_IN_TOTO_PREDICATE_TYPE,
    build_authority_review_set,
    build_bundle_index,
    build_in_toto_statement,
    canonical_json_bytes,
)
from ix_blackfox.assurance.parsing import (
    parse_assurance_manifest,
    parse_authority_reviews,
)
from ix_blackfox.assurance.report import build_assurance_readiness_report

WAVE12_VERIFICATION_SCHEMA_VERSION = "wave12.assurance_package_verification.v1"

DEFAULT_MAX_ARCHIVE_ENTRIES = 256
DEFAULT_MAX_ENTRY_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_COMPRESSION_RATIO = 200.0

_REQUIRED_PACKAGE_ENTRIES = frozenset(
    {
        "manifest.json",
        "crosswalk.json",
        "readiness-report.json",
        "authority-reviews.json",
        "in-toto-statement.json",
        "bundle-index.json",
    }
)


class PackageVerificationIssueCode(StrEnum):
    """Stable fail-closed issue codes for Wave 12 archive verification."""

    ARCHIVE_OPEN_FAILED = auto()
    TOO_MANY_ENTRIES = auto()
    UNSAFE_ENTRY_PATH = auto()
    DUPLICATE_ENTRY_PATH = auto()
    DIRECTORY_ENTRY = auto()
    SYMLINK_ENTRY = auto()
    ENTRY_TOO_LARGE = auto()
    ARCHIVE_TOO_LARGE = auto()
    COMPRESSION_RATIO_EXCEEDED = auto()
    REQUIRED_ENTRY_MISSING = auto()
    JSON_INVALID = auto()
    SCHEMA_VERSION_MISMATCH = auto()
    DIGEST_MISMATCH = auto()
    SIZE_MISMATCH = auto()
    INDEX_ENTRY_MISMATCH = auto()
    MANIFEST_EVIDENCE_MISMATCH = auto()
    SUBJECT_BINDING_MISMATCH = auto()
    PROFILE_BINDING_MISMATCH = auto()
    CROSSWALK_BINDING_MISMATCH = auto()
    READINESS_BINDING_MISMATCH = auto()
    REVIEW_BINDING_MISMATCH = auto()
    IN_TOTO_STATEMENT_MISMATCH = auto()
    PROHIBITED_CLAIM_RECORDED = auto()
    MANIFEST_SEMANTICS_MISMATCH = auto()
    CROSSWALK_EVALUATION_MISMATCH = auto()
    READINESS_SEMANTICS_MISMATCH = auto()
    REVIEW_AUTHORITY_MISMATCH = auto()


@dataclass(frozen=True, slots=True)
class PackageVerificationIssue:
    """One archive-integrity or semantic-binding failure."""

    code: PackageVerificationIssueCode
    summary: str
    path: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "summary": self.summary,
            "path": self.path,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class AssurancePackageVerification:
    """Independent verification result for a serialized Wave 12 package."""

    archive_path: str
    archive_sha256: str
    archive_size_bytes: int
    issues: tuple[PackageVerificationIssue, ...]
    entry_count: int
    uncompressed_size_bytes: int
    manifest_digest: str = ""
    profile_digest: str = ""
    readiness_status: str = ""
    bundle_index_digest: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return not self.issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": WAVE12_VERIFICATION_SCHEMA_VERSION,
            "archive_path": self.archive_path,
            "archive_sha256": self.archive_sha256,
            "archive_size_bytes": self.archive_size_bytes,
            "passed": self.passed,
            "issue_count": len(self.issues),
            "issues": [issue.to_dict() for issue in self.issues],
            "entry_count": self.entry_count,
            "uncompressed_size_bytes": self.uncompressed_size_bytes,
            "manifest_digest": self.manifest_digest,
            "profile_digest": self.profile_digest,
            "readiness_status": self.readiness_status,
            "bundle_index_digest": self.bundle_index_digest,
            "authenticated": False,
            "metadata": dict(self.metadata),
            "scope_note": (
                "A passing verification proves archive integrity and internal "
                "binding only. The package remains unsigned and this report does "
                "not certify, authorize, accredit, or declare compliance."
            ),
        }


def verify_assurance_package(
    archive_path: Path,
    *,
    max_entries: int = DEFAULT_MAX_ARCHIVE_ENTRIES,
    max_entry_bytes: int = DEFAULT_MAX_ENTRY_BYTES,
    max_uncompressed_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES,
    max_compression_ratio: float = DEFAULT_MAX_COMPRESSION_RATIO,
    metadata: Mapping[str, Any] | None = None,
) -> AssurancePackageVerification:
    """Verify archive safety, byte integrity, digests, and cross-document bindings."""

    archive_bytes = archive_path.read_bytes()
    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    issues: list[PackageVerificationIssue] = []
    entry_count = 0
    total_uncompressed = 0
    manifest_digest = ""
    profile_digest = ""
    readiness_status = ""
    bundle_index_digest = ""

    try:
        with zipfile.ZipFile(archive_path, mode="r") as archive:
            infos = archive.infolist()
            entry_count = len(infos)
            if entry_count > max_entries:
                issues.append(
                    _issue(
                        PackageVerificationIssueCode.TOO_MANY_ENTRIES,
                        f"Archive has {entry_count} entries; maximum is {max_entries}.",
                    )
                )
            names = [info.filename for info in infos]
            duplicate_names = sorted(
                {name for name in names if names.count(name) > 1}
            )
            for name in duplicate_names:
                issues.append(
                    _issue(
                        PackageVerificationIssueCode.DUPLICATE_ENTRY_PATH,
                        "Archive contains a duplicate entry path.",
                        path=name,
                    )
                )

            for info in infos:
                issues.extend(
                    _validate_zip_info(
                        info,
                        max_entry_bytes=max_entry_bytes,
                        max_compression_ratio=max_compression_ratio,
                    )
                )
                total_uncompressed += info.file_size
            if total_uncompressed > max_uncompressed_bytes:
                issues.append(
                    _issue(
                        PackageVerificationIssueCode.ARCHIVE_TOO_LARGE,
                        "Archive uncompressed size exceeds the verification limit.",
                        metadata={"size_bytes": total_uncompressed},
                    )
                )

            missing_required = sorted(_REQUIRED_PACKAGE_ENTRIES - set(names))
            for name in missing_required:
                issues.append(
                    _issue(
                        PackageVerificationIssueCode.REQUIRED_ENTRY_MISSING,
                        "Required Wave 12 package entry is missing.",
                        path=name,
                    )
                )

            if any(
                issue.code
                in {
                    PackageVerificationIssueCode.UNSAFE_ENTRY_PATH,
                    PackageVerificationIssueCode.DUPLICATE_ENTRY_PATH,
                    PackageVerificationIssueCode.DIRECTORY_ENTRY,
                    PackageVerificationIssueCode.SYMLINK_ENTRY,
                    PackageVerificationIssueCode.ENTRY_TOO_LARGE,
                    PackageVerificationIssueCode.ARCHIVE_TOO_LARGE,
                    PackageVerificationIssueCode.COMPRESSION_RATIO_EXCEEDED,
                }
                for issue in issues
            ):
                return _verification_result(
                    archive_path=archive_path,
                    archive_sha256=archive_sha256,
                    archive_size_bytes=len(archive_bytes),
                    issues=issues,
                    entry_count=entry_count,
                    total_uncompressed=total_uncompressed,
                    metadata=metadata,
                )

            contents = {name: archive.read(name) for name in names}
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        issues.append(
            _issue(
                PackageVerificationIssueCode.ARCHIVE_OPEN_FAILED,
                f"Archive could not be read: {exc}",
            )
        )
        return _verification_result(
            archive_path=archive_path,
            archive_sha256=archive_sha256,
            archive_size_bytes=len(archive_bytes),
            issues=issues,
            entry_count=entry_count,
            total_uncompressed=total_uncompressed,
            metadata=metadata,
        )

    documents = _load_json_documents(contents, issues)
    index = documents.get("bundle-index.json")
    manifest = documents.get("manifest.json")
    crosswalk = documents.get("crosswalk.json")
    readiness = documents.get("readiness-report.json")
    reviews = documents.get("authority-reviews.json")
    statement = documents.get("in-toto-statement.json")

    if index is not None:
        bundle_index_digest = _verify_digest_field(
            index,
            field="bundle_index_digest",
            path="bundle-index.json",
            issues=issues,
        )
        if index.get("schema_version") != WAVE12_BUNDLE_INDEX_SCHEMA_VERSION:
            issues.append(
                _issue(
                    PackageVerificationIssueCode.SCHEMA_VERSION_MISMATCH,
                    "Bundle index schema version is unsupported.",
                    path="bundle-index.json",
                )
            )
        _verify_bundle_index(index=index, contents=contents, issues=issues)

    if manifest is not None:
        manifest_digest = _verify_digest_field(
            manifest,
            field="manifest_digest",
            path="manifest.json",
            issues=issues,
        )
        profile_digest = _verify_nested_digest(
            manifest,
            object_field="profile",
            digest_field="digest",
            path="manifest.json",
            issues=issues,
        )
        _verify_nested_digest(
            manifest,
            object_field="subject",
            digest_field="digest",
            path="manifest.json",
            issues=issues,
        )
        _verify_manifest_evidence(manifest=manifest, contents=contents, issues=issues)
        claims = manifest.get("claims")
        if isinstance(claims, dict) and claims.get("prohibited_hits"):
            issues.append(
                _issue(
                    PackageVerificationIssueCode.PROHIBITED_CLAIM_RECORDED,
                    "Manifest contains a prohibited asserted assurance claim.",
                    path="manifest.json",
                )
            )

    if crosswalk is not None:
        _verify_digest_field(
            crosswalk,
            field="digest",
            path="crosswalk.json",
            issues=issues,
        )
    if readiness is not None:
        _verify_digest_field(
            readiness,
            field="digest",
            path="readiness-report.json",
            issues=issues,
        )
        status_value = readiness.get("status")
        readiness_status = status_value if isinstance(status_value, str) else ""
    if reviews is not None:
        _verify_digest_field(
            reviews,
            field="digest",
            path="authority-reviews.json",
            issues=issues,
        )
        _verify_review_digests(reviews, issues)

    if manifest is not None and crosswalk is not None:
        _verify_manifest_crosswalk_bindings(manifest, crosswalk, issues)
    if manifest is not None and crosswalk is not None and readiness is not None:
        _verify_readiness_bindings(manifest, crosswalk, readiness, issues)
    if manifest is not None and reviews is not None:
        _verify_review_bindings(manifest, reviews, issues)
    if manifest is not None and statement is not None:
        _verify_in_toto_statement(
            manifest=manifest,
            statement=statement,
            contents=contents,
            issues=issues,
        )
    if all(
        document is not None
        for document in (index, manifest, crosswalk, readiness, reviews, statement)
    ):
        assert index is not None
        assert manifest is not None
        assert crosswalk is not None
        assert readiness is not None
        assert reviews is not None
        assert statement is not None
        _verify_recomputed_semantics(
            index=index,
            manifest=manifest,
            crosswalk=crosswalk,
            readiness=readiness,
            reviews=reviews,
            statement=statement,
            contents=contents,
            issues=issues,
        )

    return _verification_result(
        archive_path=archive_path,
        archive_sha256=archive_sha256,
        archive_size_bytes=len(archive_bytes),
        issues=issues,
        entry_count=entry_count,
        total_uncompressed=total_uncompressed,
        manifest_digest=manifest_digest,
        profile_digest=profile_digest,
        readiness_status=readiness_status,
        bundle_index_digest=bundle_index_digest,
        metadata=metadata,
    )


def write_package_verification(
    verification: AssurancePackageVerification,
    output_path: Path,
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.is_symlink():
        raise ValueError("Verification output must not be a symlink.")
    output_path.write_bytes(canonical_json_bytes(verification.to_dict()))
    return output_path


def _validate_zip_info(
    info: zipfile.ZipInfo,
    *,
    max_entry_bytes: int,
    max_compression_ratio: float,
) -> tuple[PackageVerificationIssue, ...]:
    issues: list[PackageVerificationIssue] = []
    name = info.filename
    if not _safe_archive_path(name):
        issues.append(
            _issue(
                PackageVerificationIssueCode.UNSAFE_ENTRY_PATH,
                "Archive entry path is unsafe.",
                path=name,
            )
        )
    if info.is_dir():
        issues.append(
            _issue(
                PackageVerificationIssueCode.DIRECTORY_ENTRY,
                "Wave 12 packages must contain files only.",
                path=name,
            )
        )
    unix_mode = (info.external_attr >> 16) & 0xFFFF
    if stat.S_ISLNK(unix_mode):
        issues.append(
            _issue(
                PackageVerificationIssueCode.SYMLINK_ENTRY,
                "Archive entry is a symlink.",
                path=name,
            )
        )
    if info.file_size > max_entry_bytes:
        issues.append(
            _issue(
                PackageVerificationIssueCode.ENTRY_TOO_LARGE,
                "Archive entry exceeds the per-entry size limit.",
                path=name,
                metadata={"size_bytes": info.file_size},
            )
        )
    ratio = (
        float(info.file_size) / float(max(info.compress_size, 1))
        if info.file_size
        else 1.0
    )
    if ratio > max_compression_ratio:
        issues.append(
            _issue(
                PackageVerificationIssueCode.COMPRESSION_RATIO_EXCEEDED,
                "Archive entry compression ratio exceeds the verification limit.",
                path=name,
                metadata={"compression_ratio": ratio},
            )
        )
    return tuple(issues)


def _safe_archive_path(name: str) -> bool:
    if not name or "\\" in name or "\x00" in name:
        return False
    path = PurePosixPath(name)
    return (
        not path.is_absolute()
        and not name.startswith("/")
        and not name.endswith("/")
        and all(part not in {"", ".", ".."} for part in path.parts)
        and not (len(path.parts[0]) == 2 and path.parts[0][1] == ":")
    )


def _load_json_documents(
    contents: Mapping[str, bytes],
    issues: list[PackageVerificationIssue],
) -> dict[str, Mapping[str, Any]]:
    documents: dict[str, Mapping[str, Any]] = {}
    for name in _REQUIRED_PACKAGE_ENTRIES:
        body = contents.get(name)
        if body is None:
            continue
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            issues.append(
                _issue(
                    PackageVerificationIssueCode.JSON_INVALID,
                    "Required JSON document is not valid UTF-8 JSON.",
                    path=name,
                )
            )
            continue
        if not isinstance(payload, dict):
            issues.append(
                _issue(
                    PackageVerificationIssueCode.JSON_INVALID,
                    "Required JSON document must contain an object.",
                    path=name,
                )
            )
            continue
        documents[name] = payload
    return documents


def _verify_bundle_index(
    *,
    index: Mapping[str, Any],
    contents: Mapping[str, bytes],
    issues: list[PackageVerificationIssue],
) -> None:
    raw_entries = index.get("entries")
    if not isinstance(raw_entries, list):
        issues.append(
            _issue(
                PackageVerificationIssueCode.INDEX_ENTRY_MISMATCH,
                "Bundle index entries must be a list.",
                path="bundle-index.json",
            )
        )
        return

    indexed_paths: list[str] = []
    for item in raw_entries:
        if not isinstance(item, dict):
            issues.append(
                _issue(
                    PackageVerificationIssueCode.INDEX_ENTRY_MISMATCH,
                    "Bundle index entry must be an object.",
                    path="bundle-index.json",
                )
            )
            continue
        path = item.get("path")
        digest = item.get("sha256")
        size = item.get("size_bytes")
        if not isinstance(path, str) or path == "bundle-index.json":
            issues.append(
                _issue(
                    PackageVerificationIssueCode.INDEX_ENTRY_MISMATCH,
                    "Bundle index contains an invalid entry path.",
                    path="bundle-index.json",
                )
            )
            continue
        indexed_paths.append(path)
        body = contents.get(path)
        if body is None:
            issues.append(
                _issue(
                    PackageVerificationIssueCode.INDEX_ENTRY_MISMATCH,
                    "Indexed entry is missing from the archive.",
                    path=path,
                )
            )
            continue
        if digest != hashlib.sha256(body).hexdigest():
            issues.append(
                _issue(
                    PackageVerificationIssueCode.DIGEST_MISMATCH,
                    "Indexed entry digest does not match archive bytes.",
                    path=path,
                )
            )
        if size != len(body):
            issues.append(
                _issue(
                    PackageVerificationIssueCode.SIZE_MISMATCH,
                    "Indexed entry size does not match archive bytes.",
                    path=path,
                )
            )

    expected_paths = set(contents) - {"bundle-index.json"}
    if len(indexed_paths) != len(set(indexed_paths)) or set(indexed_paths) != expected_paths:
        issues.append(
            _issue(
                PackageVerificationIssueCode.INDEX_ENTRY_MISMATCH,
                "Bundle index paths do not exactly match archive entries.",
                path="bundle-index.json",
            )
        )


def _verify_manifest_evidence(
    *,
    manifest: Mapping[str, Any],
    contents: Mapping[str, bytes],
    issues: list[PackageVerificationIssue],
) -> None:
    raw_evidence = manifest.get("evidence")
    if not isinstance(raw_evidence, list):
        issues.append(
            _issue(
                PackageVerificationIssueCode.MANIFEST_EVIDENCE_MISMATCH,
                "Manifest evidence must be a list.",
                path="manifest.json",
            )
        )
        return
    artifact_ids: list[str] = []
    paths: list[str] = []
    for item in raw_evidence:
        if not isinstance(item, dict):
            issues.append(
                _issue(
                    PackageVerificationIssueCode.MANIFEST_EVIDENCE_MISMATCH,
                    "Manifest evidence entry must be an object.",
                    path="manifest.json",
                )
            )
            continue
        artifact_id = item.get("artifact_id")
        path = item.get("path")
        digest = item.get("sha256")
        size = item.get("size_bytes")
        if isinstance(artifact_id, str):
            artifact_ids.append(artifact_id)
        if not isinstance(path, str) or not path.startswith("evidence/"):
            issues.append(
                _issue(
                    PackageVerificationIssueCode.MANIFEST_EVIDENCE_MISMATCH,
                    "Manifest evidence path is invalid.",
                    path="manifest.json",
                )
            )
            continue
        paths.append(path)
        body = contents.get(path)
        if body is None or digest != hashlib.sha256(body).hexdigest() or size != len(body):
            issues.append(
                _issue(
                    PackageVerificationIssueCode.MANIFEST_EVIDENCE_MISMATCH,
                    "Manifest evidence descriptor does not match archive bytes.",
                    path=path,
                )
            )
    if len(artifact_ids) != len(set(artifact_ids)) or len(paths) != len(set(paths)):
        issues.append(
            _issue(
                PackageVerificationIssueCode.MANIFEST_EVIDENCE_MISMATCH,
                "Manifest evidence ids and paths must be unique.",
                path="manifest.json",
            )
        )
    archived_evidence_paths = {name for name in contents if name.startswith("evidence/")}
    if set(paths) != archived_evidence_paths:
        issues.append(
            _issue(
                PackageVerificationIssueCode.MANIFEST_EVIDENCE_MISMATCH,
                "Manifest evidence inventory does not exactly match packaged evidence.",
                path="manifest.json",
            )
        )


def _verify_manifest_crosswalk_bindings(
    manifest: Mapping[str, Any],
    crosswalk: Mapping[str, Any],
    issues: list[PackageVerificationIssue],
) -> None:
    subject = manifest.get("subject")
    profile = manifest.get("profile")
    subject_digest = subject.get("digest") if isinstance(subject, dict) else None
    profile_digest = profile.get("digest") if isinstance(profile, dict) else None
    if crosswalk.get("subject_digest") != subject_digest:
        issues.append(
            _issue(
                PackageVerificationIssueCode.SUBJECT_BINDING_MISMATCH,
                "Crosswalk is not bound to the manifest subject.",
                path="crosswalk.json",
            )
        )
    if crosswalk.get("profile_digest") != profile_digest:
        issues.append(
            _issue(
                PackageVerificationIssueCode.PROFILE_BINDING_MISMATCH,
                "Crosswalk is not bound to the manifest profile.",
                path="crosswalk.json",
            )
        )


def _verify_readiness_bindings(
    manifest: Mapping[str, Any],
    crosswalk: Mapping[str, Any],
    readiness: Mapping[str, Any],
    issues: list[PackageVerificationIssue],
) -> None:
    profile = manifest.get("profile")
    profile_digest = profile.get("digest") if isinstance(profile, dict) else None
    expected = {
        "manifest_digest": manifest.get("manifest_digest"),
        "profile_digest": profile_digest,
        "crosswalk_digest": crosswalk.get("digest"),
    }
    for binding_field, value in expected.items():
        if readiness.get(binding_field) != value:
            issues.append(
                _issue(
                    PackageVerificationIssueCode.READINESS_BINDING_MISMATCH,
                    f"Readiness report {binding_field} binding does not match.",
                    path="readiness-report.json",
                )
            )


def _verify_review_bindings(
    manifest: Mapping[str, Any],
    reviews: Mapping[str, Any],
    issues: list[PackageVerificationIssue],
) -> None:
    profile = manifest.get("profile")
    profile_digest = profile.get("digest") if isinstance(profile, dict) else None
    if (
        reviews.get("manifest_digest") != manifest.get("manifest_digest")
        or reviews.get("profile_digest") != profile_digest
    ):
        issues.append(
            _issue(
                PackageVerificationIssueCode.REVIEW_BINDING_MISMATCH,
                "Authority review set is not bound to the manifest and profile.",
                path="authority-reviews.json",
            )
        )


def _verify_review_digests(
    reviews: Mapping[str, Any],
    issues: list[PackageVerificationIssue],
) -> None:
    raw_reviews = reviews.get("reviews")
    if not isinstance(raw_reviews, list):
        issues.append(
            _issue(
                PackageVerificationIssueCode.REVIEW_BINDING_MISMATCH,
                "Authority reviews must be a list.",
                path="authority-reviews.json",
            )
        )
        return
    for item in raw_reviews:
        if not isinstance(item, dict):
            issues.append(
                _issue(
                    PackageVerificationIssueCode.REVIEW_BINDING_MISMATCH,
                    "Authority review entry must be an object.",
                    path="authority-reviews.json",
                )
            )
            continue
        _verify_digest_field(
            item,
            field="digest",
            path="authority-reviews.json",
            issues=issues,
        )


def _verify_in_toto_statement(
    *,
    manifest: Mapping[str, Any],
    statement: Mapping[str, Any],
    contents: Mapping[str, bytes],
    issues: list[PackageVerificationIssue],
) -> None:
    if (
        statement.get("_type") != "https://in-toto.io/Statement/v1"
        or statement.get("predicateType") != WAVE12_IN_TOTO_PREDICATE_TYPE
    ):
        issues.append(
            _issue(
                PackageVerificationIssueCode.IN_TOTO_STATEMENT_MISMATCH,
                "in-toto Statement type or predicate type is invalid.",
                path="in-toto-statement.json",
            )
        )
    raw_subjects = statement.get("subject")
    actual_subjects: dict[str, str] = {}
    if isinstance(raw_subjects, list):
        for item in raw_subjects:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            digest = item.get("digest")
            sha256 = digest.get("sha256") if isinstance(digest, dict) else None
            if isinstance(name, str) and isinstance(sha256, str):
                actual_subjects[name] = sha256
    expected_names = set(contents) - {
        "bundle-index.json",
        "in-toto-statement.json",
    }
    expected_subjects = {
        name: hashlib.sha256(contents[name]).hexdigest() for name in expected_names
    }
    predicate = statement.get("predicate")
    manifest_binding = (
        predicate.get("manifestDigest") if isinstance(predicate, dict) else None
    )
    if actual_subjects != expected_subjects or manifest_binding != manifest.get(
        "manifest_digest"
    ):
        issues.append(
            _issue(
                PackageVerificationIssueCode.IN_TOTO_STATEMENT_MISMATCH,
                "in-toto subjects or manifest binding do not match package bytes.",
                path="in-toto-statement.json",
            )
        )


def _verify_recomputed_semantics(
    *,
    index: Mapping[str, Any],
    manifest: Mapping[str, Any],
    crosswalk: Mapping[str, Any],
    readiness: Mapping[str, Any],
    reviews: Mapping[str, Any],
    statement: Mapping[str, Any],
    contents: Mapping[str, bytes],
    issues: list[PackageVerificationIssue],
) -> None:
    """Rebuild all derived documents from reopened archive inputs.

    Digest checks alone only prove that fields are self-consistent. This pass
    independently parses the manifest and reviews, recalculates control
    coverage and readiness, and then rebuilds the review set, in-toto
    statement, and bundle index. A package cannot pass by changing a decision
    and merely recomputing its hashes.
    """

    try:
        parsed_manifest = parse_assurance_manifest(manifest)
    except (KeyError, TypeError, ValueError) as exc:
        issues.append(
            _issue(
                PackageVerificationIssueCode.MANIFEST_SEMANTICS_MISMATCH,
                f"Manifest could not be reconstructed canonically: {exc}",
                path="manifest.json",
            )
        )
        return

    try:
        parsed_reviews = parse_authority_reviews(reviews)
        expected_review_set = build_authority_review_set(
            parsed_manifest,
            parsed_reviews,
        )
        if expected_review_set != dict(reviews):
            raise ValueError("review-set counts, bindings, or digest differ")
    except (KeyError, TypeError, ValueError) as exc:
        issues.append(
            _issue(
                PackageVerificationIssueCode.REVIEW_AUTHORITY_MISMATCH,
                f"Authority review set is not canonical: {exc}",
                path="authority-reviews.json",
            )
        )
        return

    try:
        expected_crosswalk = build_assurance_crosswalk(
            subject=parsed_manifest.subject,
            profile=parsed_manifest.profile,
            artifacts=parsed_manifest.evidence,
            report_id=_document_string(crosswalk, "report_id", "crosswalk.json"),
            metadata=_document_mapping(crosswalk, "metadata", "crosswalk.json"),
        )
        if expected_crosswalk.to_dict() != dict(crosswalk):
            raise ValueError("serialized evaluations differ from recomputed coverage")
    except (KeyError, TypeError, ValueError) as exc:
        issues.append(
            _issue(
                PackageVerificationIssueCode.CROSSWALK_EVALUATION_MISMATCH,
                f"Crosswalk does not match recomputed evidence coverage: {exc}",
                path="crosswalk.json",
            )
        )
        return

    try:
        expected_readiness = build_assurance_readiness_report(
            manifest=parsed_manifest,
            crosswalk=expected_crosswalk,
            reviews=parsed_reviews,
            report_id=_document_string(
                readiness,
                "report_id",
                "readiness-report.json",
            ),
            metadata=_document_mapping(
                readiness,
                "metadata",
                "readiness-report.json",
            ),
        )
        if expected_readiness.to_dict() != dict(readiness):
            raise ValueError("serialized status or findings differ from recomputation")
    except (KeyError, TypeError, ValueError) as exc:
        issues.append(
            _issue(
                PackageVerificationIssueCode.READINESS_SEMANTICS_MISMATCH,
                f"Readiness does not match recomputed authority gates: {exc}",
                path="readiness-report.json",
            )
        )
        return

    try:
        collected = tuple(
            CollectedEvidence(
                artifact=artifact,
                body=contents[artifact.path],
            )
            for artifact in parsed_manifest.evidence
        )
        indexed_entries = {
            name: body
            for name, body in contents.items()
            if name != "bundle-index.json"
        }
        expected_index = build_bundle_index(
            manifest=parsed_manifest,
            crosswalk=expected_crosswalk,
            readiness=expected_readiness,
            entries=indexed_entries,
            evidence=collected,
            metadata=_document_mapping(index, "metadata", "bundle-index.json"),
        )
        if expected_index != dict(index):
            raise ValueError("index bindings or inventory differ from recomputation")
    except (KeyError, TypeError, ValueError) as exc:
        issues.append(
            _issue(
                PackageVerificationIssueCode.INDEX_ENTRY_MISMATCH,
                f"Bundle index is not the recomputed canonical index: {exc}",
                path="bundle-index.json",
            )
        )

    statement_entries = {
        name: body
        for name, body in contents.items()
        if name not in {"bundle-index.json", "in-toto-statement.json"}
    }
    expected_statement = build_in_toto_statement(
        manifest=parsed_manifest,
        crosswalk=expected_crosswalk,
        readiness=expected_readiness,
        package_entries=statement_entries,
    )
    if expected_statement != dict(statement):
        issues.append(
            _issue(
                PackageVerificationIssueCode.IN_TOTO_STATEMENT_MISMATCH,
                "in-toto predicate or subjects differ from recomputed package state.",
                path="in-toto-statement.json",
            )
        )


def _document_string(
    payload: Mapping[str, Any],
    field: str,
    path: str,
) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        raise ValueError(f"{path} field {field} must be a string")
    return value


def _document_mapping(
    payload: Mapping[str, Any],
    field: str,
    path: str,
) -> Mapping[str, Any]:
    value = payload.get(field)
    if not isinstance(value, dict):
        raise ValueError(f"{path} field {field} must be an object")
    return value


def _verify_nested_digest(
    payload: Mapping[str, Any],
    *,
    object_field: str,
    digest_field: str,
    path: str,
    issues: list[PackageVerificationIssue],
) -> str:
    nested = payload.get(object_field)
    if not isinstance(nested, dict):
        issues.append(
            _issue(
                PackageVerificationIssueCode.DIGEST_MISMATCH,
                f"{object_field} object is missing.",
                path=path,
            )
        )
        return ""
    return _verify_digest_field(
        nested,
        field=digest_field,
        path=path,
        issues=issues,
    )


def _verify_digest_field(
    payload: Mapping[str, Any],
    *,
    field: str,
    path: str,
    issues: list[PackageVerificationIssue],
) -> str:
    recorded = payload.get(field)
    body = dict(payload)
    body.pop(field, None)
    computed = digest_payload(body)
    if not isinstance(recorded, str) or recorded != computed:
        issues.append(
            _issue(
                PackageVerificationIssueCode.DIGEST_MISMATCH,
                f"Recorded {field} does not match the document payload.",
                path=path,
            )
        )
        return ""
    return recorded


def _verification_result(
    *,
    archive_path: Path,
    archive_sha256: str,
    archive_size_bytes: int,
    issues: Sequence[PackageVerificationIssue],
    entry_count: int,
    total_uncompressed: int,
    manifest_digest: str = "",
    profile_digest: str = "",
    readiness_status: str = "",
    bundle_index_digest: str = "",
    metadata: Mapping[str, Any] | None,
) -> AssurancePackageVerification:
    return AssurancePackageVerification(
        archive_path=str(archive_path),
        archive_sha256=archive_sha256,
        archive_size_bytes=archive_size_bytes,
        issues=tuple(sorted(issues, key=lambda item: (item.code.value, item.path))),
        entry_count=entry_count,
        uncompressed_size_bytes=total_uncompressed,
        manifest_digest=manifest_digest,
        profile_digest=profile_digest,
        readiness_status=readiness_status,
        bundle_index_digest=bundle_index_digest,
        metadata={} if metadata is None else dict(metadata),
    )


def _issue(
    code: PackageVerificationIssueCode,
    summary: str,
    *,
    path: str = "",
    metadata: Mapping[str, Any] | None = None,
) -> PackageVerificationIssue:
    return PackageVerificationIssue(
        code=code,
        summary=summary,
        path=path,
        metadata={} if metadata is None else dict(metadata),
    )
