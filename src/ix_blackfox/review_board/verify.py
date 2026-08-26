from __future__ import annotations

import hashlib
import json
import stat
import tempfile
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum, auto
from pathlib import Path, PurePosixPath
from typing import Any

from ix_blackfox.assurance.package import canonical_json_bytes
from ix_blackfox.review_board.admission import admit_wave12_package
from ix_blackfox.review_board.models import ExternalHumanReviewVerification
from ix_blackfox.review_board.package import (
    UPSTREAM_WAVE12_ENTRY,
    build_challenge_set,
    build_human_review_set,
    build_machine_advisory_set,
    build_review_bundle_index,
    build_review_ledger,
)
from ix_blackfox.review_board.parsing import (
    parse_evidence_challenges,
    parse_human_reviews,
    parse_machine_advisories,
    parse_review_board_evaluation,
    parse_review_case,
)
from ix_blackfox.review_board.policy import evaluate_review_board

WAVE13_VERIFICATION_SCHEMA_VERSION = "wave13.review_board_package_verification.v1"
DEFAULT_MAX_ARCHIVE_ENTRIES = 64
DEFAULT_MAX_ENTRY_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
DEFAULT_MAX_COMPRESSION_RATIO = 300.0

_REQUIRED_ENTRIES = frozenset(
    {
        "review-case.json",
        "machine-advisories.json",
        "human-reviews.json",
        "evidence-challenges.json",
        "board-evaluation.json",
        "review-ledger.json",
        UPSTREAM_WAVE12_ENTRY,
        "bundle-index.json",
    }
)
_JSON_ENTRIES = _REQUIRED_ENTRIES - {UPSTREAM_WAVE12_ENTRY}


class ReviewBoardVerificationIssueCode(StrEnum):
    """Stable fail-closed issue codes for Wave 13 package verification."""

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
    UNEXPECTED_ENTRY_PATH = auto()
    JSON_INVALID = auto()
    BUNDLE_INDEX_MISMATCH = auto()
    UPSTREAM_DIGEST_MISMATCH = auto()
    UPSTREAM_VERIFICATION_FAILED = auto()
    UPSTREAM_SUBJECT_MISMATCH = auto()
    ADVISORY_SET_MISMATCH = auto()
    HUMAN_REVIEW_SET_MISMATCH = auto()
    CHALLENGE_SET_MISMATCH = auto()
    EXTERNAL_VERIFICATION_CONTEXT_MISMATCH = auto()
    EVALUATION_SEMANTICS_MISMATCH = auto()
    LEDGER_MISMATCH = auto()


@dataclass(frozen=True, slots=True)
class ReviewBoardVerificationIssue:
    """One archive, binding, or semantic verification failure."""

    code: ReviewBoardVerificationIssueCode
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
class ReviewBoardPackageVerification:
    """Independent verification result for a serialized Wave 13 package."""

    archive_path: str
    archive_sha256: str
    archive_size_bytes: int
    issues: tuple[ReviewBoardVerificationIssue, ...]
    entry_count: int
    uncompressed_size_bytes: int
    subject_digest: str = ""
    policy_digest: str = ""
    evaluation_digest: str = ""
    ledger_digest: str = ""
    bundle_index_digest: str = ""
    status: str = ""
    upstream_wave12_sha256: str = ""
    upstream_wave12_verification_passed: bool = False
    external_verification_context_digest: str = ""
    external_verification_count: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return not self.issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": WAVE13_VERIFICATION_SCHEMA_VERSION,
            "archive_path": self.archive_path,
            "archive_sha256": self.archive_sha256,
            "archive_size_bytes": self.archive_size_bytes,
            "passed": self.passed,
            "issue_count": len(self.issues),
            "issues": [issue.to_dict() for issue in self.issues],
            "entry_count": self.entry_count,
            "uncompressed_size_bytes": self.uncompressed_size_bytes,
            "subject_digest": self.subject_digest,
            "policy_digest": self.policy_digest,
            "evaluation_digest": self.evaluation_digest,
            "ledger_digest": self.ledger_digest,
            "bundle_index_digest": self.bundle_index_digest,
            "status": self.status,
            "upstream_wave12_sha256": self.upstream_wave12_sha256,
            "upstream_wave12_verification_passed": self.upstream_wave12_verification_passed,
            "external_verification_context_digest": self.external_verification_context_digest,
            "external_verification_count": self.external_verification_count,
            "metadata": dict(self.metadata),
            "scope_note": (
                "A passing Wave 13 verification proves archive integrity, nested Wave 12 "
                "verification, and deterministic board-policy recomputation. Authoritative "
                "human dispositions require matching trusted out-of-band verification context; "
                "a passing report does not grant deployment authority."
            ),
        }


def verify_review_board_package(
    archive_path: Path,
    *,
    max_entries: int = DEFAULT_MAX_ARCHIVE_ENTRIES,
    max_entry_bytes: int = DEFAULT_MAX_ENTRY_BYTES,
    max_uncompressed_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES,
    max_compression_ratio: float = DEFAULT_MAX_COMPRESSION_RATIO,
    external_verifications: Sequence[ExternalHumanReviewVerification] = (),
    metadata: Mapping[str, Any] | None = None,
) -> ReviewBoardPackageVerification:
    """Verify ZIP safety, nested Wave 12 evidence, bindings, ledger, and board semantics."""

    try:
        archive_bytes = archive_path.read_bytes()
    except OSError as exc:
        return _result(
            archive_path=archive_path,
            archive_sha256="",
            archive_size_bytes=0,
            issues=(
                _issue(
                    ReviewBoardVerificationIssueCode.ARCHIVE_OPEN_FAILED,
                    f"Archive could not be read: {exc}",
                ),
            ),
            entry_count=0,
            total_uncompressed=0,
            metadata=metadata,
        )

    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    issues: list[ReviewBoardVerificationIssue] = []
    entry_count = 0
    total_uncompressed = 0

    try:
        with zipfile.ZipFile(archive_path, mode="r") as archive:
            infos = archive.infolist()
            entry_count = len(infos)
            if entry_count > max_entries:
                issues.append(
                    _issue(
                        ReviewBoardVerificationIssueCode.TOO_MANY_ENTRIES,
                        f"Archive has {entry_count} entries; maximum is {max_entries}.",
                    )
                )
            names = [info.filename for info in infos]
            duplicates = sorted({name for name in names if names.count(name) > 1})
            for name in duplicates:
                issues.append(
                    _issue(
                        ReviewBoardVerificationIssueCode.DUPLICATE_ENTRY_PATH,
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
                        ReviewBoardVerificationIssueCode.ARCHIVE_TOO_LARGE,
                        "Archive uncompressed size exceeds the verification limit.",
                        metadata={"size_bytes": total_uncompressed},
                    )
                )

            for name in sorted(_REQUIRED_ENTRIES - set(names)):
                issues.append(
                    _issue(
                        ReviewBoardVerificationIssueCode.REQUIRED_ENTRY_MISSING,
                        "Required Wave 13 package entry is missing.",
                        path=name,
                    )
                )
            for name in sorted(set(names) - _REQUIRED_ENTRIES):
                issues.append(
                    _issue(
                        ReviewBoardVerificationIssueCode.UNEXPECTED_ENTRY_PATH,
                        "Archive contains an entry outside the canonical Wave 13 package layout.",
                        path=name,
                    )
                )

            if any(issue.code in _STRUCTURAL_CODES for issue in issues):
                return _result(
                    archive_path=archive_path,
                    archive_sha256=archive_sha256,
                    archive_size_bytes=len(archive_bytes),
                    issues=tuple(issues),
                    entry_count=entry_count,
                    total_uncompressed=total_uncompressed,
                    metadata=metadata,
                )
            contents = {name: archive.read(name) for name in names}
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        issues.append(
            _issue(
                ReviewBoardVerificationIssueCode.ARCHIVE_OPEN_FAILED,
                f"Archive could not be opened: {exc}",
            )
        )
        return _result(
            archive_path=archive_path,
            archive_sha256=archive_sha256,
            archive_size_bytes=len(archive_bytes),
            issues=tuple(issues),
            entry_count=entry_count,
            total_uncompressed=total_uncompressed,
            metadata=metadata,
        )

    documents = _load_json_documents(contents, issues)
    if any(name not in documents for name in _JSON_ENTRIES):
        return _result(
            archive_path=archive_path,
            archive_sha256=archive_sha256,
            archive_size_bytes=len(archive_bytes),
            issues=tuple(issues),
            entry_count=entry_count,
            total_uncompressed=total_uncompressed,
            metadata=metadata,
        )

    try:
        subject, policy = parse_review_case(documents["review-case.json"])
        advisories = parse_machine_advisories(documents["machine-advisories.json"])
        reviews = parse_human_reviews(documents["human-reviews.json"])
        challenges = parse_evidence_challenges(documents["evidence-challenges.json"])
        serialized_evaluation = parse_review_board_evaluation(
            documents["board-evaluation.json"]
        )
    except (KeyError, TypeError, ValueError) as exc:
        issues.append(
            _issue(
                ReviewBoardVerificationIssueCode.JSON_INVALID,
                f"Wave 13 document failed canonical parsing: {exc}",
            )
        )
        return _result(
            archive_path=archive_path,
            archive_sha256=archive_sha256,
            archive_size_bytes=len(archive_bytes),
            issues=tuple(issues),
            entry_count=entry_count,
            total_uncompressed=total_uncompressed,
            metadata=metadata,
        )

    upstream_body = contents[UPSTREAM_WAVE12_ENTRY]
    upstream_sha256 = hashlib.sha256(upstream_body).hexdigest()
    upstream_verified = False
    if upstream_sha256 != subject.wave12_archive_sha256:
        issues.append(
            _issue(
                ReviewBoardVerificationIssueCode.UPSTREAM_DIGEST_MISMATCH,
                "Embedded Wave 12 archive digest does not match the Wave 13 subject.",
                path=UPSTREAM_WAVE12_ENTRY,
            )
        )
    else:
        with tempfile.TemporaryDirectory(prefix="ix-blackfox-wave13-") as temp_dir:
            nested_path = Path(temp_dir) / "wave12.zip"
            nested_path.write_bytes(upstream_body)
            try:
                admitted = admit_wave12_package(
                    nested_path,
                    admitted_at=subject.admitted_at,
                )
            except (OSError, ValueError, zipfile.BadZipFile) as exc:
                issues.append(
                    _issue(
                        ReviewBoardVerificationIssueCode.UPSTREAM_VERIFICATION_FAILED,
                        f"Embedded Wave 12 package failed independent verification: {exc}",
                        path=UPSTREAM_WAVE12_ENTRY,
                    )
                )
            else:
                upstream_verified = admitted.verification.passed
                if admitted.subject != subject:
                    issues.append(
                        _issue(
                            ReviewBoardVerificationIssueCode.UPSTREAM_SUBJECT_MISMATCH,
                            "Wave 13 subject does not match the independently admitted Wave 12 package.",
                            path="review-case.json",
                        )
                    )

    expected_advisory_set = build_machine_advisory_set(subject, policy, advisories)
    if expected_advisory_set != documents["machine-advisories.json"]:
        issues.append(
            _issue(
                ReviewBoardVerificationIssueCode.ADVISORY_SET_MISMATCH,
                "Machine advisory set is not the canonical subject/policy-bound representation.",
                path="machine-advisories.json",
            )
        )

    expected_review_set = build_human_review_set(subject, policy, reviews)
    if expected_review_set != documents["human-reviews.json"]:
        issues.append(
            _issue(
                ReviewBoardVerificationIssueCode.HUMAN_REVIEW_SET_MISMATCH,
                "Human review set is not the canonical subject/policy-bound representation.",
                path="human-reviews.json",
            )
        )

    expected_challenge_set = build_challenge_set(subject, challenges)
    if expected_challenge_set != documents["evidence-challenges.json"]:
        issues.append(
            _issue(
                ReviewBoardVerificationIssueCode.CHALLENGE_SET_MISMATCH,
                "Evidence challenge set is not the canonical subject-bound representation.",
                path="evidence-challenges.json",
            )
        )

    recomputed_evaluation = evaluate_review_board(
        subject=subject,
        policy=policy,
        machine_advisories=advisories,
        human_reviews=reviews,
        external_verifications=external_verifications,
        challenges=challenges,
        metadata={"producer": "ix-blackfox-wave13-policy-engine"},
    )
    if (
        recomputed_evaluation.external_verification_count
        != serialized_evaluation.external_verification_count
        or recomputed_evaluation.external_verification_context_digest
        != serialized_evaluation.external_verification_context_digest
    ):
        issues.append(
            _issue(
                ReviewBoardVerificationIssueCode.EXTERNAL_VERIFICATION_CONTEXT_MISMATCH,
                (
                    "Trusted out-of-band human-review verification context does not "
                    "match the context bound into the serialized board evaluation."
                ),
                path="board-evaluation.json",
            )
        )
    if recomputed_evaluation.to_dict() != serialized_evaluation.to_dict():
        issues.append(
            _issue(
                ReviewBoardVerificationIssueCode.EVALUATION_SEMANTICS_MISMATCH,
                "Serialized board disposition differs from independent policy recomputation.",
                path="board-evaluation.json",
            )
        )

    expected_ledger = build_review_ledger(
        subject=subject,
        policy=policy,
        advisories=advisories,
        reviews=reviews,
        challenges=challenges,
        evaluation=recomputed_evaluation,
    )
    if expected_ledger != documents["review-ledger.json"]:
        issues.append(
            _issue(
                ReviewBoardVerificationIssueCode.LEDGER_MISMATCH,
                "Review ledger does not match the independently rebuilt hash chain.",
                path="review-ledger.json",
            )
        )

    index = documents["bundle-index.json"]
    indexed_metadata = index.get("metadata")
    if not isinstance(indexed_metadata, dict):
        indexed_metadata = {}
    entries_without_index = {
        name: body for name, body in contents.items() if name != "bundle-index.json"
    }
    expected_index = build_review_bundle_index(
        subject=subject,
        policy=policy,
        evaluation=recomputed_evaluation,
        ledger=expected_ledger,
        entries=entries_without_index,
        metadata=indexed_metadata,
    )
    if expected_index != index:
        issues.append(
            _issue(
                ReviewBoardVerificationIssueCode.BUNDLE_INDEX_MISMATCH,
                "Bundle index does not match package bytes and recomputed semantic digests.",
                path="bundle-index.json",
            )
        )

    return _result(
        archive_path=archive_path,
        archive_sha256=archive_sha256,
        archive_size_bytes=len(archive_bytes),
        issues=tuple(issues),
        entry_count=entry_count,
        total_uncompressed=total_uncompressed,
        subject_digest=subject.digest,
        policy_digest=policy.digest,
        evaluation_digest=recomputed_evaluation.digest,
        ledger_digest=str(expected_ledger["digest"]),
        bundle_index_digest=str(expected_index["bundle_index_digest"]),
        status=recomputed_evaluation.status.value,
        upstream_wave12_sha256=upstream_sha256,
        upstream_wave12_verification_passed=upstream_verified,
        external_verification_context_digest=(
            recomputed_evaluation.external_verification_context_digest
        ),
        external_verification_count=recomputed_evaluation.external_verification_count,
        metadata=metadata,
    )


def write_review_board_verification(
    verification: ReviewBoardPackageVerification,
    output_path: Path,
) -> None:
    """Write one canonical Wave 13 verification report."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.is_symlink():
        raise ValueError("Review-board verification output must not be a symlink.")
    output_path.write_bytes(canonical_json_bytes(verification.to_dict()))


def _validate_zip_info(
    info: zipfile.ZipInfo,
    *,
    max_entry_bytes: int,
    max_compression_ratio: float,
) -> tuple[ReviewBoardVerificationIssue, ...]:
    issues: list[ReviewBoardVerificationIssue] = []
    if not _safe_archive_path(info.filename):
        issues.append(
            _issue(
                ReviewBoardVerificationIssueCode.UNSAFE_ENTRY_PATH,
                "Archive entry path is unsafe.",
                path=info.filename,
            )
        )
    if info.is_dir():
        issues.append(
            _issue(
                ReviewBoardVerificationIssueCode.DIRECTORY_ENTRY,
                "Directory entries are not allowed in the deterministic package.",
                path=info.filename,
            )
        )
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        issues.append(
            _issue(
                ReviewBoardVerificationIssueCode.SYMLINK_ENTRY,
                "Symlink entries are not allowed.",
                path=info.filename,
            )
        )
    if info.file_size > max_entry_bytes:
        issues.append(
            _issue(
                ReviewBoardVerificationIssueCode.ENTRY_TOO_LARGE,
                "Archive entry exceeds the per-entry verification limit.",
                path=info.filename,
                metadata={"size_bytes": info.file_size},
            )
        )
    if info.file_size and info.compress_size == 0:
        ratio = float("inf")
    elif info.compress_size:
        ratio = info.file_size / info.compress_size
    else:
        ratio = 1.0
    if ratio > max_compression_ratio:
        issues.append(
            _issue(
                ReviewBoardVerificationIssueCode.COMPRESSION_RATIO_EXCEEDED,
                "Archive entry compression ratio exceeds the verification limit.",
                path=info.filename,
                metadata={"compression_ratio": ratio},
            )
        )
    return tuple(issues)


def _safe_archive_path(name: str) -> bool:
    if not name or "\\" in name or name.startswith("/"):
        return False
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return False
    if path.parts and ":" in path.parts[0]:
        return False
    return True


def _load_json_documents(
    contents: Mapping[str, bytes],
    issues: list[ReviewBoardVerificationIssue],
) -> dict[str, Mapping[str, Any]]:
    documents: dict[str, Mapping[str, Any]] = {}
    for name in sorted(_JSON_ENTRIES):
        body = contents.get(name)
        if body is None:
            continue
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            issues.append(
                _issue(
                    ReviewBoardVerificationIssueCode.JSON_INVALID,
                    f"Required JSON document could not be decoded: {exc}",
                    path=name,
                )
            )
            continue
        if not isinstance(payload, dict):
            issues.append(
                _issue(
                    ReviewBoardVerificationIssueCode.JSON_INVALID,
                    "Required JSON document root must be an object.",
                    path=name,
                )
            )
            continue
        documents[name] = payload
    return documents


def _result(
    *,
    archive_path: Path,
    archive_sha256: str,
    archive_size_bytes: int,
    issues: tuple[ReviewBoardVerificationIssue, ...],
    entry_count: int,
    total_uncompressed: int,
    subject_digest: str = "",
    policy_digest: str = "",
    evaluation_digest: str = "",
    ledger_digest: str = "",
    bundle_index_digest: str = "",
    status: str = "",
    upstream_wave12_sha256: str = "",
    upstream_wave12_verification_passed: bool = False,
    external_verification_context_digest: str = "",
    external_verification_count: int = 0,
    metadata: Mapping[str, Any] | None = None,
) -> ReviewBoardPackageVerification:
    return ReviewBoardPackageVerification(
        archive_path=str(archive_path),
        archive_sha256=archive_sha256,
        archive_size_bytes=archive_size_bytes,
        issues=tuple(sorted(issues, key=lambda item: (item.code.value, item.path, item.summary))),
        entry_count=entry_count,
        uncompressed_size_bytes=total_uncompressed,
        subject_digest=subject_digest,
        policy_digest=policy_digest,
        evaluation_digest=evaluation_digest,
        ledger_digest=ledger_digest,
        bundle_index_digest=bundle_index_digest,
        status=status,
        upstream_wave12_sha256=upstream_wave12_sha256,
        upstream_wave12_verification_passed=upstream_wave12_verification_passed,
        external_verification_context_digest=external_verification_context_digest,
        external_verification_count=external_verification_count,
        metadata={} if metadata is None else dict(metadata),
    )


def _issue(
    code: ReviewBoardVerificationIssueCode,
    summary: str,
    *,
    path: str = "",
    metadata: Mapping[str, Any] | None = None,
) -> ReviewBoardVerificationIssue:
    return ReviewBoardVerificationIssue(
        code=code,
        summary=summary,
        path=path,
        metadata={} if metadata is None else dict(metadata),
    )


_STRUCTURAL_CODES = {
    ReviewBoardVerificationIssueCode.TOO_MANY_ENTRIES,
    ReviewBoardVerificationIssueCode.UNSAFE_ENTRY_PATH,
    ReviewBoardVerificationIssueCode.DUPLICATE_ENTRY_PATH,
    ReviewBoardVerificationIssueCode.DIRECTORY_ENTRY,
    ReviewBoardVerificationIssueCode.SYMLINK_ENTRY,
    ReviewBoardVerificationIssueCode.ENTRY_TOO_LARGE,
    ReviewBoardVerificationIssueCode.ARCHIVE_TOO_LARGE,
    ReviewBoardVerificationIssueCode.COMPRESSION_RATIO_EXCEEDED,
    ReviewBoardVerificationIssueCode.REQUIRED_ENTRY_MISSING,
    ReviewBoardVerificationIssueCode.UNEXPECTED_ENTRY_PATH,
}
