from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/#-]*$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")


class SandboxSignatureAlgorithm(StrEnum):
    HMAC_SHA256 = auto()


class SandboxSignatureVerificationSeverity(StrEnum):
    ERROR = auto()
    WARNING = auto()


@dataclass(frozen=True, slots=True)
class SandboxSignatureVerificationIssue:
    code: str
    severity: SandboxSignatureVerificationSeverity
    summary: str
    location: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _normalize_id(self.code, label="code"))
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "location", _normalize_text(self.location, label="location"))

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "summary": self.summary,
            "location": self.location,
        }


@dataclass(frozen=True, slots=True)
class SandboxSignedArtifactStatement:
    statement_id: str
    subject_uri: str
    subject_sha256: str
    subject_size_bytes: int
    head_sha: str
    signer_id: str
    algorithm: SandboxSignatureAlgorithm
    created_at: datetime
    signature: str
    profile_digest: str | None = None
    artifact_manifest_digest: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "statement_id", _normalize_id(self.statement_id, label="statement_id"))
        object.__setattr__(self, "subject_uri", _normalize_uri(self.subject_uri))
        object.__setattr__(self, "subject_sha256", _normalize_sha256(self.subject_sha256, label="subject_sha256"))
        if self.subject_size_bytes <= 0:
            raise ValueError("subject_size_bytes must be greater than zero.")
        object.__setattr__(self, "head_sha", _normalize_sha(self.head_sha, label="head_sha"))
        object.__setattr__(self, "signer_id", _normalize_id(self.signer_id, label="signer_id"))
        _require_aware_datetime(self.created_at, label="created_at")
        object.__setattr__(self, "signature", _normalize_sha256(self.signature, label="signature"))
        object.__setattr__(
            self,
            "profile_digest",
            _normalize_optional_sha256(self.profile_digest, label="profile_digest"),
        )
        object.__setattr__(
            self,
            "artifact_manifest_digest",
            _normalize_optional_sha256(
                self.artifact_manifest_digest,
                label="artifact_manifest_digest",
            ),
        )
        object.__setattr__(self, "metadata", _normalize_str_mapping(self.metadata, label="metadata"))

    @property
    def body_digest(self) -> str:
        return _sha256_json(self.body_dict())

    @property
    def statement_digest(self) -> str:
        return _sha256_json(self.to_dict(include_digest=False))

    def body_dict(self) -> dict[str, Any]:
        return {
            "statement_id": self.statement_id,
            "subject_uri": self.subject_uri,
            "subject_sha256": self.subject_sha256,
            "subject_size_bytes": self.subject_size_bytes,
            "head_sha": self.head_sha,
            "signer_id": self.signer_id,
            "algorithm": self.algorithm.value,
            "created_at": self.created_at.isoformat(),
            "profile_digest": self.profile_digest,
            "artifact_manifest_digest": self.artifact_manifest_digest,
            "metadata": dict(sorted(self.metadata.items())),
        }

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload = self.body_dict()
        payload["signature"] = self.signature
        payload["body_digest"] = self.body_digest
        if include_digest:
            payload["statement_digest"] = self.statement_digest
        return payload


@dataclass(frozen=True, slots=True)
class SandboxArtifactSigner:
    signer_id: str
    key: bytes
    algorithm: SandboxSignatureAlgorithm = SandboxSignatureAlgorithm.HMAC_SHA256

    def __post_init__(self) -> None:
        object.__setattr__(self, "signer_id", _normalize_id(self.signer_id, label="signer_id"))
        if not self.key:
            raise ValueError("signing key must not be empty.")

    def sign(
        self,
        *,
        statement_id: str,
        subject_uri: str,
        subject_sha256: str,
        subject_size_bytes: int,
        head_sha: str,
        profile_digest: str | None = None,
        artifact_manifest_digest: str | None = None,
        created_at: datetime | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> SandboxSignedArtifactStatement:
        issued_at = created_at if created_at is not None else datetime.now(tz=UTC)
        _require_aware_datetime(issued_at, label="created_at")
        normalized_statement_id = _normalize_id(statement_id, label="statement_id")
        normalized_subject_uri = _normalize_uri(subject_uri)
        normalized_subject_sha256 = _normalize_sha256(subject_sha256, label="subject_sha256")
        if subject_size_bytes <= 0:
            raise ValueError("subject_size_bytes must be greater than zero.")
        normalized_head_sha = _normalize_sha(head_sha, label="head_sha")
        normalized_profile_digest = _normalize_optional_sha256(profile_digest, label="profile_digest")
        normalized_manifest_digest = _normalize_optional_sha256(
            artifact_manifest_digest,
            label="artifact_manifest_digest",
        )
        normalized_metadata = _normalize_str_mapping(metadata if metadata is not None else {}, label="metadata")
        body = {
            "statement_id": normalized_statement_id,
            "subject_uri": normalized_subject_uri,
            "subject_sha256": normalized_subject_sha256,
            "subject_size_bytes": subject_size_bytes,
            "head_sha": normalized_head_sha,
            "signer_id": self.signer_id,
            "algorithm": self.algorithm.value,
            "created_at": issued_at.isoformat(),
            "profile_digest": normalized_profile_digest,
            "artifact_manifest_digest": normalized_manifest_digest,
            "metadata": normalized_metadata,
        }
        signature = _hmac_sha256(self.key, body)
        return SandboxSignedArtifactStatement(
            statement_id=normalized_statement_id,
            subject_uri=normalized_subject_uri,
            subject_sha256=normalized_subject_sha256,
            subject_size_bytes=subject_size_bytes,
            head_sha=normalized_head_sha,
            signer_id=self.signer_id,
            algorithm=self.algorithm,
            created_at=issued_at,
            signature=signature,
            profile_digest=normalized_profile_digest,
            artifact_manifest_digest=normalized_manifest_digest,
            metadata=normalized_metadata,
        )


@dataclass(frozen=True, slots=True)
class SandboxSignatureVerificationReport:
    statement_id: str
    verified_at: datetime
    issues: tuple[SandboxSignatureVerificationIssue, ...] = field(default_factory=tuple)
    statement_digest: str | None = None
    body_digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "statement_id", _normalize_id(self.statement_id, label="statement_id"))
        _require_aware_datetime(self.verified_at, label="verified_at")
        object.__setattr__(self, "issues", tuple(self.issues))
        object.__setattr__(
            self,
            "statement_digest",
            _normalize_optional_sha256(self.statement_digest, label="statement_digest"),
        )
        object.__setattr__(
            self,
            "body_digest",
            _normalize_optional_sha256(self.body_digest, label="body_digest"),
        )

    @property
    def passed(self) -> bool:
        return not any(issue.severity is SandboxSignatureVerificationSeverity.ERROR for issue in self.issues)

    @property
    def error_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity is SandboxSignatureVerificationSeverity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity is SandboxSignatureVerificationSeverity.WARNING)

    @property
    def issue_codes(self) -> tuple[str, ...]:
        return tuple(issue.code for issue in self.issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "statement_id": self.statement_id,
            "verified_at": self.verified_at.isoformat(),
            "passed": self.passed,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "issue_codes": list(self.issue_codes),
            "statement_digest": self.statement_digest,
            "body_digest": self.body_digest,
            "issues": [issue.to_dict() for issue in self.issues],
        }


@dataclass(frozen=True, slots=True)
class SandboxArtifactSignatureVerifier:
    allowed_signer_ids: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "allowed_signer_ids",
            _normalize_id_tuple(self.allowed_signer_ids, label="allowed_signer_ids"),
        )

    def verify(
        self,
        statement: SandboxSignedArtifactStatement,
        *,
        keyring: Mapping[str, bytes],
        expected_head_sha: str | None = None,
        expected_subject_sha256: str | None = None,
        expected_artifact_manifest_digest: str | None = None,
    ) -> SandboxSignatureVerificationReport:
        issues: list[SandboxSignatureVerificationIssue] = []
        normalized_keyring = _normalize_keyring(keyring)

        if self.allowed_signer_ids and statement.signer_id not in self.allowed_signer_ids:
            issues.append(
                _error(
                    "wave6.signature.signer_not_allowed",
                    f"Signer '{statement.signer_id}' is not in the allowed signer set.",
                    "statement.signer_id",
                )
            )

        key = normalized_keyring.get(statement.signer_id)
        if key is None:
            issues.append(
                _error(
                    "wave6.signature.unknown_signer",
                    f"No verification key exists for signer '{statement.signer_id}'.",
                    "keyring",
                )
            )
        else:
            expected_signature = _hmac_sha256(key, statement.body_dict())
            if not hmac.compare_digest(expected_signature, statement.signature):
                issues.append(
                    _error(
                        "wave6.signature.invalid",
                        "Signed artifact statement signature does not match the canonical statement body.",
                        "statement.signature",
                    )
                )

        if expected_head_sha is not None:
            normalized_head = _normalize_sha(expected_head_sha, label="expected_head_sha")
            if statement.head_sha != normalized_head:
                issues.append(
                    _error(
                        "wave6.signature.head_sha_mismatch",
                        f"Statement head SHA '{statement.head_sha}' does not match expected head SHA '{normalized_head}'.",
                        "statement.head_sha",
                    )
                )

        if expected_subject_sha256 is not None:
            normalized_subject = _normalize_sha256(expected_subject_sha256, label="expected_subject_sha256")
            if statement.subject_sha256 != normalized_subject:
                issues.append(
                    _error(
                        "wave6.signature.subject_digest_mismatch",
                        "Statement subject digest does not match the expected artifact digest.",
                        "statement.subject_sha256",
                    )
                )

        if expected_artifact_manifest_digest is not None:
            normalized_manifest = _normalize_sha256(
                expected_artifact_manifest_digest,
                label="expected_artifact_manifest_digest",
            )
            if statement.artifact_manifest_digest != normalized_manifest:
                issues.append(
                    _error(
                        "wave6.signature.artifact_manifest_digest_mismatch",
                        "Statement artifact manifest digest does not match the expected manifest digest.",
                        "statement.artifact_manifest_digest",
                    )
                )

        return SandboxSignatureVerificationReport(
            statement_id=statement.statement_id,
            verified_at=datetime.now(tz=UTC),
            issues=tuple(issues),
            statement_digest=statement.statement_digest,
            body_digest=statement.body_digest,
        )


def _hmac_sha256(key: bytes, payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, encoded, hashlib.sha256).hexdigest()


def _sha256_json(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _error(
    code: str,
    summary: str,
    location: str,
) -> SandboxSignatureVerificationIssue:
    return SandboxSignatureVerificationIssue(
        code=code,
        severity=SandboxSignatureVerificationSeverity.ERROR,
        summary=summary,
        location=location,
    )


def _normalize_id_tuple(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    normalized = tuple(_normalize_id(value, label=label) for value in values)
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{label} must not contain duplicates.")
    return normalized


def _normalize_keyring(keyring: Mapping[str, bytes]) -> dict[str, bytes]:
    normalized: dict[str, bytes] = {}
    for signer_id, key in keyring.items():
        normalized_signer_id = _normalize_id(signer_id, label="signer_id")
        if not key:
            raise ValueError("verification keys must not be empty.")
        normalized[normalized_signer_id] = key
    return normalized


def _normalize_id(value: str, *, label: str) -> str:
    cleaned = _normalize_text(value, label=label)
    if not _SAFE_ID_RE.fullmatch(cleaned):
        raise ValueError(f"{label} contains unsupported characters.")
    if ".." in cleaned:
        raise ValueError(f"{label} must not contain '..'.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_uri(value: str) -> str:
    cleaned = _normalize_text(value.replace("\\", "/"), label="subject_uri")
    if cleaned.startswith(("http://", "https://")):
        return cleaned
    if cleaned.startswith("/") or ".." in cleaned:
        raise ValueError("subject_uri must be relative or an http(s) URI and must not contain '..'.")
    return cleaned


def _normalize_sha(value: str, *, label: str) -> str:
    cleaned = _normalize_text(value.lower(), label=label)
    if not _HEX_SHA_RE.fullmatch(cleaned):
        raise ValueError(f"{label} must be a hexadecimal commit identifier.")
    return cleaned


def _normalize_sha256(value: str, *, label: str) -> str:
    cleaned = _normalize_text(value.lower(), label=label)
    if not _SHA256_RE.fullmatch(cleaned):
        raise ValueError(f"{label} must be a 64-character lowercase SHA-256 digest.")
    return cleaned


def _normalize_optional_sha256(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    return _normalize_sha256(value, label=label)


def _normalize_str_mapping(values: Mapping[str, str], *, label: str) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in values.items():
        normalized[_normalize_id(key, label=f"{label}_key")] = _normalize_text(value, label=f"{label}_value")
    return dict(sorted(normalized.items()))


def _require_aware_datetime(value: datetime, *, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware.")
