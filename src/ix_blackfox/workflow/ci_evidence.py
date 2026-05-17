from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.workflow.pr_evidence_pack import (
    EvidenceArtifact,
    EvidenceArtifactKind,
    Wave5ValidationIssue,
    Wave5ValidationSeverity,
)

_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/#-]*$")
_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")


class CiCheckStatus(StrEnum):
    QUEUED = auto()
    IN_PROGRESS = auto()
    COMPLETED = auto()
    SKIPPED = auto()
    UNKNOWN = auto()


class CiCheckConclusion(StrEnum):
    SUCCESS = auto()
    FAILURE = auto()
    CANCELLED = auto()
    TIMED_OUT = auto()
    ACTION_REQUIRED = auto()
    NEUTRAL = auto()
    SKIPPED = auto()
    UNKNOWN = auto()


@dataclass(frozen=True, slots=True)
class CiEvidenceRecord:
    check_name: str
    provider: str
    status: CiCheckStatus
    conclusion: CiCheckConclusion
    started_at: datetime | None = None
    completed_at: datetime | None = None
    url: str | None = None
    required: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "check_name", _normalize_text(self.check_name, label="check_name"))
        object.__setattr__(self, "provider", _normalize_token(self.provider, label="provider"))
        if self.started_at is not None:
            _require_aware_datetime(self.started_at, label="started_at")
        if self.completed_at is not None:
            _require_aware_datetime(self.completed_at, label="completed_at")
        if self.started_at is not None and self.completed_at is not None and self.completed_at < self.started_at:
            raise ValueError("completed_at must not be earlier than started_at.")
        object.__setattr__(self, "url", _normalize_optional_url(self.url))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def passed(self) -> bool:
        return self.status is CiCheckStatus.COMPLETED and self.conclusion is CiCheckConclusion.SUCCESS

    @property
    def terminal(self) -> bool:
        return self.status in (CiCheckStatus.COMPLETED, CiCheckStatus.SKIPPED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_name": self.check_name,
            "provider": self.provider,
            "status": self.status.value,
            "conclusion": self.conclusion.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "url": self.url,
            "required": self.required,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class CiEvidenceBundle:
    bundle_id: str
    provider: str
    repository: str
    head_sha: str
    collected_at: datetime
    records: tuple[CiEvidenceRecord, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "bundle_id", _normalize_token(self.bundle_id, label="bundle_id"))
        object.__setattr__(self, "provider", _normalize_token(self.provider, label="provider"))
        object.__setattr__(self, "repository", _normalize_repository(self.repository))
        object.__setattr__(self, "head_sha", _normalize_sha(self.head_sha))
        _require_aware_datetime(self.collected_at, label="collected_at")
        object.__setattr__(self, "records", tuple(self.records))
        object.__setattr__(self, "metadata", dict(self.metadata))
        check_names = tuple(record.check_name for record in self.records)
        if len(set(check_names)) != len(check_names):
            raise ValueError("CI evidence records must have unique check names.")

    @property
    def required_records(self) -> tuple[CiEvidenceRecord, ...]:
        return tuple(record for record in self.records if record.required)

    @property
    def passed_required_records(self) -> tuple[CiEvidenceRecord, ...]:
        return tuple(record for record in self.required_records if record.passed)

    @property
    def failed_required_records(self) -> tuple[CiEvidenceRecord, ...]:
        return tuple(record for record in self.required_records if record.terminal and not record.passed)

    @property
    def pending_required_records(self) -> tuple[CiEvidenceRecord, ...]:
        return tuple(record for record in self.required_records if not record.terminal)

    @property
    def passed(self) -> bool:
        return bool(self.required_records) and len(self.passed_required_records) == len(self.required_records)

    def missing_required_checks(self, required_checks: Sequence[str]) -> tuple[str, ...]:
        present = {record.check_name for record in self.records}
        return tuple(check for check in required_checks if check not in present)

    def to_evidence_artifact(self, *, uri: str, produced_by: str = "blackfox-ci-evidence-ingestion") -> EvidenceArtifact:
        payload = self.to_json()
        return EvidenceArtifact(
            artifact_id=f"ci-summary-{self.bundle_id}",
            kind=EvidenceArtifactKind.CI_SUMMARY,
            uri=uri,
            produced_by=produced_by,
            size_bytes=len(payload.encode("utf-8")),
            metadata={
                "provider": self.provider,
                "repository": self.repository,
                "head_sha": self.head_sha,
                "required_check_count": len(self.required_records),
                "passed_required_check_count": len(self.passed_required_records),
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "provider": self.provider,
            "repository": self.repository,
            "head_sha": self.head_sha,
            "collected_at": self.collected_at.isoformat(),
            "passed": self.passed,
            "required_check_count": len(self.required_records),
            "passed_required_check_count": len(self.passed_required_records),
            "failed_required_checks": [record.check_name for record in self.failed_required_records],
            "pending_required_checks": [record.check_name for record in self.pending_required_records],
            "records": [record.to_dict() for record in self.records],
            "metadata": dict(self.metadata),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class CiEvidenceValidationReport:
    bundle_id: str
    required_checks: tuple[str, ...]
    issues: tuple[Wave5ValidationIssue, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "bundle_id", _normalize_token(self.bundle_id, label="bundle_id"))
        object.__setattr__(self, "required_checks", _normalize_check_names(self.required_checks))
        object.__setattr__(self, "issues", tuple(self.issues))

    @property
    def passed(self) -> bool:
        return not any(issue.severity is Wave5ValidationSeverity.ERROR for issue in self.issues)

    @property
    def error_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity is Wave5ValidationSeverity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity is Wave5ValidationSeverity.WARNING)

    @property
    def issue_codes(self) -> tuple[str, ...]:
        return tuple(issue.code for issue in self.issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "passed": self.passed,
            "required_checks": list(self.required_checks),
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "issue_codes": list(self.issue_codes),
            "issues": [issue.to_dict() for issue in self.issues],
        }


@dataclass(frozen=True, slots=True)
class CiEvidenceValidator:
    required_checks: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "required_checks", _normalize_check_names(self.required_checks))
        if not self.required_checks:
            raise ValueError("required_checks must not be empty.")

    def validate(self, bundle: CiEvidenceBundle) -> CiEvidenceValidationReport:
        issues: list[Wave5ValidationIssue] = []
        if not bundle.records:
            issues.append(
                _error(
                    "wave5.ci_evidence_empty",
                    "CI evidence bundle contains no check records.",
                    "ci.records",
                )
            )
        for check_name in bundle.missing_required_checks(self.required_checks):
            issues.append(
                _error(
                    "wave5.ci_required_check_missing",
                    f"Required CI check '{check_name}' is missing from the evidence bundle.",
                    "ci.required_checks",
                )
            )
        for record in bundle.required_records:
            if record.check_name not in self.required_checks:
                continue
            if record.status is not CiCheckStatus.COMPLETED:
                issues.append(
                    _error(
                        "wave5.ci_required_check_not_completed",
                        f"Required CI check '{record.check_name}' is not completed.",
                        f"ci.records.{record.check_name}.status",
                    )
                )
            elif record.conclusion is not CiCheckConclusion.SUCCESS:
                issues.append(
                    _error(
                        "wave5.ci_required_check_failed",
                        f"Required CI check '{record.check_name}' concluded with '{record.conclusion.value}'.",
                        f"ci.records.{record.check_name}.conclusion",
                    )
                )
        return CiEvidenceValidationReport(
            bundle_id=bundle.bundle_id,
            required_checks=self.required_checks,
            issues=tuple(issues),
        )


class CiEvidenceNormalizer:
    def from_mapping(self, payload: Mapping[str, Any]) -> CiEvidenceBundle:
        records_payload = payload.get("records")
        if not isinstance(records_payload, Sequence) or isinstance(records_payload, (str, bytes)):
            raise ValueError("CI evidence payload must contain a records sequence.")
        return CiEvidenceBundle(
            bundle_id=_require_str(payload, "bundle_id"),
            provider=_require_str(payload, "provider"),
            repository=_require_str(payload, "repository"),
            head_sha=_require_str(payload, "head_sha"),
            collected_at=_parse_datetime(_require_str(payload, "collected_at"), label="collected_at"),
            records=tuple(self.record_from_mapping(record) for record in records_payload),
            metadata=_optional_mapping(payload.get("metadata")),
        )

    def record_from_mapping(self, payload: Any) -> CiEvidenceRecord:
        if not isinstance(payload, Mapping):
            raise ValueError("CI evidence record must be a mapping.")
        return CiEvidenceRecord(
            check_name=_require_str(payload, "check_name"),
            provider=_require_str(payload, "provider"),
            status=_status_from_value(_require_str(payload, "status")),
            conclusion=_conclusion_from_value(_require_str(payload, "conclusion")),
            started_at=_parse_optional_datetime(payload.get("started_at"), label="started_at"),
            completed_at=_parse_optional_datetime(payload.get("completed_at"), label="completed_at"),
            url=_optional_str(payload.get("url"), label="url"),
            required=_optional_bool(payload.get("required"), default=True, label="required"),
            metadata=_optional_mapping(payload.get("metadata")),
        )


def _status_from_value(value: str) -> CiCheckStatus:
    cleaned = value.strip().lower().replace("-", "_")
    try:
        return CiCheckStatus(cleaned)
    except ValueError as exc:
        raise ValueError(f"unsupported CI check status: {value!r}.") from exc


def _conclusion_from_value(value: str) -> CiCheckConclusion:
    cleaned = value.strip().lower().replace("-", "_")
    try:
        return CiCheckConclusion(cleaned)
    except ValueError as exc:
        raise ValueError(f"unsupported CI check conclusion: {value!r}.") from exc


def _parse_optional_datetime(value: Any, *, label: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an ISO datetime string when provided.")
    return _parse_datetime(value, label=label)


def _parse_datetime(value: str, *, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid ISO datetime string.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware.")
    return parsed.astimezone(UTC)


def _require_str(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError(f"CI evidence payload field '{key}' must be a string.")
    return value


def _optional_str(value: Any, *, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string when provided.")
    return value


def _optional_bool(value: Any, *, default: bool, label: str) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean when provided.")
    return value


def _optional_mapping(value: Any) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("metadata must be a mapping when provided.")
    return dict(value)


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_token(value: str, *, label: str) -> str:
    cleaned = _normalize_text(value, label=label)
    if not _SAFE_TOKEN_RE.fullmatch(cleaned):
        raise ValueError(f"{label} contains unsupported characters.")
    if ".." in cleaned:
        raise ValueError(f"{label} must not contain '..'.")
    return cleaned


def _normalize_repository(value: str) -> str:
    cleaned = _normalize_token(value, label="repository")
    if cleaned.startswith("/") or cleaned.endswith("/"):
        raise ValueError("repository must be a stable owner/name token, not an absolute path.")
    return cleaned


def _normalize_sha(value: str) -> str:
    cleaned = _normalize_text(value.lower(), label="head_sha")
    if not _SHA_RE.fullmatch(cleaned):
        raise ValueError("head_sha must be a hexadecimal commit identifier.")
    return cleaned


def _normalize_check_names(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized = tuple(_normalize_text(value, label="check_name") for value in values)
    if len(set(normalized)) != len(normalized):
        raise ValueError("check names must not contain duplicates.")
    return normalized


def _normalize_optional_url(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = _normalize_text(value, label="url")
    if not cleaned.startswith(("http://", "https://")):
        raise ValueError("url must start with http:// or https:// when provided.")
    return cleaned


def _require_aware_datetime(value: datetime, *, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware.")


def _error(code: str, summary: str, location: str) -> Wave5ValidationIssue:
    return Wave5ValidationIssue(code, Wave5ValidationSeverity.ERROR, summary, location)
