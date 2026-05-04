from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any, Self
from uuid import uuid4

from ix_blackfox.authoring.policy import AuthoringPolicyDecision
from ix_blackfox.runtime.authoring_repair import AuthoredRepairStatus
from ix_blackfox.runtime.control_plane import AuthoredEngineeringControlPlaneReport


class Wave3AcceptanceStatus(StrEnum):
    """
    Terminal acceptance status for a governed Wave 3 authored repair handoff.
    """

    PASSED = auto()
    FAILED = auto()
    REQUIRES_REVIEW = auto()
    BLOCKED = auto()
    NOT_EXECUTED = auto()


class Wave3AcceptanceFindingSeverity(StrEnum):
    """
    Severity for one Wave 3 acceptance finding.
    """

    INFO = auto()
    WARNING = auto()
    ERROR = auto()


class Wave3AcceptanceFindingCode(StrEnum):
    """
    Machine-readable Wave 3 acceptance finding codes.
    """

    ACCEPTANCE_PASSED = auto()
    AUTHORING_BLOCKED = auto()
    AUTHORING_FAILED = auto()
    AUTHORING_NO_CANDIDATE = auto()
    AUTHORING_RECEIPT_CHAIN_INVALID = auto()
    AUTHORING_REQUIRES_REVIEW = auto()
    POLICY_ALLOWED = auto()
    POLICY_BLOCKED = auto()
    POLICY_REQUIRES_REVIEW = auto()
    SELECTED_PATCH_MISSING = auto()
    WAVE2_FAILED = auto()
    WAVE2_NOT_EXECUTED = auto()
    WAVE2_REPORT_MISSING = auto()
    WAVE2_SELECTED_PATCH_MISMATCH = auto()
    WAVE2_SUCCEEDED = auto()


@dataclass(frozen=True, slots=True)
class Wave3AcceptanceFinding:
    """
    One reviewable finding emitted by Wave 3 acceptance validation.
    """

    code: Wave3AcceptanceFindingCode
    severity: Wave3AcceptanceFindingSeverity
    summary: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "summary", _normalize_text(self.summary, label="summary")
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "severity": self.severity.value,
            "summary": self.summary,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            code=Wave3AcceptanceFindingCode(_require_text(payload, "code")),
            severity=Wave3AcceptanceFindingSeverity(_require_text(payload, "severity")),
            summary=_require_text(payload, "summary"),
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )


@dataclass(frozen=True, slots=True)
class Wave3AcceptanceReport:
    """
    Deterministic acceptance report for a Wave 3-authored, Wave 2-executed run.
    """

    report_id: str
    run_id: str
    task_id: str
    status: Wave3AcceptanceStatus
    selected_patch_id: str | None
    selected_candidate_id: str | None
    authoring_status: str
    authoring_chain_digest: str | None
    wave2_executed: bool
    wave2_succeeded: bool
    findings: tuple[Wave3AcceptanceFinding, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "report_id", _normalize_identifier(self.report_id, label="report_id")
        )
        object.__setattr__(
            self, "run_id", _normalize_identifier(self.run_id, label="run_id")
        )
        object.__setattr__(
            self, "task_id", _normalize_identifier(self.task_id, label="task_id")
        )
        object.__setattr__(
            self,
            "selected_patch_id",
            _normalize_optional_identifier(
                self.selected_patch_id, label="selected_patch_id"
            ),
        )
        object.__setattr__(
            self,
            "selected_candidate_id",
            _normalize_optional_identifier(
                self.selected_candidate_id, label="selected_candidate_id"
            ),
        )
        object.__setattr__(
            self,
            "authoring_status",
            _normalize_text(self.authoring_status, label="authoring_status"),
        )
        object.__setattr__(
            self,
            "authoring_chain_digest",
            _normalize_optional_sha256(self.authoring_chain_digest),
        )
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def passed(self) -> bool:
        return self.status is Wave3AcceptanceStatus.PASSED

    @property
    def failed(self) -> bool:
        return self.status is Wave3AcceptanceStatus.FAILED

    @property
    def requires_review(self) -> bool:
        return self.status is Wave3AcceptanceStatus.REQUIRES_REVIEW

    @property
    def blocked(self) -> bool:
        return self.status is Wave3AcceptanceStatus.BLOCKED

    @property
    def not_executed(self) -> bool:
        return self.status is Wave3AcceptanceStatus.NOT_EXECUTED

    @property
    def finding_codes(self) -> tuple[str, ...]:
        return tuple(finding.code.value for finding in self.findings)

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            _canonical_json(self.to_dict(include_digest=False)).encode("utf-8")
        ).hexdigest()

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload = {
            "report_id": self.report_id,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "status": self.status.value,
            "passed": self.passed,
            "failed": self.failed,
            "requires_review": self.requires_review,
            "blocked": self.blocked,
            "not_executed": self.not_executed,
            "selected_patch_id": self.selected_patch_id,
            "selected_candidate_id": self.selected_candidate_id,
            "authoring_status": self.authoring_status,
            "authoring_chain_digest": self.authoring_chain_digest,
            "wave2_executed": self.wave2_executed,
            "wave2_succeeded": self.wave2_succeeded,
            "finding_codes": list(self.finding_codes),
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            report_id=_require_text(payload, "report_id"),
            run_id=_require_text(payload, "run_id"),
            task_id=_require_text(payload, "task_id"),
            status=Wave3AcceptanceStatus(_require_text(payload, "status")),
            selected_patch_id=_optional_text_from_payload(payload, "selected_patch_id"),
            selected_candidate_id=_optional_text_from_payload(
                payload, "selected_candidate_id"
            ),
            authoring_status=_require_text(payload, "authoring_status"),
            authoring_chain_digest=_optional_text_from_payload(
                payload, "authoring_chain_digest"
            ),
            wave2_executed=_require_bool(payload, "wave2_executed"),
            wave2_succeeded=_require_bool(payload, "wave2_succeeded"),
            findings=_load_findings(payload.get("findings", ())),
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )


@dataclass(frozen=True, slots=True)
class Wave3AcceptanceValidatorConfig:
    """
    Validation settings for Wave 3 acceptance.
    """

    require_valid_authoring_receipt_chain: bool = True
    require_wave2_execution_for_authored_success: bool = True
    require_wave2_selected_patch_match: bool = True


@dataclass(frozen=True, slots=True)
class Wave3AcceptanceValidator:
    """
    Validate that a Wave 3-authored patch crossed into Wave 2 safely.
    """

    config: Wave3AcceptanceValidatorConfig = field(
        default_factory=Wave3AcceptanceValidatorConfig
    )

    def validate(
        self, report: AuthoredEngineeringControlPlaneReport
    ) -> Wave3AcceptanceReport:
        findings: list[Wave3AcceptanceFinding] = []
        authored = report.authored_repair_report
        wave2 = report.wave2_report
        selected_candidate = authored.selected_candidate
        selected_patch = authored.selected_patch

        selected_patch_id = None if selected_patch is None else selected_patch.patch_id
        selected_candidate_id = (
            None if selected_candidate is None else selected_candidate.candidate_id
        )

        if (
            self.config.require_valid_authoring_receipt_chain
            and not authored.receipt_snapshot.verify_chain()
        ):
            findings.append(
                _finding(
                    Wave3AcceptanceFindingCode.AUTHORING_RECEIPT_CHAIN_INVALID,
                    Wave3AcceptanceFindingSeverity.ERROR,
                    "Wave 3 authoring receipt chain failed deterministic validation.",
                )
            )

        self._append_authoring_status_findings(
            authored_status=authored.status, findings=findings
        )
        self._append_policy_findings(report=report, findings=findings)
        self._append_wave2_findings(report=report, findings=findings)

        if selected_patch is None and authored.status is AuthoredRepairStatus.AUTHORED:
            findings.append(
                _finding(
                    Wave3AcceptanceFindingCode.SELECTED_PATCH_MISSING,
                    Wave3AcceptanceFindingSeverity.ERROR,
                    "Authoring reported success but no selected patch was present.",
                )
            )

        if (
            self.config.require_wave2_selected_patch_match
            and wave2 is not None
            and selected_patch_id is not None
        ):
            wave2_selected_patch_id = wave2.metadata.get("selected_patch_id")
            if wave2_selected_patch_id != selected_patch_id:
                findings.append(
                    _finding(
                        Wave3AcceptanceFindingCode.WAVE2_SELECTED_PATCH_MISMATCH,
                        Wave3AcceptanceFindingSeverity.ERROR,
                        "Wave 2 metadata selected_patch_id does not match the Wave 3 selected patch.",
                        metadata={
                            "wave3_selected_patch_id": selected_patch_id,
                            "wave2_selected_patch_id": wave2_selected_patch_id,
                        },
                    )
                )

        if not findings:
            findings.append(
                _finding(
                    Wave3AcceptanceFindingCode.ACCEPTANCE_PASSED,
                    Wave3AcceptanceFindingSeverity.INFO,
                    "Wave 3 acceptance passed all configured gates.",
                )
            )

        status = self._status_from_findings(
            authored_status=authored.status,
            wave2_executed=wave2 is not None,
            wave2_succeeded=False if wave2 is None else wave2.succeeded,
            findings=tuple(findings),
        )

        if (
            status is Wave3AcceptanceStatus.PASSED
            and Wave3AcceptanceFindingCode.ACCEPTANCE_PASSED.value
            not in {finding.code.value for finding in findings}
        ):
            findings.insert(
                0,
                _finding(
                    Wave3AcceptanceFindingCode.ACCEPTANCE_PASSED,
                    Wave3AcceptanceFindingSeverity.INFO,
                    "Wave 3 acceptance passed all configured gates.",
                ),
            )

        return Wave3AcceptanceReport(
            report_id=f"wave3-acceptance-report-{uuid4().hex}",
            run_id=report.run_id,
            task_id=report.task_id,
            status=status,
            selected_patch_id=selected_patch_id,
            selected_candidate_id=selected_candidate_id,
            authoring_status=authored.status.value,
            authoring_chain_digest=authored.receipt_snapshot.latest_chain_digest,
            wave2_executed=wave2 is not None,
            wave2_succeeded=False if wave2 is None else wave2.succeeded,
            findings=tuple(findings),
            metadata={
                "validator": "Wave3AcceptanceValidator",
                "wave": 3,
                "authored_succeeded": authored.succeeded,
                "wave2_executed": wave2 is not None,
            },
        )

    def _append_authoring_status_findings(
        self,
        *,
        authored_status: AuthoredRepairStatus,
        findings: list[Wave3AcceptanceFinding],
    ) -> None:
        if authored_status is AuthoredRepairStatus.AUTHORED:
            return
        if authored_status is AuthoredRepairStatus.NO_CANDIDATE:
            findings.append(
                _finding(
                    Wave3AcceptanceFindingCode.AUTHORING_NO_CANDIDATE,
                    Wave3AcceptanceFindingSeverity.WARNING,
                    "Wave 3 authoring produced no selectable candidate.",
                )
            )
            return
        if authored_status is AuthoredRepairStatus.REQUIRES_REVIEW:
            findings.append(
                _finding(
                    Wave3AcceptanceFindingCode.AUTHORING_REQUIRES_REVIEW,
                    Wave3AcceptanceFindingSeverity.WARNING,
                    "Wave 3 authoring required human review before execution.",
                )
            )
            return
        if authored_status is AuthoredRepairStatus.BLOCKED:
            findings.append(
                _finding(
                    Wave3AcceptanceFindingCode.AUTHORING_BLOCKED,
                    Wave3AcceptanceFindingSeverity.ERROR,
                    "Wave 3 authoring was blocked by policy.",
                )
            )
            return
        findings.append(
            _finding(
                Wave3AcceptanceFindingCode.AUTHORING_FAILED,
                Wave3AcceptanceFindingSeverity.ERROR,
                f"Wave 3 authoring ended with status {authored_status.value}.",
            )
        )

    def _append_policy_findings(
        self,
        *,
        report: AuthoredEngineeringControlPlaneReport,
        findings: list[Wave3AcceptanceFinding],
    ) -> None:
        selected_candidate = report.authored_repair_report.selected_ranked_candidate
        if selected_candidate is None:
            return
        policy_report_id = selected_candidate.policy_report_id
        policy_report = next(
            (
                candidate_policy
                for candidate_policy in report.authored_repair_report.policy_reports
                if candidate_policy.report_id == policy_report_id
            ),
            None,
        )
        if policy_report is None:
            return
        if policy_report.decision is AuthoringPolicyDecision.ALLOW:
            findings.append(
                _finding(
                    Wave3AcceptanceFindingCode.POLICY_ALLOWED,
                    Wave3AcceptanceFindingSeverity.INFO,
                    "Selected Wave 3 patch candidate was allowed by authoring policy.",
                )
            )
        elif policy_report.decision is AuthoringPolicyDecision.REQUIRE_REVIEW:
            findings.append(
                _finding(
                    Wave3AcceptanceFindingCode.POLICY_REQUIRES_REVIEW,
                    Wave3AcceptanceFindingSeverity.WARNING,
                    "Selected Wave 3 patch candidate required review by authoring policy.",
                )
            )
        elif policy_report.decision is AuthoringPolicyDecision.BLOCK:
            findings.append(
                _finding(
                    Wave3AcceptanceFindingCode.POLICY_BLOCKED,
                    Wave3AcceptanceFindingSeverity.ERROR,
                    "Selected Wave 3 patch candidate was blocked by authoring policy.",
                )
            )

    def _append_wave2_findings(
        self,
        *,
        report: AuthoredEngineeringControlPlaneReport,
        findings: list[Wave3AcceptanceFinding],
    ) -> None:
        authored = report.authored_repair_report
        wave2 = report.wave2_report
        if wave2 is None:
            findings.append(
                _finding(
                    Wave3AcceptanceFindingCode.WAVE2_REPORT_MISSING,
                    Wave3AcceptanceFindingSeverity.WARNING,
                    "No Wave 2 execution report is attached to the authored run.",
                )
            )
            if (
                self.config.require_wave2_execution_for_authored_success
                and authored.succeeded
            ):
                findings.append(
                    _finding(
                        Wave3AcceptanceFindingCode.WAVE2_NOT_EXECUTED,
                        Wave3AcceptanceFindingSeverity.ERROR,
                        "Authoring selected a patch but Wave 2 did not execute it.",
                    )
                )
            return

        if wave2.succeeded:
            findings.append(
                _finding(
                    Wave3AcceptanceFindingCode.WAVE2_SUCCEEDED,
                    Wave3AcceptanceFindingSeverity.INFO,
                    "Wave 2 patch-test-verify execution succeeded.",
                )
            )
            return

        findings.append(
            _finding(
                Wave3AcceptanceFindingCode.WAVE2_FAILED,
                Wave3AcceptanceFindingSeverity.ERROR,
                "Wave 2 patch-test-verify execution did not succeed.",
            )
        )

    def _status_from_findings(
        self,
        *,
        authored_status: AuthoredRepairStatus,
        wave2_executed: bool,
        wave2_succeeded: bool,
        findings: tuple[Wave3AcceptanceFinding, ...],
    ) -> Wave3AcceptanceStatus:
        codes = {finding.code for finding in findings}

        if (
            Wave3AcceptanceFindingCode.AUTHORING_BLOCKED in codes
            or Wave3AcceptanceFindingCode.POLICY_BLOCKED in codes
        ):
            return Wave3AcceptanceStatus.BLOCKED

        if any(
            finding.severity is Wave3AcceptanceFindingSeverity.ERROR
            for finding in findings
        ):
            return Wave3AcceptanceStatus.FAILED

        if (
            Wave3AcceptanceFindingCode.AUTHORING_REQUIRES_REVIEW in codes
            or Wave3AcceptanceFindingCode.POLICY_REQUIRES_REVIEW in codes
        ):
            return Wave3AcceptanceStatus.REQUIRES_REVIEW

        if not wave2_executed:
            return Wave3AcceptanceStatus.NOT_EXECUTED

        if authored_status is AuthoredRepairStatus.AUTHORED and wave2_succeeded:
            return Wave3AcceptanceStatus.PASSED

        return Wave3AcceptanceStatus.FAILED


def _finding(
    code: Wave3AcceptanceFindingCode,
    severity: Wave3AcceptanceFindingSeverity,
    summary: str,
    *,
    metadata: Mapping[str, Any] | None = None,
) -> Wave3AcceptanceFinding:
    return Wave3AcceptanceFinding(
        code=code,
        severity=severity,
        summary=summary,
        metadata=dict(metadata or {}),
    )


def _load_findings(value: Any) -> tuple[Wave3AcceptanceFinding, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError("findings must be an iterable of mappings.")
    findings: list[Wave3AcceptanceFinding] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise TypeError("findings must contain only mappings.")
        findings.append(Wave3AcceptanceFinding.from_dict(item))
    return tuple(findings)


def _canonical_json(payload: Any) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_identifier(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    return _normalize_identifier(value, label=label)


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_sha256(value: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) != 64 or any(char not in "0123456789abcdef" for char in cleaned):
        raise ValueError("sha256 must be a 64-character lowercase hexadecimal digest.")
    return cleaned


def _normalize_optional_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_sha256(value)


def _coerce_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")
    return dict(value)


def _require_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string.")
    return value


def _optional_text_from_payload(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string or None.")
    return value


def _require_bool(payload: Mapping[str, Any], key: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise TypeError(f"Field {key!r} must be a boolean.")
    return value
