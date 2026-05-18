from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.sandbox.contracts import SandboxBackendKind
from ix_blackfox.sandbox.egress import SandboxEgressDecision
from ix_blackfox.sandbox.receipt import SandboxReceiptBundle

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/#-]*$")


class SandboxAdversarialScenarioKind(StrEnum):
    DENY_ALL_EGRESS = auto()
    UNEXPECTED_EGRESS_ALLOWANCE = auto()
    RECEIPT_BUNDLE_ACCEPTANCE = auto()
    RECEIPT_BUNDLE_REJECTION = auto()
    PATH_ESCAPE_BLOCK = auto()
    SYMLINK_BLOCK = auto()
    POLICY_EXCEPTION_BLOCK = auto()


class SandboxAdversarialOutcome(StrEnum):
    DEFENSE_PASSED = auto()
    DEFENSE_FAILED = auto()


@dataclass(frozen=True, slots=True)
class SandboxAdversarialFinding:
    code: str
    summary: str
    location: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _normalize_id(self.code, label="code"))
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "location", _normalize_text(self.location, label="location"))

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "summary": self.summary,
            "location": self.location,
        }


@dataclass(frozen=True, slots=True)
class SandboxAdversarialScenarioResult:
    scenario_id: str
    kind: SandboxAdversarialScenarioKind
    outcome: SandboxAdversarialOutcome
    summary: str
    evidence_digest: str
    evaluated_at: datetime
    findings: tuple[SandboxAdversarialFinding, ...] = field(default_factory=tuple)
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "scenario_id", _normalize_id(self.scenario_id, label="scenario_id"))
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "evidence_digest", _normalize_sha256(self.evidence_digest))
        _require_aware_datetime(self.evaluated_at, label="evaluated_at")
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metadata", _normalize_str_mapping(self.metadata, label="metadata"))

    @property
    def passed(self) -> bool:
        return self.outcome is SandboxAdversarialOutcome.DEFENSE_PASSED

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "kind": self.kind.value,
            "outcome": self.outcome.value,
            "passed": self.passed,
            "summary": self.summary,
            "evidence_digest": self.evidence_digest,
            "evaluated_at": self.evaluated_at.isoformat(),
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": dict(sorted(self.metadata.items())),
        }


@dataclass(frozen=True, slots=True)
class SandboxAdversarialReport:
    report_id: str
    created_at: datetime
    results: tuple[SandboxAdversarialScenarioResult, ...]
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "report_id", _normalize_id(self.report_id, label="report_id"))
        _require_aware_datetime(self.created_at, label="created_at")
        object.__setattr__(self, "results", tuple(sorted(self.results, key=lambda result: result.scenario_id)))
        object.__setattr__(self, "metadata", _normalize_str_mapping(self.metadata, label="metadata"))
        scenario_ids = tuple(result.scenario_id for result in self.results)
        if len(set(scenario_ids)) != len(scenario_ids):
            raise ValueError("adversarial report must not contain duplicate scenario_id values.")

    @property
    def passed(self) -> bool:
        return bool(self.results) and all(result.passed for result in self.results)

    @property
    def scenario_count(self) -> int:
        return len(self.results)

    @property
    def passed_count(self) -> int:
        return sum(1 for result in self.results if result.passed)

    @property
    def failed_count(self) -> int:
        return sum(1 for result in self.results if not result.passed)

    @property
    def digest(self) -> str:
        return _sha256_json(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "report_id": self.report_id,
            "created_at": self.created_at.isoformat(),
            "passed": self.passed,
            "scenario_count": self.scenario_count,
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "results": [result.to_dict() for result in self.results],
            "metadata": dict(sorted(self.metadata.items())),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class SandboxAdversarialHarness:
    allowed_hardened_backends: tuple[SandboxBackendKind, ...] = (
        SandboxBackendKind.CONTAINER,
        SandboxBackendKind.GVISOR,
        SandboxBackendKind.FIRECRACKER,
    )
    require_artifact_manifest_digest: bool = True
    require_egress_audit_bundle_digest: bool = True

    def expect_egress_denied(
        self,
        decision: SandboxEgressDecision,
        *,
        scenario_id: str,
    ) -> SandboxAdversarialScenarioResult:
        finding = None
        if decision.allowed:
            finding = SandboxAdversarialFinding(
                code="wave6.adversarial.egress_unexpectedly_allowed",
                summary="Egress decision allowed traffic that the adversarial scenario expected to be denied.",
                location=f"egress.{decision.decision_id}.allowed",
            )
        return _scenario_result(
            scenario_id=scenario_id,
            kind=SandboxAdversarialScenarioKind.DENY_ALL_EGRESS,
            passed=finding is None,
            summary="Deny-all egress probe was blocked."
            if finding is None
            else "Deny-all egress probe was unexpectedly allowed.",
            evidence=decision.to_dict(),
            findings=() if finding is None else (finding,),
            metadata={"decision_id": decision.decision_id},
        )

    def expect_receipt_bundle_accepted(
        self,
        receipt_bundle: SandboxReceiptBundle,
        *,
        scenario_id: str,
    ) -> SandboxAdversarialScenarioResult:
        findings = _receipt_bundle_rejection_findings(
            receipt_bundle,
            allowed_hardened_backends=self.allowed_hardened_backends,
            require_artifact_manifest_digest=self.require_artifact_manifest_digest,
            require_egress_audit_bundle_digest=self.require_egress_audit_bundle_digest,
        )
        return _scenario_result(
            scenario_id=scenario_id,
            kind=SandboxAdversarialScenarioKind.RECEIPT_BUNDLE_ACCEPTANCE,
            passed=not findings,
            summary="Sandbox receipt bundle satisfies hardened Wave 6 evidence requirements."
            if not findings
            else "Sandbox receipt bundle failed hardened Wave 6 evidence requirements.",
            evidence=receipt_bundle.to_dict(),
            findings=findings,
            metadata={"bundle_id": receipt_bundle.bundle_id},
        )

    def expect_receipt_bundle_rejected(
        self,
        receipt_bundle: SandboxReceiptBundle,
        *,
        scenario_id: str,
    ) -> SandboxAdversarialScenarioResult:
        findings = _receipt_bundle_rejection_findings(
            receipt_bundle,
            allowed_hardened_backends=self.allowed_hardened_backends,
            require_artifact_manifest_digest=self.require_artifact_manifest_digest,
            require_egress_audit_bundle_digest=self.require_egress_audit_bundle_digest,
        )
        return _scenario_result(
            scenario_id=scenario_id,
            kind=SandboxAdversarialScenarioKind.RECEIPT_BUNDLE_REJECTION,
            passed=bool(findings),
            summary="Adversarial receipt bundle was rejected as expected."
            if findings
            else "Adversarial receipt bundle was not rejected.",
            evidence=receipt_bundle.to_dict(),
            findings=findings,
            metadata={"bundle_id": receipt_bundle.bundle_id},
        )

    def expect_exception_blocked(
        self,
        error: BaseException | None,
        *,
        scenario_id: str,
        kind: SandboxAdversarialScenarioKind,
        required_message_fragments: tuple[str, ...],
    ) -> SandboxAdversarialScenarioResult:
        findings: tuple[SandboxAdversarialFinding, ...]
        if error is None:
            findings = (
                SandboxAdversarialFinding(
                    code="wave6.adversarial.expected_exception_missing",
                    summary="Expected policy/security exception was not raised.",
                    location="exception",
                ),
            )
            passed = False
            summary = "Expected policy/security exception was not raised."
        else:
            message = str(error).lower()
            missing_fragments = tuple(
                fragment
                for fragment in required_message_fragments
                if fragment.lower() not in message
            )
            if missing_fragments:
                findings = (
                    SandboxAdversarialFinding(
                        code="wave6.adversarial.exception_message_mismatch",
                        summary=f"Exception was raised, but did not include required fragments: {missing_fragments}.",
                        location="exception.message",
                    ),
                )
                passed = False
                summary = "Exception did not match the expected block reason."
            else:
                findings = ()
                passed = True
                summary = "Expected policy/security exception was raised."
        return _scenario_result(
            scenario_id=scenario_id,
            kind=kind,
            passed=passed,
            summary=summary,
            evidence={
                "error_type": type(error).__name__ if error is not None else None,
                "error_message": str(error) if error is not None else None,
                "required_message_fragments": list(required_message_fragments),
            },
            findings=findings,
            metadata={"expectation": "exception-block"},
        )

    def report(
        self,
        *,
        report_id: str,
        results: tuple[SandboxAdversarialScenarioResult, ...],
        metadata: Mapping[str, str] | None = None,
    ) -> SandboxAdversarialReport:
        return SandboxAdversarialReport(
            report_id=report_id,
            created_at=datetime.now(tz=UTC),
            results=results,
            metadata=metadata if metadata is not None else {"wave": "6"},
        )


def _receipt_bundle_rejection_findings(
    receipt_bundle: SandboxReceiptBundle,
    *,
    allowed_hardened_backends: tuple[SandboxBackendKind, ...],
    require_artifact_manifest_digest: bool,
    require_egress_audit_bundle_digest: bool,
) -> tuple[SandboxAdversarialFinding, ...]:
    findings: list[SandboxAdversarialFinding] = []
    if not receipt_bundle.receipts:
        findings.append(
            SandboxAdversarialFinding(
                code="wave6.adversarial.receipt_bundle_empty",
                summary="Sandbox receipt bundle is empty.",
                location="receipts",
            )
        )
    if not receipt_bundle.passed:
        findings.append(
            SandboxAdversarialFinding(
                code="wave6.adversarial.receipt_bundle_failed",
                summary="Sandbox receipt bundle contains failed receipts.",
                location="passed",
            )
        )
    for receipt in receipt_bundle.receipts:
        if receipt.backend is SandboxBackendKind.LOCAL_AUDIT:
            findings.append(
                SandboxAdversarialFinding(
                    code="wave6.adversarial.local_audit_not_hardened",
                    summary=f"Receipt '{receipt.receipt_id}' uses local_audit, which is not hardened Wave 6 evidence.",
                    location=f"receipts.{receipt.receipt_id}.backend",
                )
            )
        if receipt.backend not in allowed_hardened_backends:
            findings.append(
                SandboxAdversarialFinding(
                    code="wave6.adversarial.backend_not_allowed",
                    summary=f"Receipt '{receipt.receipt_id}' uses disallowed backend '{receipt.backend.value}'.",
                    location=f"receipts.{receipt.receipt_id}.backend",
                )
            )
        if receipt.expected_head_sha != receipt_bundle.expected_head_sha:
            findings.append(
                SandboxAdversarialFinding(
                    code="wave6.adversarial.receipt_head_sha_mismatch",
                    summary=f"Receipt '{receipt.receipt_id}' head SHA does not match the bundle head SHA.",
                    location=f"receipts.{receipt.receipt_id}.expected_head_sha",
                )
            )
        if require_artifact_manifest_digest and receipt.artifact_manifest_digest is None:
            findings.append(
                SandboxAdversarialFinding(
                    code="wave6.adversarial.artifact_manifest_missing",
                    summary=f"Receipt '{receipt.receipt_id}' does not bind an artifact manifest digest.",
                    location=f"receipts.{receipt.receipt_id}.artifact_manifest_digest",
                )
            )
        if require_egress_audit_bundle_digest and receipt.egress_audit_bundle_digest is None:
            findings.append(
                SandboxAdversarialFinding(
                    code="wave6.adversarial.egress_audit_missing",
                    summary=f"Receipt '{receipt.receipt_id}' does not bind an egress audit bundle digest.",
                    location=f"receipts.{receipt.receipt_id}.egress_audit_bundle_digest",
                )
            )
    return tuple(findings)


def _scenario_result(
    *,
    scenario_id: str,
    kind: SandboxAdversarialScenarioKind,
    passed: bool,
    summary: str,
    evidence: Mapping[str, Any],
    findings: tuple[SandboxAdversarialFinding, ...],
    metadata: Mapping[str, str],
) -> SandboxAdversarialScenarioResult:
    return SandboxAdversarialScenarioResult(
        scenario_id=scenario_id,
        kind=kind,
        outcome=SandboxAdversarialOutcome.DEFENSE_PASSED
        if passed
        else SandboxAdversarialOutcome.DEFENSE_FAILED,
        summary=summary,
        evidence_digest=_sha256_json(evidence),
        evaluated_at=datetime.now(tz=UTC),
        findings=findings,
        metadata=metadata,
    )


def _sha256_json(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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


def _normalize_sha256(value: str) -> str:
    cleaned = _normalize_text(value.lower(), label="sha256")
    if len(cleaned) != 64 or any(char not in "0123456789abcdef" for char in cleaned):
        raise ValueError("sha256 must be a 64-character lowercase hexadecimal digest.")
    return cleaned


def _normalize_str_mapping(values: Mapping[str, str], *, label: str) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in values.items():
        normalized[_normalize_id(key, label=f"{label}_key")] = _normalize_text(value, label=f"{label}_value")
    return dict(sorted(normalized.items()))


def _require_aware_datetime(value: datetime, *, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware.")
