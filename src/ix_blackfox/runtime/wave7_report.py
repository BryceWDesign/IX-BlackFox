from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ix_blackfox.runtime.brain_repair import BrainRepairSelectionReport
from ix_blackfox.runtime.brain_repair_evidence import (
    BrainRepairEvidenceExport,
    BrainRepairEvidenceSnapshot,
)
from ix_blackfox.runtime.operator_summary import (
    OperatorSummaryDocument,
    OperatorSummaryFinding,
    OperatorSummaryFindingSeverity,
    OperatorSummarySection,
)
from ix_blackfox.runtime.verification_summary import (
    VerificationEvidence,
    VerificationEvidenceKind,
    VerificationFinding,
    VerificationFindingSeverity,
    VerificationSummary,
    VerificationSummaryStatus,
)


@dataclass(frozen=True, slots=True)
class Wave7ModelRepairReportBundle:
    """
    Paired operator-readable and machine-readable Wave 7 report artifacts.
    """

    operator_summary: OperatorSummaryDocument
    verification_summary: VerificationSummary
    selection_report_digest: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "selection_report_digest",
            _normalize_digest(self.selection_report_digest),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable report bundle.
        """
        return {
            "operator_summary": self.operator_summary.to_dict(),
            "verification_summary": self.verification_summary.to_dict(),
            "selection_report_digest": self.selection_report_digest,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class Wave7ModelRepairReportRenderer:
    """
    Human-reviewable reporting layer for Wave 7 model repair evidence.

    The renderer intentionally reports Wave 7 selection as bounded evidence. It
    never claims a patch was applied, tests passed, production readiness exists,
    or autonomous approval was granted.
    """

    product_name: str = "IX-BlackFox"

    def render(
        self,
        *,
        run_id: str,
        task_id: str,
        contract_id: str,
        selection_report: BrainRepairSelectionReport,
        evidence_export: BrainRepairEvidenceExport | None = None,
        ledger_snapshot: BrainRepairEvidenceSnapshot | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Wave7ModelRepairReportBundle:
        """
        Render paired operator and verification summaries for Wave 7 evidence.
        """
        normalized_run_id = _normalize_identifier(run_id, label="run_id")
        normalized_task_id = _normalize_identifier(task_id, label="task_id")
        normalized_contract_id = _normalize_identifier(contract_id, label="contract_id")
        report_payload = selection_report.to_dict()
        report_digest = _digest_payload(report_payload)
        merged_metadata = {
            "renderer": "wave7-model-repair-report",
            "product_name": self.product_name,
            "summary_type": "wave7_model_repair",
            "contract_id": normalized_contract_id,
            "selection_report_digest": report_digest,
            **dict(metadata or {}),
        }

        operator_summary = self._operator_summary(
            run_id=normalized_run_id,
            task_id=normalized_task_id,
            selection_report=selection_report,
            selection_report_digest=report_digest,
            evidence_export=evidence_export,
            ledger_snapshot=ledger_snapshot,
            metadata=merged_metadata,
        )
        verification_summary = self._verification_summary(
            run_id=normalized_run_id,
            task_id=normalized_task_id,
            contract_id=normalized_contract_id,
            selection_report=selection_report,
            selection_report_digest=report_digest,
            evidence_export=evidence_export,
            ledger_snapshot=ledger_snapshot,
            metadata=merged_metadata,
        )
        return Wave7ModelRepairReportBundle(
            operator_summary=operator_summary,
            verification_summary=verification_summary,
            selection_report_digest=report_digest,
            metadata=merged_metadata,
        )

    def _operator_summary(
        self,
        *,
        run_id: str,
        task_id: str,
        selection_report: BrainRepairSelectionReport,
        selection_report_digest: str,
        evidence_export: BrainRepairEvidenceExport | None,
        ledger_snapshot: BrainRepairEvidenceSnapshot | None,
        metadata: Mapping[str, Any],
    ) -> OperatorSummaryDocument:
        report_payload = selection_report.to_dict()
        findings = tuple(
            _operator_findings(
                selection_report=selection_report,
                evidence_export=evidence_export,
                ledger_snapshot=ledger_snapshot,
            )
        )
        status = _operator_status(selection_report=selection_report, export=evidence_export)
        selected_source_id = _optional_string(report_payload["selected_source_id"])
        selected_brain_name = _optional_string(report_payload["selected_brain_name"])
        sections = (
            OperatorSummarySection(
                title="Wave 7 Model Selection Outcome",
                body=_selection_outcome_markdown(
                    selected_source_id=selected_source_id,
                    selected_brain_name=selected_brain_name,
                    report=selection_report,
                    selection_report_digest=selection_report_digest,
                ),
            ),
            OperatorSummarySection(
                title="Comparison Evidence",
                body=_comparison_markdown(selection_report),
            ),
            OperatorSummarySection(
                title="Separated Review Evidence",
                body=_tribunal_markdown(selection_report),
            ),
            OperatorSummarySection(
                title="Evidence Chain",
                body=_evidence_chain_markdown(
                    evidence_export=evidence_export,
                    ledger_snapshot=ledger_snapshot,
                ),
            ),
            OperatorSummarySection(
                title="Human Review Boundaries",
                body=(
                    "Wave 7 can select an untrusted model-generated proposal for "
                    "downstream governed review, but it does not authorize file "
                    "changes, test success claims, production release, certification, "
                    "or autonomous execution. A human reviewer remains the authority."
                ),
            ),
        )
        return OperatorSummaryDocument(
            title="IX-BlackFox Wave 7 Model Repair Operator Report",
            run_id=run_id,
            task_id=task_id,
            status=status,
            executive_summary=_operator_executive_summary(
                selected_source_id=selected_source_id,
                selected_brain_name=selected_brain_name,
                selection_report=selection_report,
                evidence_export=evidence_export,
            ),
            sections=sections,
            findings=findings,
            metadata=dict(metadata),
        )

    def _verification_summary(
        self,
        *,
        run_id: str,
        task_id: str,
        contract_id: str,
        selection_report: BrainRepairSelectionReport,
        selection_report_digest: str,
        evidence_export: BrainRepairEvidenceExport | None,
        ledger_snapshot: BrainRepairEvidenceSnapshot | None,
        metadata: Mapping[str, Any],
    ) -> VerificationSummary:
        evidence = tuple(
            _verification_evidence(
                selection_report=selection_report,
                selection_report_digest=selection_report_digest,
                evidence_export=evidence_export,
                ledger_snapshot=ledger_snapshot,
            )
        )
        findings = tuple(
            _verification_findings(
                selection_report=selection_report,
                evidence_export=evidence_export,
                ledger_snapshot=ledger_snapshot,
                evidence=evidence,
            )
        )
        status = _verification_status(
            selection_report=selection_report,
            evidence_export=evidence_export,
        )
        return VerificationSummary(
            summary_id=f"wave7-verification-{run_id}",
            run_id=run_id,
            task_id=task_id,
            status=status,
            objective="Verify Wave 7 model-agnostic repair-selection evidence.",
            conclusion=_verification_conclusion(status, contract_id=contract_id),
            evidence=evidence,
            findings=findings,
            metadata=dict(metadata),
        )


def _operator_findings(
    *,
    selection_report: BrainRepairSelectionReport,
    evidence_export: BrainRepairEvidenceExport | None,
    ledger_snapshot: BrainRepairEvidenceSnapshot | None,
) -> tuple[OperatorSummaryFinding, ...]:
    findings: list[OperatorSummaryFinding] = []
    payload = selection_report.to_dict()

    if selection_report.blocked:
        findings.append(
            OperatorSummaryFinding(
                code="wave7.selection_blocked",
                severity=OperatorSummaryFindingSeverity.ERROR,
                summary="Wave 7 model repair selection was blocked.",
                detail="No model proposal should be released downstream from this report.",
            )
        )
    else:
        findings.append(
            OperatorSummaryFinding(
                code="wave7.selection_recorded",
                severity=OperatorSummaryFindingSeverity.PASS,
                summary="Wave 7 selected one model repair proposal for downstream governed review.",
                detail=(
                    f"Selected source `{payload['selected_source_id']}` from "
                    f"brain `{payload['selected_brain_name']}`."
                ),
            )
        )

    if selection_report.review_routed:
        findings.append(
            OperatorSummaryFinding(
                code="wave7.review_routed",
                severity=OperatorSummaryFindingSeverity.PASS,
                summary="Separated tribunal review was routed.",
                detail="The selected generator was not the sole reviewer of its own output.",
            )
        )
    else:
        findings.append(
            OperatorSummaryFinding(
                code="wave7.review_not_routed",
                severity=OperatorSummaryFindingSeverity.ERROR,
                summary="Separated tribunal review was not routed.",
                detail="Do not trust the selected proposal without human review and corrected role separation.",
            )
        )

    if evidence_export is None:
        findings.append(
            OperatorSummaryFinding(
                code="wave7.export_missing",
                severity=OperatorSummaryFindingSeverity.WARNING,
                summary="No Wave 7 evidence export was attached to this operator report.",
            )
        )
    elif evidence_export.chain_valid:
        findings.append(
            OperatorSummaryFinding(
                code="wave7.export_chain_valid",
                severity=OperatorSummaryFindingSeverity.PASS,
                summary="Wave 7 evidence export chain was valid when rendered.",
                detail=f"Export digest: `{evidence_export.digest}`.",
            )
        )
    else:
        findings.append(
            OperatorSummaryFinding(
                code="wave7.export_chain_invalid",
                severity=OperatorSummaryFindingSeverity.ERROR,
                summary="Wave 7 evidence export chain was invalid when rendered.",
            )
        )

    if ledger_snapshot is not None:
        findings.append(
            OperatorSummaryFinding(
                code="wave7.ledger_snapshot_present",
                severity=OperatorSummaryFindingSeverity.INFO,
                summary="Wave 7 repair evidence ledger snapshot was attached.",
                detail=f"Snapshot contains {len(ledger_snapshot.receipts)} receipt(s).",
            )
        )

    return tuple(findings)


def _verification_evidence(
    *,
    selection_report: BrainRepairSelectionReport,
    selection_report_digest: str,
    evidence_export: BrainRepairEvidenceExport | None,
    ledger_snapshot: BrainRepairEvidenceSnapshot | None,
) -> tuple[VerificationEvidence, ...]:
    evidence = [
        VerificationEvidence(
            evidence_id="wave7-selection-report",
            kind=VerificationEvidenceKind.GENERIC,
            summary="Wave 7 model-repair selection report was rendered.",
            sha256=selection_report_digest,
            metadata={
                "selected_source_id": selection_report.to_dict()["selected_source_id"],
                "selected_brain_name": selection_report.to_dict()["selected_brain_name"],
                "record_count": len(selection_report.records),
                "comparison_result_count": len(selection_report.comparison_decision.results),
                "blocked": selection_report.blocked,
                "review_routed": selection_report.review_routed,
            },
        )
    ]

    if selection_report.tribunal_decision is not None:
        tribunal_payload = selection_report.tribunal_decision.to_dict()
        tribunal_findings = tribunal_payload.get("findings", ())
        finding_count = len(tribunal_findings) if isinstance(tribunal_findings, list) else 0
        evidence.append(
            VerificationEvidence(
                evidence_id="wave7-tribunal-decision",
                kind=VerificationEvidenceKind.GENERIC,
                summary="Wave 7 separated-review tribunal decision was rendered.",
                sha256=_digest_payload(tribunal_payload),
                metadata={
                    "disposition": tribunal_payload["disposition"],
                    "selected_brain_name": tribunal_payload["selected_brain_name"],
                    "finding_count": finding_count,
                },
            )
        )

    if evidence_export is not None:
        evidence.append(
            VerificationEvidence(
                evidence_id="wave7-evidence-export",
                kind=VerificationEvidenceKind.GENERIC,
                summary="Wave 7 evidence export artifact was recorded.",
                reference=str(evidence_export.path),
                sha256=evidence_export.digest,
                metadata={
                    "chain_valid": evidence_export.chain_valid,
                    "receipt_id": evidence_export.receipt.receipt_id,
                    "event_type": evidence_export.receipt.event_type.value,
                },
            )
        )

    if ledger_snapshot is not None:
        evidence.append(
            VerificationEvidence(
                evidence_id="wave7-ledger-snapshot",
                kind=VerificationEvidenceKind.GENERIC,
                summary="Wave 7 evidence ledger snapshot was rendered.",
                sha256=_digest_payload(ledger_snapshot.to_dict()),
                metadata={"receipt_count": len(ledger_snapshot.receipts)},
            )
        )

    return tuple(evidence)


def _verification_findings(
    *,
    selection_report: BrainRepairSelectionReport,
    evidence_export: BrainRepairEvidenceExport | None,
    ledger_snapshot: BrainRepairEvidenceSnapshot | None,
    evidence: tuple[VerificationEvidence, ...],
) -> tuple[VerificationFinding, ...]:
    evidence_ids = tuple(item.evidence_id for item in evidence)
    findings: list[VerificationFinding] = []

    if selection_report.blocked:
        findings.append(
            VerificationFinding(
                code="wave7.selection_blocked",
                severity=VerificationFindingSeverity.ERROR,
                summary="Wave 7 selection evidence is blocked.",
                detail="No selected raw model proposal may be released from this selection report.",
                evidence_ids=evidence_ids,
            )
        )
    else:
        findings.append(
            VerificationFinding(
                code="wave7.selection_available",
                severity=VerificationFindingSeverity.PASS,
                summary="Wave 7 selected proposal evidence is available.",
                detail="This verifies proposal selection evidence only, not patch correctness or test success.",
                evidence_ids=("wave7-selection-report",),
            )
        )

    if selection_report.review_routed:
        findings.append(
            VerificationFinding(
                code="wave7.separated_review_routed",
                severity=VerificationFindingSeverity.PASS,
                summary="Separated review evidence was routed.",
                evidence_ids=("wave7-tribunal-decision",)
                if selection_report.tribunal_decision is not None
                else (),
            )
        )
    else:
        findings.append(
            VerificationFinding(
                code="wave7.separated_review_missing",
                severity=VerificationFindingSeverity.ERROR,
                summary="Separated review evidence is missing or blocked.",
                evidence_ids=evidence_ids,
            )
        )

    if evidence_export is None:
        findings.append(
            VerificationFinding(
                code="wave7.export_missing",
                severity=VerificationFindingSeverity.WARNING,
                summary="No Wave 7 export artifact was attached.",
                detail="CI should attach the JSON evidence export for durable review.",
            )
        )
    elif evidence_export.chain_valid:
        findings.append(
            VerificationFinding(
                code="wave7.export_chain_valid",
                severity=VerificationFindingSeverity.PASS,
                summary="Wave 7 evidence export chain was valid.",
                evidence_ids=("wave7-evidence-export",),
            )
        )
    else:
        findings.append(
            VerificationFinding(
                code="wave7.export_chain_invalid",
                severity=VerificationFindingSeverity.ERROR,
                summary="Wave 7 evidence export chain was invalid.",
                evidence_ids=("wave7-evidence-export",),
            )
        )

    if ledger_snapshot is not None and not ledger_snapshot.receipts:
        findings.append(
            VerificationFinding(
                code="wave7.ledger_empty",
                severity=VerificationFindingSeverity.WARNING,
                summary="Wave 7 ledger snapshot was attached but empty.",
            )
        )

    findings.append(
        VerificationFinding(
            code="wave7.no_certification_claim",
            severity=VerificationFindingSeverity.INFO,
            summary="Wave 7 reporting does not certify production readiness.",
            detail="The evidence supports bounded model-selection review only.",
            evidence_ids=evidence_ids,
        )
    )
    return tuple(findings)


def _operator_status(
    *,
    selection_report: BrainRepairSelectionReport,
    export: BrainRepairEvidenceExport | None,
) -> str:
    if selection_report.blocked or not selection_report.review_routed:
        return "wave7-blocked"
    if export is not None and not export.chain_valid:
        return "wave7-evidence-error"
    return "wave7-review-ready"


def _verification_status(
    *,
    selection_report: BrainRepairSelectionReport,
    evidence_export: BrainRepairEvidenceExport | None,
) -> VerificationSummaryStatus:
    if selection_report.blocked or not selection_report.review_routed:
        return VerificationSummaryStatus.BLOCKED
    if evidence_export is not None and not evidence_export.chain_valid:
        return VerificationSummaryStatus.FAILED
    return VerificationSummaryStatus.PARTIAL


def _verification_conclusion(
    status: VerificationSummaryStatus,
    *,
    contract_id: str,
) -> str:
    if status is VerificationSummaryStatus.BLOCKED:
        return (
            "Wave 7 model repair selection was blocked or lacked separated review. "
            "No selected proposal should be trusted for downstream execution."
        )
    if status is VerificationSummaryStatus.FAILED:
        return (
            "Wave 7 evidence export failed chain validation. Operator review is "
            "required before relying on the report."
        )
    return (
        "Wave 7 model repair selection evidence is review-ready for contract "
        f"`{contract_id}`. This is partial verification only: it does not prove "
        "patch correctness, test success, production readiness, or certification."
    )


def _operator_executive_summary(
    *,
    selected_source_id: str | None,
    selected_brain_name: str | None,
    selection_report: BrainRepairSelectionReport,
    evidence_export: BrainRepairEvidenceExport | None,
) -> str:
    if selection_report.blocked:
        return (
            "Wave 7 model-repair selection was blocked. No model-generated repair "
            "proposal should be released downstream until role separation, comparison, "
            "and human-review evidence are corrected."
        )

    export_text = (
        "No evidence export was attached."
        if evidence_export is None
        else f"Evidence export chain valid: `{evidence_export.chain_valid}`."
    )
    return (
        "Wave 7 selected one model-generated repair proposal for downstream "
        f"governed review: source `{selected_source_id}` from brain "
        f"`{selected_brain_name}`. {export_text} Human authority is still required."
    )


def _selection_outcome_markdown(
    *,
    selected_source_id: str | None,
    selected_brain_name: str | None,
    report: BrainRepairSelectionReport,
    selection_report_digest: str,
) -> str:
    return "\n".join(
        [
            f"- Selected source: `{selected_source_id or 'n/a'}`",
            f"- Selected brain: `{selected_brain_name or 'n/a'}`",
            f"- Blocked: `{report.blocked}`",
            f"- Review routed: `{report.review_routed}`",
            f"- Candidate record count: `{len(report.records)}`",
            f"- Comparison result count: `{len(report.comparison_decision.results)}`",
            f"- Selection report digest: `{selection_report_digest}`",
        ]
    )


def _comparison_markdown(report: BrainRepairSelectionReport) -> str:
    lines = [
        f"- Comparison ID: `{report.comparison_decision.request.comparison_id}`",
        f"- Selected comparison brain: `{report.comparison_decision.selected_brain_name or 'n/a'}`",
        "",
        "### Candidate Results",
    ]
    for result in report.comparison_decision.results:
        lines.extend(
            [
                f"- `{result.candidate.brain_name}`: `{result.disposition.value}` "
                f"score `{result.candidate.score.total}` rank `{result.rank or 'n/a'}`",
                f"  - Reasons: {', '.join(result.reasons)}",
            ]
        )
    return "\n".join(lines)


def _tribunal_markdown(report: BrainRepairSelectionReport) -> str:
    decision = report.tribunal_decision
    if decision is None:
        return "No tribunal decision was attached."

    lines = [
        f"- Disposition: `{decision.disposition.value}`",
        f"- Selected reviewer brain: `{decision.selected_brain_name or 'n/a'}`",
        f"- Finding count: `{len(decision.findings)}`",
        "",
        "### Tribunal Findings",
    ]
    for finding in decision.findings:
        lines.append(
            f"- `{finding.assignment.assignment_id}` eligible `{finding.eligible}`"
        )
        if finding.reasons:
            lines.append(f"  - Reasons: {', '.join(finding.reasons)}")
    return "\n".join(lines)


def _evidence_chain_markdown(
    *,
    evidence_export: BrainRepairEvidenceExport | None,
    ledger_snapshot: BrainRepairEvidenceSnapshot | None,
) -> str:
    if evidence_export is None and ledger_snapshot is None:
        return "No Wave 7 evidence export or ledger snapshot was attached."

    lines: list[str] = []
    if evidence_export is not None:
        lines.extend(
            [
                f"- Export path: `{evidence_export.path}`",
                f"- Export digest: `{evidence_export.digest}`",
                f"- Export chain valid: `{evidence_export.chain_valid}`",
                f"- Export receipt: `{evidence_export.receipt.receipt_id}`",
            ]
        )
    if ledger_snapshot is not None:
        lines.append(f"- Ledger receipt count: `{len(ledger_snapshot.receipts)}`")
        latest = ledger_snapshot.receipts[-1] if ledger_snapshot.receipts else None
        if latest is not None:
            lines.append(f"- Latest ledger receipt: `{latest.receipt_id}`")
    return "\n".join(lines)


def _digest_payload(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_digest(value: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) != 64:
        raise ValueError("selection_report_digest must be 64 lowercase hex characters.")
    int(cleaned, 16)
    return cleaned


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError("Expected string or None value in selection report payload.")
    return value


Wave7ModelRepairOperatorReportRenderer = Wave7ModelRepairReportRenderer
