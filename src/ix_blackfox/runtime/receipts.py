from __future__ import annotations

from dataclasses import dataclass, field, replace

from ix_blackfox.brains.receipts import BrainInvocationReceipt, BrainInvocationReceiptLedger
from ix_blackfox.governance import (
    ApprovalStatus,
    GovernanceReceiptLedger,
    GovernanceReceiptRecord,
    ReceiptEventType,
)
from ix_blackfox.runtime.approval import RuntimeApprovalResolution
from ix_blackfox.runtime.governance import RuntimeGovernancePreflightResult


@dataclass(frozen=True, slots=True)
class RuntimeGovernanceReceiptReport:
    """
    Immutable persisted view of runtime governance receipts.
    """

    intent_id: str
    chain_verified: bool
    receipt_count: int
    records: tuple[dict[str, object], ...]
    artifact_path: str | None = None
    brain_receipt_count: int = 0
    brain_receipts: tuple[dict[str, object], ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "intent_id": self.intent_id,
            "chain_verified": self.chain_verified,
            "receipt_count": self.receipt_count,
            "records": list(self.records),
            "artifact_path": self.artifact_path,
            "brain_receipt_count": self.brain_receipt_count,
            "brain_receipts": list(self.brain_receipts),
        }


class RuntimeGovernanceReceiptRecorder:
    """
    Runtime-facing receipt recorder for governed execution flows.

    The recorder translates runtime decisions into the lower-level
    governance receipt ledger so a full reviewable chain exists across:
    - governance preflight
    - approval resolution
    - execution start/outcome
    - verification outcome
    """

    def create_ledger(self) -> GovernanceReceiptLedger:
        return GovernanceReceiptLedger()

    def record_preflight(
        self,
        *,
        ledger: GovernanceReceiptLedger,
        preflight: RuntimeGovernancePreflightResult,
    ) -> str:
        event_type = _map_preflight_event(preflight=preflight)
        record = ledger.append(
            intent_id=preflight.intent.intent_id,
            event_type=event_type,
            summary=preflight.decision.rationale,
            actor="runtime.governance",
            metadata={
                "ticket_id": preflight.ticket.ticket_id,
                "ticket_disposition": preflight.ticket.disposition.value,
                "policy_decision": preflight.decision.decision.value,
                "policy_reason": preflight.decision.reason.value,
                "risk_level": preflight.risk.risk_level.value,
            },
        )
        return record.receipt_id

    def record_approval_resolution(
        self,
        *,
        ledger: GovernanceReceiptLedger,
        preflight: RuntimeGovernancePreflightResult,
        resolution: RuntimeApprovalResolution,
    ) -> str | None:
        if not resolution.required:
            return None

        if resolution.satisfied:
            record = ledger.append(
                intent_id=preflight.intent.intent_id,
                event_type=ReceiptEventType.APPROVAL_RECORDED,
                summary="Governance approval satisfied the runtime review gate.",
                actor="runtime.approval",
                metadata={
                    "approval_ids": list(resolution.approval_ids),
                    "issues": list(resolution.issues),
                },
            )
            return record.receipt_id

        if any(
            state.current_status() in {ApprovalStatus.REJECTED, ApprovalStatus.CANCELED}
            for state in resolution.approvals
        ):
            record = ledger.append(
                intent_id=preflight.intent.intent_id,
                event_type=ReceiptEventType.APPROVAL_REJECTED,
                summary="Governance approval explicitly rejected the runtime review gate.",
                actor="runtime.approval",
                metadata={
                    "approval_ids": list(resolution.approval_ids),
                    "issues": list(resolution.issues),
                },
            )
            return record.receipt_id

        return None

    def record_execution_started(
        self,
        *,
        ledger: GovernanceReceiptLedger,
        preflight: RuntimeGovernancePreflightResult,
        pack_name: str,
    ) -> str:
        record = ledger.append(
            intent_id=preflight.intent.intent_id,
            event_type=ReceiptEventType.EXECUTION_STARTED,
            summary=f"Runtime pack execution started for '{pack_name}'.",
            actor="runtime.orchestrator",
            metadata={
                "pack_name": pack_name,
                "task_id": preflight.intent.task_id,
            },
        )
        return record.receipt_id

    def record_execution_completed(
        self,
        *,
        ledger: GovernanceReceiptLedger,
        preflight: RuntimeGovernancePreflightResult,
        pack_name: str,
        artifact_count: int,
    ) -> str:
        record = ledger.append(
            intent_id=preflight.intent.intent_id,
            event_type=ReceiptEventType.EXECUTION_COMPLETED,
            summary=f"Runtime pack execution completed for '{pack_name}'.",
            actor="runtime.orchestrator",
            metadata={
                "pack_name": pack_name,
                "artifact_count": artifact_count,
                "task_id": preflight.intent.task_id,
            },
        )
        return record.receipt_id

    def record_execution_failed(
        self,
        *,
        ledger: GovernanceReceiptLedger,
        preflight: RuntimeGovernancePreflightResult,
        pack_name: str,
        error: str,
    ) -> str:
        record = ledger.append(
            intent_id=preflight.intent.intent_id,
            event_type=ReceiptEventType.EXECUTION_FAILED,
            summary=f"Runtime pack execution failed for '{pack_name}'.",
            actor="runtime.orchestrator",
            metadata={
                "pack_name": pack_name,
                "error": error,
                "task_id": preflight.intent.task_id,
            },
        )
        return record.receipt_id

    def record_verification_outcome(
        self,
        *,
        ledger: GovernanceReceiptLedger,
        preflight: RuntimeGovernancePreflightResult,
        verification_status: str,
        issue_count: int,
    ) -> str | None:
        normalized_status = verification_status.strip().lower()
        if normalized_status == "passed":
            event_type = ReceiptEventType.VERIFICATION_PASSED
            summary = "Runtime verification passed for the governed run."
        elif normalized_status == "failed":
            event_type = ReceiptEventType.VERIFICATION_FAILED
            summary = "Runtime verification failed for the governed run."
        else:
            return None

        record = ledger.append(
            intent_id=preflight.intent.intent_id,
            event_type=event_type,
            summary=summary,
            actor="runtime.verification",
            metadata={
                "verification_status": normalized_status,
                "issue_count": issue_count,
                "task_id": preflight.intent.task_id,
            },
        )
        return record.receipt_id

    def report_from_ledger(
        self,
        *,
        ledger: GovernanceReceiptLedger,
        intent_id: str,
        artifact_path: str | None = None,
    ) -> RuntimeGovernanceReceiptReport:
        snapshot = ledger.snapshot()
        records = snapshot.filter_by_intent(intent_id)
        return RuntimeGovernanceReceiptReport(
            intent_id=intent_id,
            chain_verified=ledger.verify_intent_chain(intent_id),
            receipt_count=len(records),
            records=tuple(_record_to_dict(record) for record in records),
            artifact_path=artifact_path,
        )

    def attach_brain_receipts(
        self,
        *,
        report: RuntimeGovernanceReceiptReport,
        ledger: BrainInvocationReceiptLedger | None,
        task_id: str | None,
    ) -> RuntimeGovernanceReceiptReport:
        """
        Attach task-scoped brain invocation receipts to a governance report.
        """
        if ledger is None or task_id is None:
            return report

        snapshot = ledger.snapshot()
        brain_receipts = snapshot.filter_by_task(task_id)
        return replace(
            report,
            brain_receipt_count=len(brain_receipts),
            brain_receipts=tuple(
                _brain_receipt_to_dict(receipt) for receipt in brain_receipts
            ),
        )


def _map_preflight_event(
    *,
    preflight: RuntimeGovernancePreflightResult,
) -> ReceiptEventType:
    decision = preflight.decision.decision.value
    if decision == "allow":
        return ReceiptEventType.POLICY_ALLOWED
    if decision == "require_review":
        return ReceiptEventType.POLICY_REVIEW_REQUIRED
    return ReceiptEventType.POLICY_BLOCKED


def _record_to_dict(record: GovernanceReceiptRecord) -> dict[str, object]:
    return {
        "receipt_id": record.receipt_id,
        "intent_id": record.intent_id,
        "event_type": record.event_type.value,
        "summary": record.summary,
        "previous_receipt_id": record.previous_receipt_id,
        "previous_chain_digest": record.previous_chain_digest,
        "chain_digest": record.chain_digest,
        "created_at": record.created_at.isoformat(),
        "actor": record.actor,
        "metadata": dict(record.metadata),
    }


def _brain_receipt_to_dict(receipt: BrainInvocationReceipt) -> dict[str, object]:
    return receipt.to_dict()
