from __future__ import annotations

from dataclasses import dataclass, field

from ix_blackfox.governance import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalState,
    ApprovalStatus,
)
from ix_blackfox.kernel import TaskRecord
from ix_blackfox.runtime.governance import RuntimeGovernancePreflightResult


@dataclass(frozen=True, slots=True)
class RuntimeApprovalResolution:
    """
    Immutable runtime approval resolution result.

    This structure converts raw approval artifacts supplied with a task
    into normalized governance approval state so the runtime can decide
    whether a review-gated task may proceed.
    """

    required: bool
    satisfied: bool
    approvals: tuple[ApprovalState, ...] = field(default_factory=tuple)
    issues: tuple[str, ...] = field(default_factory=tuple)

    @property
    def approval_ids(self) -> tuple[str, ...]:
        return tuple(state.request.approval_id for state in self.approvals)

    def to_dict(self) -> dict[str, object]:
        return {
            "required": self.required,
            "satisfied": self.satisfied,
            "approval_ids": self.approval_ids,
            "issues": list(self.issues),
            "approvals": [
                {
                    "approval_id": state.request.approval_id,
                    "intent_id": state.request.intent_id,
                    "status": state.current_status().value,
                    "requested_by": state.request.requested_by,
                    "requested_at": state.request.requested_at.isoformat(),
                    "policy_reason": state.request.policy_reason,
                    "evidence_refs": list(state.request.evidence_refs),
                    "decided_by": None if state.decision is None else state.decision.decided_by,
                    "decided_at": (
                        None if state.decision is None else state.decision.decided_at.isoformat()
                    ),
                    "decision_note": None if state.decision is None else state.decision.note,
                }
                for state in self.approvals
            ],
        }


class RuntimeApprovalResolver:
    """
    Resolve runtime approval artifacts from task metadata.

    Tasks may provide raw approval artifacts under the metadata key
    ``governance_approvals``. This resolver normalizes those artifacts
    into approval requests and terminal decisions that the runtime can
    use to satisfy review-gated governance paths.
    """

    def resolve(
        self,
        *,
        task: TaskRecord,
        preflight: RuntimeGovernancePreflightResult,
    ) -> RuntimeApprovalResolution:
        if not preflight.requires_review:
            return RuntimeApprovalResolution(
                required=False,
                satisfied=True,
                approvals=(),
                issues=(),
            )

        metadata = _request_metadata(task)
        raw_entries = metadata.get("governance_approvals", ())
        approvals: list[ApprovalState] = []
        issues: list[str] = []

        if raw_entries is None:
            raw_entries = ()

        if not isinstance(raw_entries, (list, tuple)):
            issues.append(
                "Task metadata field 'governance_approvals' must be a list or tuple of mappings."
            )
            raw_entries = ()

        for index, raw_entry in enumerate(raw_entries):
            if not isinstance(raw_entry, dict):
                issues.append(
                    f"Approval artifact at index {index} is not a mapping and was ignored."
                )
                continue

            try:
                approvals.append(
                    _build_approval_state(
                        preflight=preflight,
                        raw_entry=raw_entry,
                    )
                )
            except ValueError as exc:
                issues.append(f"Approval artifact at index {index} is invalid: {exc}")

        satisfied = any(
            state.current_status() == ApprovalStatus.APPROVED
            for state in approvals
            if state.request.intent_id == preflight.intent.intent_id
        )

        return RuntimeApprovalResolution(
            required=True,
            satisfied=satisfied,
            approvals=tuple(approvals),
            issues=tuple(issues),
        )


def _build_approval_state(
    *,
    preflight: RuntimeGovernancePreflightResult,
    raw_entry: dict[str, object],
) -> ApprovalState:
    status = _coerce_status(raw_entry.get("status", "approved"))
    requested_by = _coerce_optional_text(raw_entry.get("requested_by")) or "runtime.approval"
    decided_by = _coerce_optional_text(raw_entry.get("decided_by")) or requested_by
    note = _coerce_optional_text(raw_entry.get("note")) or (
        "Runtime approval artifact accepted for governed execution."
    )
    evidence_refs = _coerce_refs(raw_entry.get("evidence_refs", ()))

    request = ApprovalRequest.create(
        intent_id=preflight.intent.intent_id,
        summary=f"Approval for task '{preflight.intent.task_id}' runtime execution.",
        rationale=preflight.decision.rationale,
        policy_reason=preflight.decision.reason.value,
        requested_by=requested_by,
        evidence_refs=evidence_refs,
        metadata={
            "source": "runtime.metadata",
            "task_id": preflight.intent.task_id,
            "ticket_id": preflight.ticket.ticket_id,
        },
    )

    if status == ApprovalStatus.PENDING:
        return ApprovalState(request=request)

    decision = ApprovalDecision.create(
        approval_id=request.approval_id,
        intent_id=request.intent_id,
        status=status,
        decided_by=decided_by,
        note=note,
        evidence_refs=evidence_refs,
    )
    return ApprovalState(
        request=request,
        decision=decision,
    )


def _coerce_status(raw_value: object) -> ApprovalStatus:
    value = str(raw_value).strip().lower()
    if not value:
        raise ValueError("approval status must not be empty")
    try:
        return ApprovalStatus(value)
    except ValueError as exc:
        raise ValueError(
            "approval status must be one of: pending, approved, rejected, canceled"
        ) from exc


def _coerce_optional_text(raw_value: object) -> str | None:
    if raw_value is None:
        return None
    value = str(raw_value).strip()
    return value or None


def _coerce_refs(raw_value: object) -> tuple[str, ...]:
    if raw_value is None:
        return ()

    if not isinstance(raw_value, (list, tuple)):
        raise ValueError("evidence_refs must be a list or tuple of strings")

    normalized: list[str] = []
    seen: set[str] = set()

    for raw_item in raw_value:
        value = str(raw_item).strip()
        if not value:
            continue
        if value not in seen:
            normalized.append(value)
            seen.add(value)

    return tuple(normalized)


def _request_metadata(task: TaskRecord) -> dict[str, object]:
    request = task.request

    raw_input = getattr(request, "input", None)
    raw_input_metadata = getattr(raw_input, "metadata", None)
    if isinstance(raw_input_metadata, dict):
        return dict(raw_input_metadata)

    raw_request_metadata = getattr(request, "metadata", None)
    if isinstance(raw_request_metadata, dict):
        return dict(raw_request_metadata)

    return {}
