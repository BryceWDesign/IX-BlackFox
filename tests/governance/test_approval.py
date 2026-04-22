from __future__ import annotations

import pytest

from ix_blackfox.governance import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    GovernanceApprovalStore,
)


def test_approval_request_create_normalizes_fields() -> None:
    request = ApprovalRequest.create(
        intent_id="  INTENT-123  ",
        summary="  Review governed file mutation.  ",
        rationale="  This action changes tracked runtime code.  ",
        policy_reason="  HIGH RISK REQUIRES REVIEW  ",
        requested_by="  orchestrator.runtime  ",
        required_roles=(" Reviewer ", "Security", "reviewer"),
        evidence_refs=(" trace/run-1.json ", "trace/run-1.json", " policy/decision.json "),
        metadata={"ticket": "OPS-42"},
    )

    assert request.approval_id.startswith("approval-")
    assert request.intent_id == "intent-123"
    assert request.summary == "Review governed file mutation."
    assert request.rationale == "This action changes tracked runtime code."
    assert request.policy_reason == "high-risk-requires-review"
    assert request.requested_by == "orchestrator.runtime"
    assert request.required_roles == ("reviewer", "security")
    assert request.evidence_refs == ("trace/run-1.json", "policy/decision.json")
    assert request.metadata == {"ticket": "OPS-42"}


def test_approval_decision_requires_terminal_status() -> None:
    with pytest.raises(
        ValueError,
        match="terminal status",
    ):
        ApprovalDecision.create(
            approval_id="approval-1",
            intent_id="intent-1",
            status=ApprovalStatus.PENDING,
            decided_by="reviewer.one",
            note="Pending is not a terminal decision.",
        )


def test_approval_store_round_trip_and_resolve(tmp_path) -> None:
    store = GovernanceApprovalStore(root_dir=tmp_path / "approvals")
    request = ApprovalRequest.create(
        intent_id="intent-1",
        summary="Approve controlled source mutation.",
        rationale="Mutates tracked source files under governance.",
        policy_reason="high-risk-requires-review",
        requested_by="orchestrator.runtime",
        required_roles=("maintainer",),
        evidence_refs=("trace/task-1.json",),
    )

    pending_state = store.put_request(request)
    assert pending_state.current_status() == ApprovalStatus.PENDING

    loaded_pending = store.get(request.approval_id)
    assert loaded_pending is not None
    assert loaded_pending.request.approval_id == request.approval_id
    assert loaded_pending.current_status() == ApprovalStatus.PENDING

    decision = ApprovalDecision.create(
        approval_id=request.approval_id,
        intent_id=request.intent_id,
        status=ApprovalStatus.APPROVED,
        decided_by="maintainer.one",
        note="Approved after source review.",
        evidence_refs=("review/approval.txt",),
    )

    resolved = store.resolve(decision)
    assert resolved.current_status() == ApprovalStatus.APPROVED
    assert resolved.decision is not None
    assert resolved.decision.decided_by == "maintainer.one"

    loaded_resolved = store.get(request.approval_id)
    assert loaded_resolved is not None
    assert loaded_resolved.current_status() == ApprovalStatus.APPROVED
    assert loaded_resolved.decision is not None
    assert loaded_resolved.decision.evidence_refs == ("review/approval.txt",)


def test_approval_store_rejects_duplicate_request_id(tmp_path) -> None:
    store = GovernanceApprovalStore(root_dir=tmp_path / "approvals")
    request = ApprovalRequest.create(
        intent_id="intent-2",
        summary="Review runtime state mutation.",
        rationale="Controlled state mutation requires signoff.",
        policy_reason="approval-required",
    )

    store.put_request(request)

    with pytest.raises(ValueError, match="already exists"):
        store.put_request(request)


def test_approval_store_rejects_mismatched_decision_identity(tmp_path) -> None:
    store = GovernanceApprovalStore(root_dir=tmp_path / "approvals")
    request = ApprovalRequest.create(
        intent_id="intent-3",
        summary="Review forge command execution.",
        rationale="Command touches governed workspace.",
        policy_reason="high-risk-requires-review",
    )
    store.put_request(request)

    bad_decision = ApprovalDecision.create(
        approval_id=request.approval_id,
        intent_id="intent-other",
        status=ApprovalStatus.REJECTED,
        decided_by="reviewer.one",
        note="Wrong intent identity.",
    )

    with pytest.raises(ValueError, match="same intent_id"):
        store.resolve(bad_decision)


def test_approval_store_find_by_intent_returns_sorted_matches(tmp_path) -> None:
    store = GovernanceApprovalStore(root_dir=tmp_path / "approvals")
    first = ApprovalRequest.create(
        intent_id="intent-4",
        summary="First review request.",
        rationale="First governed action for the same intent.",
        policy_reason="approval-required",
    )
    second = ApprovalRequest.create(
        intent_id="intent-4",
        summary="Second review request.",
        rationale="Second governed action for the same intent.",
        policy_reason="approval-required",
    )
    other = ApprovalRequest.create(
        intent_id="intent-5",
        summary="Different intent review.",
        rationale="Different governed action.",
        policy_reason="approval-required",
    )

    store.put_request(first)
    store.put_request(second)
    store.put_request(other)

    states = store.find_by_intent("intent-4")

    assert tuple(state.request.approval_id for state in states) == (
        first.approval_id,
        second.approval_id,
    )
