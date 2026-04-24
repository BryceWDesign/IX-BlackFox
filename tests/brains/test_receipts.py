from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ix_blackfox.brains import (
    BrainFailure,
    BrainFailureKind,
    BrainInvocationReceiptLedger,
    BrainInvocationRequest,
    BrainInvocationResult,
    BrainInvocationStatus,
    BrainModality,
    BrainRole,
)
from ix_blackfox.runtime.receipts import (
    RuntimeGovernanceReceiptRecorder,
    RuntimeGovernanceReceiptReport,
)


def test_brain_receipt_ledger_records_successful_invocation() -> None:
    ledger = BrainInvocationReceiptLedger()
    request = BrainInvocationRequest.create(
        brain_name=" GPT OSS 20B ",
        role=BrainRole.PRIMARY,
        prompt="Solve the task.",
        task_id=" Task 123 ",
        pack_name=" Programming ",
        input_modalities=(BrainModality.TEXT, BrainModality.TEXT),
        metadata={"temperature": 0},
    )
    result = BrainInvocationResult(
        invocation_id=request.invocation_id,
        brain_name=request.brain_name,
        status=BrainInvocationStatus.SUCCEEDED,
        output_text="Patch prepared.",
        output_modalities=(BrainModality.TEXT, BrainModality.TEXT),
        metadata={"finish_reason": "stop"},
    )

    started_at = datetime(2026, 4, 23, 12, 0, tzinfo=UTC)
    completed_at = started_at + timedelta(milliseconds=850)

    receipt = ledger.append(
        request=request,
        result=result,
        provider_name=" Ollama ",
        model_name="  gpt-oss:20b  ",
        started_at=started_at,
        completed_at=completed_at,
        input_tokens=120,
        output_tokens=80,
        escalation_reason=" verification_retry ",
        safety_labels=(" safe ", "safe", "low-risk"),
        metadata={"operator": "local-dev"},
    )

    assert receipt.receipt_id.startswith("brain-receipt-")
    assert receipt.invocation_id == request.invocation_id
    assert receipt.brain_name == "gpt-oss-20b"
    assert receipt.provider_name == "ollama"
    assert receipt.model_name == "gpt-oss:20b"
    assert receipt.task_id == "task-123"
    assert receipt.pack_name == "programming"
    assert receipt.input_modalities == (BrainModality.TEXT,)
    assert receipt.output_modalities == (BrainModality.TEXT,)
    assert receipt.latency_ms == 850
    assert receipt.input_tokens == 120
    assert receipt.output_tokens == 80
    assert receipt.total_tokens == 200
    assert receipt.escalation_reason == "verification_retry"
    assert receipt.safety_labels == ("safe", "low-risk")
    assert receipt.metadata["operator"] == "local-dev"
    assert receipt.metadata["request"] == {"temperature": 0}
    assert receipt.metadata["result"] == {"finish_reason": "stop"}
    assert ledger.count() == 1


def test_brain_receipt_snapshot_filters_by_task_invocation_and_brain() -> None:
    ledger = BrainInvocationReceiptLedger()

    first_request = BrainInvocationRequest.create(
        brain_name="gpt-oss-20b",
        role=BrainRole.PRIMARY,
        prompt="One",
        task_id="task-a",
        pack_name="programming",
    )
    first_result = BrainInvocationResult(
        invocation_id=first_request.invocation_id,
        brain_name=first_request.brain_name,
        status=BrainInvocationStatus.SUCCEEDED,
        output_text="done",
        output_modalities=(BrainModality.TEXT,),
    )

    second_request = BrainInvocationRequest.create(
        brain_name="qwen3.5-vision",
        role=BrainRole.MULTIMODAL,
        prompt="Two",
        task_id="task-b",
        pack_name="architecture",
        input_modalities=(BrainModality.TEXT, BrainModality.IMAGE),
    )
    second_result = BrainInvocationResult(
        invocation_id=second_request.invocation_id,
        brain_name=second_request.brain_name,
        status=BrainInvocationStatus.REFUSED,
        output_text=None,
        output_modalities=(),
        failure=BrainFailure(
            kind=BrainFailureKind.POLICY_BLOCKED,
            message="Refused by safety policy.",
        ),
    )

    ledger.append(
        request=first_request,
        result=first_result,
        provider_name="ollama",
        model_name="gpt-oss:20b",
    )
    ledger.append(
        request=second_request,
        result=second_result,
        provider_name="vllm",
        model_name="Qwen3.5-27B",
        safety_labels=("review",),
    )

    snapshot = ledger.snapshot()

    assert len(snapshot.filter_by_task("task-a")) == 1
    assert len(snapshot.filter_by_invocation(first_request.invocation_id)) == 1
    assert len(snapshot.filter_by_brain(" qwen3.5 vision ")) == 1


def test_brain_receipt_ledger_rejects_mismatched_request_and_result() -> None:
    ledger = BrainInvocationReceiptLedger()
    request = BrainInvocationRequest.create(
        brain_name="gpt-oss-20b",
        role=BrainRole.PRIMARY,
        prompt="Solve",
    )
    result = BrainInvocationResult(
        invocation_id="brain-call-mismatch",
        brain_name=request.brain_name,
        status=BrainInvocationStatus.SUCCEEDED,
        output_text="done",
        output_modalities=(BrainModality.TEXT,),
    )

    with pytest.raises(ValueError, match="same invocation_id"):
        ledger.append(
            request=request,
            result=result,
            provider_name="ollama",
            model_name="gpt-oss:20b",
        )


def test_runtime_receipt_report_can_attach_brain_receipts() -> None:
    ledger = BrainInvocationReceiptLedger()
    request = BrainInvocationRequest.create(
        brain_name="gpt-oss-20b",
        role=BrainRole.PRIMARY,
        prompt="Solve",
        task_id="task-123",
        pack_name="programming",
    )
    result = BrainInvocationResult(
        invocation_id=request.invocation_id,
        brain_name=request.brain_name,
        status=BrainInvocationStatus.SUCCEEDED,
        output_text="done",
        output_modalities=(BrainModality.TEXT,),
    )
    ledger.append(
        request=request,
        result=result,
        provider_name="ollama",
        model_name="gpt-oss:20b",
    )

    report = RuntimeGovernanceReceiptReport(
        intent_id="intent-123",
        chain_verified=True,
        receipt_count=2,
        records=(
            {
                "receipt_id": "receipt-1",
                "intent_id": "intent-123",
                "event_type": "policy_allowed",
                "summary": "Allowed.",
                "previous_receipt_id": None,
                "previous_chain_digest": None,
                "chain_digest": "abc",
                "created_at": "2026-04-23T12:00:00+00:00",
                "actor": "runtime.governance",
                "metadata": {},
            },
        ),
    )

    recorder = RuntimeGovernanceReceiptRecorder()
    updated = recorder.attach_brain_receipts(
        report=report,
        ledger=ledger,
        task_id="task-123",
    )

    assert updated.brain_receipt_count == 1
    assert updated.brain_receipts[0]["brain_name"] == "gpt-oss-20b"
    assert updated.brain_receipts[0]["provider_name"] == "ollama"
    assert updated.to_dict()["brain_receipt_count"] == 1
