from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from ix_blackfox.authoring import (
    AuthoringContextBuilder,
    AuthoringContextBuilderConfig,
    AuthoringEvidence,
    AuthoringEvidenceStrength,
    AuthoringMode,
    AuthoringReceipt,
    AuthoringReceiptEventType,
    AuthoringReceiptLedger,
    AuthoringReceiptSnapshot,
    AuthoringReceiptStatus,
    FailureEvidenceExtractor,
    PatchAuthoringPromptRenderer,
    PatchAuthoringResponseParser,
    PatchProposalCompiler,
    RepairHypothesisEngine,
    RepairTaskDecomposer,
    digest_payload,
)


def test_receipt_digest_and_chain_digest_are_stable() -> None:
    payload = {"value": 1}
    receipt = AuthoringReceipt(
        receipt_id="authoring-receipt-test",
        event_type=AuthoringReceiptEventType.CONTEXT_COLLECTED,
        status=AuthoringReceiptStatus.RECORDED,
        subject_id="request-1",
        payload=payload,
        payload_digest=digest_payload(payload),
        parent_chain_digest=None,
        recorded_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert receipt.receipt_digest == receipt.receipt_digest
    assert receipt.chain_digest == receipt.chain_digest
    assert len(receipt.receipt_digest) == 64
    assert len(receipt.chain_digest) == 64


def test_receipt_rejects_mismatched_payload_digest() -> None:
    with pytest.raises(ValueError, match="payload_digest"):
        AuthoringReceipt(
            receipt_id="authoring-receipt-test",
            event_type=AuthoringReceiptEventType.CONTEXT_COLLECTED,
            status=AuthoringReceiptStatus.RECORDED,
            subject_id="request-1",
            payload={"value": 1},
            payload_digest="0" * 64,
            parent_chain_digest=None,
            recorded_at=datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_ledger_appends_receipts_with_valid_chain() -> None:
    ledger = AuthoringReceiptLedger()

    first = ledger.append(
        event_type=AuthoringReceiptEventType.CONTEXT_COLLECTED,
        subject_id="request-1",
        payload={"context_id": "context-1"},
        recorded_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    second = ledger.append(
        event_type=AuthoringReceiptEventType.EVIDENCE_EXTRACTED,
        subject_id="request-1",
        payload={"evidence_id": "evidence-1"},
        recorded_at=datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC),
    )

    snapshot = ledger.snapshot()

    assert snapshot.count == 2
    assert second.parent_chain_digest == first.chain_digest
    assert snapshot.latest_chain_digest == second.chain_digest
    assert snapshot.verify_chain()


def test_snapshot_filters_and_requires_events() -> None:
    ledger = AuthoringReceiptLedger()
    ledger.append(
        event_type=AuthoringReceiptEventType.CONTEXT_COLLECTED,
        subject_id="request-1",
        payload={"context_id": "context-1"},
    )
    ledger.append(
        event_type=AuthoringReceiptEventType.EVIDENCE_EXTRACTED,
        subject_id="request-2",
        payload={"evidence_id": "evidence-1"},
    )

    snapshot = ledger.snapshot()

    assert len(snapshot.filter_by_event(AuthoringReceiptEventType.CONTEXT_COLLECTED)) == 1
    assert len(snapshot.filter_by_subject("request-1")) == 1
    assert snapshot.require_event(AuthoringReceiptEventType.CONTEXT_COLLECTED).subject_id == "request-1"
    assert snapshot.has_event(AuthoringReceiptEventType.EVIDENCE_EXTRACTED)

    with pytest.raises(LookupError, match="Missing required"):
        snapshot.require_event(AuthoringReceiptEventType.PATCH_COMPILED)


def test_snapshot_round_trip_preserves_chain() -> None:
    ledger = AuthoringReceiptLedger()
    ledger.append(
        event_type=AuthoringReceiptEventType.CONTEXT_COLLECTED,
        subject_id="request-1",
        payload={"context_id": "context-1"},
        recorded_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    ledger.append(
        event_type=AuthoringReceiptEventType.EVIDENCE_EXTRACTED,
        subject_id="request-1",
        payload={"evidence_id": "evidence-1"},
        recorded_at=datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC),
    )

    restored = AuthoringReceiptSnapshot.from_dict(ledger.snapshot().to_dict())

    assert restored.count == 2
    assert restored.verify_chain()
    assert restored.latest_chain_digest == ledger.snapshot().latest_chain_digest


def test_record_context_and_evidence_receipts(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()
    (workspace / "src" / "example.py").write_text("VALUE = 1\n", encoding="utf-8")

    context_snapshot = AuthoringContextBuilder(
        workspace_root=workspace,
        config=AuthoringContextBuilderConfig(include_paths=("src",)),
    ).build()
    evidence_report = FailureEvidenceExtractor().from_objective_only(
        objective="Repair the reported behavior."
    )

    ledger = AuthoringReceiptLedger()
    context_receipt = ledger.record_context_collected(
        request_id="request-1",
        snapshot=context_snapshot,
    )
    evidence_receipt = ledger.record_evidence_extracted(
        request_id="request-1",
        report=evidence_report,
    )

    snapshot = ledger.snapshot()

    assert context_receipt.event_type is AuthoringReceiptEventType.CONTEXT_COLLECTED
    assert context_receipt.metadata["context_digest"] == context_snapshot.context.digest
    assert evidence_receipt.event_type is AuthoringReceiptEventType.EVIDENCE_EXTRACTED
    assert evidence_receipt.metadata["evidence_strength"] == "weak"
    assert snapshot.verify_chain()


def test_records_decomposition_hypotheses_prompt_and_response() -> None:
    request = _request_with_direct_evidence()
    decomposition = RepairTaskDecomposer().decompose_request(request)
    hypotheses = RepairHypothesisEngine().generate(
        request=request,
        decomposition=decomposition,
    )
    contract = PatchAuthoringPromptRenderer().render(
        request=request,
        decomposition=decomposition,
        hypotheses=hypotheses,
    )
    raw_response = _proposal_json()
    proposal = PatchAuthoringResponseParser().parse(raw_response)

    ledger = AuthoringReceiptLedger()
    ledger.record_decomposition_created(
        request_id=request.request_id,
        plan=decomposition,
    )
    ledger.record_hypotheses_generated(
        request_id=request.request_id,
        report=hypotheses,
    )
    ledger.record_prompt_contract_rendered(
        request_id=request.request_id,
        contract=contract,
    )
    ledger.record_model_response_received(
        request_id=request.request_id,
        raw_response=raw_response,
        provider_name="local-test-provider",
        model_name="test-model",
    )
    ledger.record_response_parsed(
        request_id=request.request_id,
        proposal=proposal,
    )
    ledger.record_proposal_validated(
        request_id=request.request_id,
        proposal=proposal,
    )

    snapshot = ledger.snapshot()

    assert snapshot.verify_chain()
    assert snapshot.has_event(AuthoringReceiptEventType.DECOMPOSITION_CREATED)
    assert snapshot.has_event(AuthoringReceiptEventType.HYPOTHESES_GENERATED)
    assert snapshot.has_event(AuthoringReceiptEventType.PROMPT_CONTRACT_RENDERED)
    assert snapshot.has_event(AuthoringReceiptEventType.MODEL_RESPONSE_RECEIVED)
    assert snapshot.has_event(AuthoringReceiptEventType.RESPONSE_PARSED)
    assert snapshot.has_event(AuthoringReceiptEventType.PROPOSAL_VALIDATED)


def test_records_patch_compiled_and_policy_decided(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()
    (workspace / "src" / "example.py").write_text(
        "def add(a, b):\n    return a - b\n",
        encoding="utf-8",
    )
    request = _request_with_direct_evidence()
    proposal = PatchAuthoringResponseParser().parse(_proposal_json())
    candidate = PatchProposalCompiler(workspace_root=workspace).compile(proposal)

    from ix_blackfox.authoring import AuthoringPolicyGate

    policy_report = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        candidate=candidate,
        evidence=request.evidence,
    )

    ledger = AuthoringReceiptLedger()
    compiled_receipt = ledger.record_patch_compiled(
        request_id=request.request_id,
        candidate=candidate,
    )
    policy_receipt = ledger.record_policy_decided(
        request_id=request.request_id,
        report=policy_report,
    )

    assert compiled_receipt.event_type is AuthoringReceiptEventType.PATCH_COMPILED
    assert compiled_receipt.metadata["candidate_id"] == candidate.candidate_id
    assert policy_receipt.event_type is AuthoringReceiptEventType.POLICY_DECIDED
    assert policy_receipt.metadata["policy_decision"] == policy_report.decision.value
    assert ledger.snapshot().verify_chain()


def test_policy_block_receipt_uses_blocked_status() -> None:
    proposal = PatchAuthoringResponseParser().parse(
        _proposal_json(
            mutations=[
                {
                    "mutation_id": "mutation-1",
                    "mutation_type": "create_file",
                    "path": "config/api_token.txt",
                    "before_text": "",
                    "after_text": "TOKEN=abc\n",
                    "rationale": "Create token file.",
                }
            ]
        )
    )

    from ix_blackfox.authoring import AuthoringPolicyGate

    policy_report = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        evidence=_request_with_direct_evidence().evidence,
    )

    ledger = AuthoringReceiptLedger()
    receipt = ledger.record_policy_decided(
        request_id="request-1",
        report=policy_report,
    )

    assert receipt.status is AuthoringReceiptStatus.BLOCKED


def test_records_candidate_selected_and_rejected() -> None:
    ledger = AuthoringReceiptLedger()

    selected = ledger.record_candidate_selected(
        request_id="request-1",
        selected_candidate_id="candidate-a",
        candidate_ids=("candidate-a", "candidate-b"),
        selection_reason="Candidate A had the lowest risk and best evidence alignment.",
    )
    rejected = ledger.record_candidate_rejected(
        request_id="request-1",
        candidate_id="candidate-b",
        rejection_phase="policy_gate",
        rejection_reason="Candidate B required blocked secret-path mutation.",
        proposal_digest="a" * 64,
        affected_paths=("src/example.py",),
    )

    snapshot = ledger.snapshot()

    assert selected.event_type is AuthoringReceiptEventType.CANDIDATE_SELECTED
    assert rejected.event_type is AuthoringReceiptEventType.CANDIDATE_REJECTED
    assert rejected.status is AuthoringReceiptStatus.REJECTED
    assert snapshot.verify_chain()


def test_candidate_selected_rejects_unknown_selected_candidate() -> None:
    ledger = AuthoringReceiptLedger()

    with pytest.raises(ValueError, match="selected_candidate_id"):
        ledger.record_candidate_selected(
            request_id="request-1",
            selected_candidate_id="candidate-c",
            candidate_ids=("candidate-a", "candidate-b"),
            selection_reason="Invalid selection.",
        )


def test_records_authoring_failure() -> None:
    ledger = AuthoringReceiptLedger()

    receipt = ledger.record_authoring_failed(
        request_id="request-1",
        failure_phase="response_parser",
        failure_reason="Model response was malformed JSON.",
    )

    assert receipt.event_type is AuthoringReceiptEventType.AUTHORING_FAILED
    assert receipt.status is AuthoringReceiptStatus.FAILED
    assert receipt.payload["failure_phase"] == "response_parser"


def test_digest_payload_is_order_independent() -> None:
    first = digest_payload({"a": 1, "b": 2})
    second = digest_payload({"b": 2, "a": 1})

    assert first == second
    assert len(first) == 64


def test_ledger_clear_removes_receipts() -> None:
    ledger = AuthoringReceiptLedger()
    ledger.append(
        event_type=AuthoringReceiptEventType.CONTEXT_COLLECTED,
        subject_id="request-1",
        payload={"context_id": "context-1"},
    )

    assert ledger.snapshot().count == 1

    ledger.clear()

    assert ledger.snapshot().count == 0


def _request_with_direct_evidence():
    from ix_blackfox.authoring import AuthoringRequest

    request = AuthoringRequest.create(
        task_id="task-add",
        objective="Repair addition behavior.",
        mode=AuthoringMode.MODEL_ASSISTED,
    )
    evidence = AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="AssertionError: expected addition behavior.",
        raw_text="FAILED tests/test_example.py::test_add",
        related_paths=("src/example.py",),
    )
    return AuthoringRequest(
        request_id=request.request_id,
        objective=request.objective,
        mode=request.mode,
        status=request.status,
        context=request.context,
        evidence=(evidence,),
        subtasks=request.subtasks,
        findings=request.findings,
        metadata=request.metadata,
    )


def _proposal_json(
    *,
    mutations: list[dict[str, object]] | None = None,
) -> str:
    return json.dumps(
        {
            "schema_version": "wave3.patch_authoring_response.v1",
            "proposal_id": "proposal-1",
            "objective_summary": "Repair the failing addition behavior.",
            "reasoning_summary": "The proposed source change aligns with the failure evidence.",
            "confidence": 0.72,
            "assumptions": [
                "The compiler must verify before_text.",
            ],
            "risk_notes": [
                "The patch still requires policy and Wave 2 execution.",
            ],
            "expected_tests": [
                "The targeted behavior test should pass after governed execution.",
            ],
            "mutations": mutations
            if mutations is not None
            else [
                {
                    "mutation_id": "mutation-1",
                    "mutation_type": "replace_text",
                    "path": "src/example.py",
                    "before_text": "return a - b",
                    "after_text": "return a + b",
                    "rationale": "Repair source behavior.",
                }
            ],
        },
        sort_keys=True,
    )
