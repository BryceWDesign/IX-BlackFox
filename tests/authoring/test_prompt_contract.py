from __future__ import annotations

import json

from ix_blackfox.authoring import (
    AuthoringContextBuilder,
    AuthoringContextBuilderConfig,
    AuthoringEvidence,
    AuthoringEvidenceStrength,
    AuthoringMode,
    AuthoringRequest,
    PatchAuthoringPromptContract,
    PatchAuthoringPromptRenderer,
    PatchAuthoringPromptRendererConfig,
    PatchAuthoringResponseSchema,
    PromptContractMessage,
    PromptMessageRole,
    RepairHypothesisEngine,
    RepairTaskDecomposer,
)


def test_response_schema_requires_structured_patch_fields() -> None:
    schema = PatchAuthoringResponseSchema().to_dict()

    assert schema["schema_version"] == "wave3.patch_authoring_response.v1"
    assert "mutations" in schema["required"]
    assert schema["properties"]["mutations"]["items"]["properties"]["mutation_type"]["enum"] == [
        "replace_text",
        "create_file",
    ]
    assert schema["additionalProperties"] is False


def test_response_schema_json_is_canonical_and_parseable() -> None:
    schema_json = PatchAuthoringResponseSchema().to_json()
    parsed = json.loads(schema_json)

    assert parsed["schema_version"] == "wave3.patch_authoring_response.v1"
    assert schema_json == PatchAuthoringResponseSchema().to_json()


def test_prompt_renderer_creates_strict_system_and_user_messages(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()
    (workspace / "src" / "example.py").write_text(
        "def add(a, b):\n    return a - b\n",
        encoding="utf-8",
    )

    context_snapshot = AuthoringContextBuilder(
        workspace_root=workspace,
        config=AuthoringContextBuilderConfig(include_paths=("src",)),
    ).build()

    request = AuthoringRequest.create(
        task_id="task-add",
        objective="Repair add so the failing assertion passes.",
        mode=AuthoringMode.MODEL_ASSISTED,
    )
    evidence = AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="AssertionError: expected 4 but got 0.",
        raw_text="FAILED tests/test_example.py::test_add - assert 0 == 4",
        related_paths=("src/example.py",),
    )
    request = _with_evidence(request, evidence)

    decomposition = RepairTaskDecomposer().decompose_request(request)
    hypotheses = RepairHypothesisEngine().generate(
        request=request,
        decomposition=decomposition,
    )

    contract = PatchAuthoringPromptRenderer().render(
        request=request,
        context_snapshot=context_snapshot,
        decomposition=decomposition,
        hypotheses=hypotheses,
    )

    assert contract.mode is AuthoringMode.MODEL_ASSISTED
    assert contract.context_digest == context_snapshot.context.digest
    assert contract.evidence_digest is not None
    assert contract.decomposition_plan_id == decomposition.plan_id
    assert contract.hypothesis_report_id == hypotheses.report_id
    assert contract.selected_hypothesis_id == hypotheses.selected_hypothesis_id
    assert contract.system_message.role is PromptMessageRole.SYSTEM
    assert contract.user_message.role is PromptMessageRole.USER
    assert "Return JSON only." in contract.system_message.content
    assert "Do not include shell commands." in contract.system_message.content
    assert "## TASK OBJECTIVE" in contract.user_message.content
    assert "src/example.py" in contract.user_message.content


def test_prompt_contract_digest_is_stable_for_same_payload() -> None:
    message = PromptContractMessage(
        role=PromptMessageRole.SYSTEM,
        content="Return JSON only.",
    )
    contract = PatchAuthoringPromptContract(
        contract_id="prompt-contract-test",
        request_id="request-test",
        objective_id="objective-test",
        prompt_version="wave3-patch-authoring-v1",
        mode=AuthoringMode.MODEL_ASSISTED,
        messages=(message,),
        response_schema=PatchAuthoringResponseSchema(),
    )

    assert contract.digest == contract.digest
    assert len(contract.digest) == 64
    assert contract.to_dict()["digest"] == contract.digest


def test_prompt_contract_round_trip_preserves_messages_and_digest() -> None:
    request = AuthoringRequest.create(
        task_id="task-round-trip",
        objective="Repair the failing test.",
        mode=AuthoringMode.MODEL_ASSISTED,
    )
    contract = PatchAuthoringPromptRenderer().render(request=request)

    restored = PatchAuthoringPromptContract.from_dict(contract.to_dict())

    assert restored.contract_id == contract.contract_id
    assert restored.request_id == contract.request_id
    assert restored.objective_id == contract.objective_id
    assert restored.prompt_version == contract.prompt_version
    assert restored.mode is AuthoringMode.MODEL_ASSISTED
    assert restored.system_message.content == contract.system_message.content
    assert restored.user_message.content == contract.user_message.content
    assert restored.digest == contract.digest


def test_prompt_renderer_records_no_context_or_no_evidence_honestly() -> None:
    request = AuthoringRequest.create(
        task_id="task-no-context",
        objective="Repair reported behavior.",
        mode=AuthoringMode.MODEL_ASSISTED,
    )

    contract = PatchAuthoringPromptRenderer().render(request=request)

    assert contract.context_digest is None
    assert contract.evidence_digest is not None
    assert "No evidence items were attached" in contract.user_message.content
    assert "No bounded context snapshot was supplied" in contract.user_message.content


def test_prompt_renderer_bounds_context_text(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()
    (workspace / "src" / "large.py").write_text("x" * 500, encoding="utf-8")

    context_snapshot = AuthoringContextBuilder(
        workspace_root=workspace,
        config=AuthoringContextBuilderConfig(include_paths=("src",)),
    ).build()
    request = AuthoringRequest.create(
        task_id="task-bounds",
        objective="Repair large file issue.",
        mode=AuthoringMode.MODEL_ASSISTED,
    )
    renderer = PatchAuthoringPromptRenderer(
        config=PatchAuthoringPromptRendererConfig(
            max_context_document_chars=80,
            max_total_context_chars=80,
        )
    )

    contract = renderer.render(
        request=request,
        context_snapshot=context_snapshot,
    )

    assert "[truncated]" in contract.user_message.content
    assert "src/large.py" in contract.user_message.content


def test_system_message_contains_forbidden_authority_rules() -> None:
    request = AuthoringRequest.create(
        task_id="task-rules",
        objective="Repair failing test.",
        mode=AuthoringMode.MODEL_ASSISTED,
    )
    contract = PatchAuthoringPromptRenderer().render(request=request)

    system_message = contract.system_message.content

    assert "You do not have authority to edit files." in system_message
    assert "You do not have authority to run commands." in system_message
    assert "You do not have authority to approve review." in system_message
    assert "Do not use absolute paths." in system_message
    assert "Do not use path traversal." in system_message
    assert "Do not weaken tests to force success." in system_message


def test_user_message_includes_response_requirements() -> None:
    request = AuthoringRequest.create(
        task_id="task-requirements",
        objective="Repair failing test.",
        mode=AuthoringMode.MODEL_ASSISTED,
    )

    contract = PatchAuthoringPromptRenderer().render(request=request)

    assert "Every mutation must include exact before_text and after_text." in contract.user_message.content
    assert "Use workspace-relative paths only." in contract.user_message.content
    assert "Expected tests are descriptions only; do not provide shell commands." in contract.user_message.content


def _with_evidence(
    request: AuthoringRequest,
    *evidence: AuthoringEvidence,
) -> AuthoringRequest:
    return AuthoringRequest(
        request_id=request.request_id,
        objective=request.objective,
        mode=request.mode,
        status=request.status,
        context=request.context,
        evidence=tuple(evidence),
        subtasks=request.subtasks,
        findings=request.findings,
        metadata=request.metadata,
    )
