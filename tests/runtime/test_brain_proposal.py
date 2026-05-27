from __future__ import annotations

from datetime import UTC, datetime

from ix_blackfox.authoring import (
    AuthoringMode,
    PatchAuthoringPromptContract,
    PatchAuthoringResponseSchema,
    PromptContractMessage,
    PromptMessageRole,
)
from ix_blackfox.brains import (
    BrainCapability,
    BrainContextWindow,
    BrainFailure,
    BrainFailureKind,
    BrainInvocationResult,
    BrainInvocationStatus,
    BrainManifest,
    BrainModality,
    BrainModalityProfile,
    BrainModelProfile,
    BrainRole,
)
from ix_blackfox.brains.providers import (
    BrainProvider,
    BrainProviderHealth,
    BrainProviderInvocation,
    BrainProviderResponse,
)
from ix_blackfox.runtime import BrainPatchProposalProvider


class RecordingBrainProvider(BrainProvider):
    def __init__(
        self,
        *,
        provider_name: str = "ollama",
        output_text: str | None = '{"schema_version":"wave3.patch_authoring_response.v1"}',
        status: BrainInvocationStatus = BrainInvocationStatus.SUCCEEDED,
    ) -> None:
        super().__init__(provider_name=provider_name)
        self.output_text = output_text
        self.status = status
        self.invocations: list[BrainProviderInvocation] = []

    def health_check(self) -> BrainProviderHealth:
        return BrainProviderHealth(
            provider_name=self.provider_name,
            is_available=True,
            checked_at=datetime(2026, 5, 25, 12, 0, tzinfo=UTC),
            message="healthy",
        )

    def invoke(self, invocation: BrainProviderInvocation) -> BrainProviderResponse:
        self.validate_invocation(invocation)
        self.invocations.append(invocation)
        failure = None
        if self.status is not BrainInvocationStatus.SUCCEEDED:
            failure = BrainFailure(
                kind=BrainFailureKind.PROVIDER_UNAVAILABLE,
                message="provider failed",
            )
        return BrainProviderResponse(
            provider_name=self.provider_name,
            model_name=invocation.manifest.model_name,
            result=BrainInvocationResult(
                invocation_id=invocation.request.invocation_id,
                brain_name=invocation.request.brain_name,
                status=self.status,
                output_text=self.output_text,
                output_modalities=(BrainModality.TEXT,),
                failure=failure,
            ),
            latency_ms=50,
        )


def test_brain_patch_provider_invokes_brain_with_authoring_contract() -> None:
    provider = RecordingBrainProvider(
        output_text='  {"schema_version":"wave3.patch_authoring_response.v1"}  ',
    )
    bridge = BrainPatchProposalProvider(
        provider=provider,
        manifest=_manifest(),
        timeout_seconds=30.0,
        labels=(" Wave 7 ", "wave-7", "repair"),
        metadata={"temperature": 0},
    )

    responses = tuple(bridge.generate(_contract()))

    assert responses == ('{"schema_version":"wave3.patch_authoring_response.v1"}',)
    assert len(provider.invocations) == 1

    invocation = provider.invocations[0]
    assert invocation.manifest.brain_name == "repair-brain"
    assert invocation.request.brain_name == "repair-brain"
    assert invocation.request.role is BrainRole.PRIMARY
    assert invocation.request.task_id == "request-1"
    assert invocation.request.pack_name == "programming"
    assert invocation.request.labels == ("wave-7", "repair")
    assert invocation.timeout_seconds == 30.0
    assert invocation.metadata["bridge"] == "wave7_brain_patch_proposal_provider"
    assert invocation.request.metadata["wave"] == 7
    assert invocation.request.metadata["response_format"] == "json"
    assert invocation.request.metadata["temperature"] == 0
    assert invocation.request.metadata["authoring_contract_digest"] == _contract().digest
    assert tuple(message.role for message in invocation.request.messages) == (
        "system",
        "user",
    )
    assert "Return JSON only" in invocation.request.prompt
    assert "Do not approve your own proposal" in invocation.request.prompt


def test_brain_patch_provider_exposes_provider_and_model_names_for_receipts() -> None:
    bridge = BrainPatchProposalProvider(
        provider=RecordingBrainProvider(provider_name="vllm"),
        manifest=_manifest(provider_name="vllm", model_name="repair-model"),
    )

    assert bridge.provider_name == "vllm"
    assert bridge.model_name == "repair-model"


def test_brain_patch_provider_returns_no_response_for_failed_invocation() -> None:
    provider = RecordingBrainProvider(
        status=BrainInvocationStatus.FAILED,
        output_text=None,
    )
    bridge = BrainPatchProposalProvider(provider=provider, manifest=_manifest())

    assert tuple(bridge.generate(_contract())) == ()
    assert len(provider.invocations) == 1


def test_brain_patch_provider_rejects_provider_manifest_mismatch() -> None:
    try:
        BrainPatchProposalProvider(
            provider=RecordingBrainProvider(provider_name="ollama"),
            manifest=_manifest(provider_name="vllm"),
        )
        raised = False
    except ValueError as exc:
        raised = "provider_name must match" in str(exc)

    assert raised


def test_brain_patch_provider_rejects_unsupported_role() -> None:
    try:
        BrainPatchProposalProvider(
            provider=RecordingBrainProvider(),
            manifest=_manifest(role=BrainRole.SAFETY),
            role=BrainRole.PRIMARY,
        )
        raised = False
    except ValueError as exc:
        raised = "role must be supported" in str(exc)

    assert raised


def test_brain_patch_provider_rejects_non_text_manifest() -> None:
    try:
        BrainPatchProposalProvider(
            provider=RecordingBrainProvider(),
            manifest=_manifest(input_modalities=(BrainModality.IMAGE,)),
        )
        raised = False
    except ValueError as exc:
        raised = "text-capable manifest" in str(exc)

    assert raised


def _contract() -> PatchAuthoringPromptContract:
    return PatchAuthoringPromptContract(
        contract_id="contract-1",
        request_id="request-1",
        objective_id="objective-1",
        prompt_version="wave3-patch-authoring-v1",
        mode=AuthoringMode.MODEL_ASSISTED,
        messages=(
            PromptContractMessage(
                role=PromptMessageRole.SYSTEM,
                content="System rules.",
                metadata={"purpose": "rules"},
            ),
            PromptContractMessage(
                role=PromptMessageRole.USER,
                content="User repair request.",
                metadata={"purpose": "task"},
            ),
        ),
        response_schema=PatchAuthoringResponseSchema(),
        context_digest="0" * 64,
        evidence_digest="1" * 64,
    )


def _manifest(
    *,
    provider_name: str = "ollama",
    model_name: str = "repair-model",
    role: BrainRole = BrainRole.PRIMARY,
    input_modalities: tuple[BrainModality, ...] = (BrainModality.TEXT,),
) -> BrainManifest:
    return BrainManifest(
        brain_name="repair-brain",
        provider_name=provider_name,
        model_name=model_name,
        version="0.1.0",
        profile=BrainModelProfile(
            brain_name="repair-brain",
            roles=(role,),
            capabilities=(BrainCapability.CODE_GENERATION,),
            context_window=BrainContextWindow(
                max_input_tokens=32768,
                max_output_tokens=4096,
            ),
            modalities=BrainModalityProfile(input_modalities=input_modalities),
        ),
    )
