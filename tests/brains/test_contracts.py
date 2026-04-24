from __future__ import annotations

import pytest

from ix_blackfox.brains import (
    BrainCapability,
    BrainContextWindow,
    BrainExecutionLimits,
    BrainFailure,
    BrainFailureKind,
    BrainInvocationRequest,
    BrainInvocationResult,
    BrainInvocationStatus,
    BrainMessage,
    BrainModality,
    BrainModalityProfile,
    BrainModelProfile,
    BrainRole,
)


def test_brain_invocation_request_normalizes_identifiers() -> None:
    request = BrainInvocationRequest.create(
        brain_name=" GPT OSS 20B ",
        role=BrainRole.PRIMARY,
        prompt="  Solve the task.  ",
        messages=(BrainMessage(role=" User ", content="  hello  "),),
        input_modalities=(BrainModality.TEXT, BrainModality.TEXT, BrainModality.IMAGE),
        task_id=" Task 123 ",
        pack_name=" Programming ",
        labels=(" Main ", "main", " coding "),
        metadata={"temperature": 0.1},
    )

    assert request.invocation_id.startswith("brain-call-")
    assert request.brain_name == "gpt-oss-20b"
    assert request.prompt == "Solve the task."
    assert request.messages[0].role == "user"
    assert request.messages[0].content == "hello"
    assert request.input_modalities == (BrainModality.TEXT, BrainModality.IMAGE)
    assert request.task_id == "task-123"
    assert request.pack_name == "programming"
    assert request.labels == ("main", "coding")
    assert request.metadata == {"temperature": 0.1}


def test_successful_invocation_result_requires_output_text() -> None:
    with pytest.raises(ValueError, match="output_text"):
        BrainInvocationResult(
            invocation_id="brain-call-123",
            brain_name="gpt-oss-20b",
            status=BrainInvocationStatus.SUCCEEDED,
            output_text=None,
        )


def test_failed_invocation_result_requires_failure_details() -> None:
    with pytest.raises(ValueError, match="failure details"):
        BrainInvocationResult(
            invocation_id="brain-call-123",
            brain_name="gpt-oss-20b",
            status=BrainInvocationStatus.FAILED,
        )


def test_brain_failure_normalizes_message() -> None:
    failure = BrainFailure(
        kind=BrainFailureKind.TIMEOUT,
        message="  Provider timed out.  ",
        retryable=True,
        metadata={"seconds": 30},
    )

    assert failure.message == "Provider timed out."
    assert failure.retryable is True
    assert failure.metadata == {"seconds": 30}


def test_brain_model_profile_declares_roles_capabilities_and_modalities() -> None:
    profile = BrainModelProfile(
        brain_name=" Qwen Vision ",
        roles=(BrainRole.MULTIMODAL, BrainRole.MULTIMODAL, BrainRole.REASONING),
        capabilities=(
            BrainCapability.VISION_ANALYSIS,
            BrainCapability.STRUCTURED_OUTPUT,
            BrainCapability.STRUCTURED_OUTPUT,
        ),
        context_window=BrainContextWindow(max_input_tokens=32768, max_output_tokens=4096),
        modalities=BrainModalityProfile(
            input_modalities=(BrainModality.TEXT, BrainModality.IMAGE, BrainModality.IMAGE),
            output_modalities=(BrainModality.TEXT, BrainModality.JSON),
            supports_structured_output=True,
        ),
        limits=BrainExecutionLimits(
            max_concurrent_invocations=2,
            timeout_seconds=45.0,
            max_tool_calls=0,
        ),
        description="  Vision specialist.  ",
    )

    assert profile.brain_name == "qwen-vision"
    assert profile.roles == (BrainRole.MULTIMODAL, BrainRole.REASONING)
    assert profile.capabilities == (
        BrainCapability.VISION_ANALYSIS,
        BrainCapability.STRUCTURED_OUTPUT,
    )
    assert profile.accepts_modality(BrainModality.IMAGE) is True
    assert profile.emits_modality(BrainModality.JSON) is True
    assert profile.supports_role(BrainRole.MULTIMODAL) is True
    assert profile.declares_capability(BrainCapability.VISION_ANALYSIS) is True
    assert profile.description == "Vision specialist."


def test_structured_output_flag_requires_capability() -> None:
    with pytest.raises(ValueError, match="structured_output capability"):
        BrainModelProfile(
            brain_name="gpt-oss-20b",
            roles=(BrainRole.PRIMARY,),
            capabilities=(BrainCapability.TEXT_GENERATION,),
            context_window=BrainContextWindow(
                max_input_tokens=16384,
                max_output_tokens=2048,
            ),
            modalities=BrainModalityProfile(supports_structured_output=True),
        )


def test_tool_use_flag_requires_tool_planning_capability() -> None:
    with pytest.raises(ValueError, match="tool_planning capability"):
        BrainModelProfile(
            brain_name="gpt-oss-20b",
            roles=(BrainRole.PRIMARY,),
            capabilities=(BrainCapability.CODE_GENERATION,),
            context_window=BrainContextWindow(
                max_input_tokens=16384,
                max_output_tokens=2048,
            ),
            modalities=BrainModalityProfile(supports_tool_use=True),
        )


def test_context_and_execution_limits_reject_invalid_values() -> None:
    with pytest.raises(ValueError, match="max_input_tokens"):
        BrainContextWindow(max_input_tokens=0, max_output_tokens=1)

    with pytest.raises(ValueError, match="max_concurrent_invocations"):
        BrainExecutionLimits(max_concurrent_invocations=0)
