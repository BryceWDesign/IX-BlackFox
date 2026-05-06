from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ix_blackfox.brains import (
    BrainFailure,
    BrainFailureKind,
    BrainInvocationReceipt,
    BrainInvocationReceiptLedger,
    BrainInvocationRequest,
    BrainInvocationResult,
    BrainInvocationStatus,
    BrainManifest,
    BrainManifestRegistry,
    BrainMessageNormalizer,
    BrainRole,
    HarmonyRenderer,
    build_reasoning_brain_catalog,
)
from ix_blackfox.brains.providers import (
    BrainProvider,
    BrainProviderConfigurationError,
    BrainProviderInvocation,
    BrainProviderTimeoutError,
    BrainProviderUnavailableError,
)
from ix_blackfox.config import RuntimeConfig
from ix_blackfox.kernel import TaskRecord
from ix_blackfox.switchboard import RoutingDecision


@dataclass(frozen=True, slots=True)
class EscalatedReasoningPlan:
    """
    Planned deep-reasoning invocation prepared for escalation.

    Attributes
    ----------
    manifest:
        Selected deep-reasoning manifest.
    request:
        Normalized invocation request.
    rendered_prompt:
        Rendered reasoning prompt envelope.
    source_pack_name:
        Pack whose task is being escalated.
    route_capability_name:
        Capability route that led to the escalation.
    escalation_score:
        Score that triggered escalation.
    trigger_codes:
        Canonical escalation trigger codes in declaration order.
    """

    manifest: BrainManifest
    request: BrainInvocationRequest
    rendered_prompt: str
    source_pack_name: str
    route_capability_name: str
    escalation_score: int
    trigger_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EscalatedReasoningOutcome:
    """
    Result of attempting to invoke the deep-reasoning lane.
    """

    plan: EscalatedReasoningPlan
    provider_name: str | None = None
    result: BrainInvocationResult | None = None
    receipt: BrainInvocationReceipt | None = None
    parsed_output: dict[str, Any] | None = None
    failure_message: str | None = None
    skipped: bool = False

    @property
    def invoked(self) -> bool:
        """
        Return True when a provider invocation was attempted.
        """
        return self.result is not None or self.receipt is not None

    @property
    def succeeded(self) -> bool:
        """
        Return True when invocation succeeded.
        """
        return self.result is not None and self.result.succeeded

    @property
    def summary(self) -> str | None:
        """
        Return the parsed summary field when present.
        """
        if self.parsed_output is None:
            return None
        summary = self.parsed_output.get("summary")
        if not isinstance(summary, str):
            return None
        cleaned = summary.strip()
        return cleaned or None


class EscalatedReasoningRuntime:
    """
    Prepare and optionally invoke the deep-reasoning escalation lane.

    Wave 1 keeps this path bounded:
    - one dedicated escalation brain manifest
    - strict JSON response contract
    - no automatic authority over deterministic execution
    - explicit receipts when a provider call actually happened
    """

    def __init__(
        self,
        *,
        config: RuntimeConfig,
        registry: BrainManifestRegistry | None = None,
        normalizer: BrainMessageNormalizer | None = None,
        renderer: HarmonyRenderer | None = None,
    ) -> None:
        self._config = config
        self._catalog = build_reasoning_brain_catalog()
        self._registry = registry or BrainManifestRegistry()
        self._normalizer = normalizer or BrainMessageNormalizer()
        self._renderer = renderer or HarmonyRenderer()

        for manifest in self._catalog.manifests:
            self._registry.register(manifest)
        for manifest in config.brains.manifests:
            self._registry.register(manifest)

    def plan(
        self,
        *,
        task: TaskRecord,
        route: RoutingDecision,
        pack_name: str,
        escalation_score: int,
        trigger_codes: tuple[str, ...],
        verification_status: str | None = None,
        sentinel_issue_codes: tuple[str, ...] | None = None,
        prior_failure_message: str | None = None,
    ) -> EscalatedReasoningPlan:
        """
        Build the deep-reasoning escalation plan for a task.
        """
        reasoning_brain_name = self._catalog.metadata.get("reasoning_brain_name")
        if reasoning_brain_name is None:
            raise RuntimeError("Wave 1 reasoning catalog does not declare a reasoning brain.")

        manifest = self._registry.get(reasoning_brain_name) or self._catalog.get_manifest(
            reasoning_brain_name
        )
        if manifest is None:
            raise RuntimeError("Wave 1 deep-reasoning manifest is not available.")

        normalized_trigger_codes = _normalize_identifiers(trigger_codes)
        prompt = self._build_prompt(
            task=task,
            route=route,
            pack_name=pack_name,
            escalation_score=escalation_score,
            trigger_codes=normalized_trigger_codes,
            verification_status=verification_status,
            sentinel_issue_codes=tuple(sentinel_issue_codes or ()),
            prior_failure_message=prior_failure_message,
        )
        request = BrainInvocationRequest.create(
            brain_name=manifest.brain_name,
            role=BrainRole.REASONING,
            prompt=prompt,
            task_id=task.request.task_id,
            pack_name=pack_name,
            labels=task.request.labels,
            metadata={
                "route_capability_name": route.capability_name,
                "route_confidence": route.confidence,
                "route_reason": route.reason.value,
                "task_kind": task.request.kind.value,
                "response_format": {"type": "json_object"},
                "reasoning_schema_version": "1",
                "escalation_score": escalation_score,
                "trigger_codes": normalized_trigger_codes,
            },
        )
        rendered_prompt = self._renderer.render_request(
            request,
            developer_prompt=_reasoning_developer_prompt(),
            normalizer=self._normalizer,
        )
        return EscalatedReasoningPlan(
            manifest=manifest,
            request=request,
            rendered_prompt=rendered_prompt,
            source_pack_name=pack_name.strip().lower().replace(" ", "-"),
            route_capability_name=route.capability_name,
            escalation_score=escalation_score,
            trigger_codes=normalized_trigger_codes,
        )

    def invoke(
        self,
        *,
        plan: EscalatedReasoningPlan,
        providers: Mapping[str, BrainProvider],
        receipt_ledger: BrainInvocationReceiptLedger | None = None,
    ) -> EscalatedReasoningOutcome:
        """
        Attempt to invoke the deep-reasoning lane.
        """
        provider = providers.get(plan.manifest.provider_name)
        if provider is None:
            return EscalatedReasoningOutcome(
                plan=plan,
                provider_name=plan.manifest.provider_name,
                failure_message="Deep reasoning provider is not configured for this runtime.",
                skipped=True,
            )

        provider_invocation = BrainProviderInvocation(
            manifest=plan.manifest,
            request=plan.request,
            timeout_seconds=plan.manifest.profile.limits.timeout_seconds,
            metadata={"rendered_prompt": plan.rendered_prompt},
        )

        try:
            response = provider.invoke(provider_invocation)
        except Exception as error:
            failure_kind = _failure_kind_from_error(error)
            failure_result = BrainInvocationResult(
                invocation_id=plan.request.invocation_id,
                brain_name=plan.request.brain_name,
                status=BrainInvocationStatus.FAILED,
                failure=BrainFailure(
                    kind=failure_kind,
                    message=str(error),
                ),
            )
            receipt = None
            if receipt_ledger is not None:
                receipt = receipt_ledger.append(
                    request=plan.request,
                    result=failure_result,
                    provider_name=plan.manifest.provider_name,
                    model_name=plan.manifest.model_name,
                    metadata={"failure_stage": "provider_invoke"},
                )
            return EscalatedReasoningOutcome(
                plan=plan,
                provider_name=plan.manifest.provider_name,
                result=failure_result,
                receipt=receipt,
                parsed_output=None,
                failure_message=str(error),
                skipped=False,
            )

        parsed_output = _parse_json_object(response.result.output_text)

        receipt = None
        if receipt_ledger is not None:
            receipt = receipt_ledger.append(
                request=plan.request,
                result=response.result,
                provider_name=response.provider_name,
                model_name=response.model_name,
                latency_ms=response.latency_ms,
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
                total_tokens=response.usage.total_tokens,
                metadata=response.metadata,
            )

        return EscalatedReasoningOutcome(
            plan=plan,
            provider_name=response.provider_name,
            result=response.result,
            receipt=receipt,
            parsed_output=parsed_output,
            failure_message=None
            if response.result.succeeded
            else response.result.failure.message
            if response.result.failure
            else None,
            skipped=False,
        )

    def _build_prompt(
        self,
        *,
        task: TaskRecord,
        route: RoutingDecision,
        pack_name: str,
        escalation_score: int,
        trigger_codes: tuple[str, ...],
        verification_status: str | None,
        sentinel_issue_codes: tuple[str, ...],
        prior_failure_message: str | None,
    ) -> str:
        lines = [
            "Perform escalated deep reasoning for this task.",
            "",
            "Return strict JSON with this shape:",
            "{",
            '  "summary": "one concise summary",',
            '  "key_points": ["important point"],',
            '  "recommended_action": "next best action",',
            '  "confidence": 0.0,',
            '  "metadata": {"optional": "fields"}',
            "}",
            "",
            f"Task kind: {task.request.kind.value}",
            f"Route capability: {route.capability_name}",
            f"Pack name: {pack_name}",
            f"Escalation score: {escalation_score}",
            f"Trigger codes: {', '.join(trigger_codes) if trigger_codes else '(none)'}",
            f"Verification status: {_normalize_optional_text(verification_status) or '(unknown)'}",
            f"Sentinel issue codes: {', '.join(_normalize_identifiers(sentinel_issue_codes)) if sentinel_issue_codes else '(none)'}",
            "",
            "User request:",
            task.request.input.prompt.strip(),
        ]

        normalized_failure_message = _normalize_optional_text(prior_failure_message)
        if normalized_failure_message is not None:
            lines.extend(
                [
                    "",
                    "Prior failure context:",
                    normalized_failure_message,
                ]
            )

        return "\n".join(lines)


def _parse_json_object(value: str | None) -> dict[str, Any] | None:
    normalized = _normalize_optional_text(value)
    if normalized is None:
        return None

    candidate = normalized
    if candidate.startswith("```") and candidate.endswith("```"):
        lines = candidate.splitlines()
        if len(lines) >= 3:
            candidate = "\n".join(lines[1:-1]).strip()

    try:
        payload = json.loads(candidate)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None
    return payload


def _reasoning_developer_prompt() -> str:
    return (
        "Operate as the BlackFox deep reasoning escalation coprocessor. "
        "Return strict JSON only. Focus on hard-case analysis, contradiction handling, "
        "and explicit next-action guidance."
    )


def _normalize_identifiers(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = _normalize_optional_text(value)
        if cleaned is None:
            continue
        normalized_value = cleaned.lower().replace(" ", "-")
        if normalized_value not in seen:
            normalized.append(normalized_value)
            seen.add(normalized_value)

    return tuple(normalized)


def _normalize_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def _failure_kind_from_error(error: Exception) -> BrainFailureKind:
    if isinstance(error, BrainProviderUnavailableError):
        return BrainFailureKind.PROVIDER_UNAVAILABLE
    if isinstance(error, BrainProviderTimeoutError):
        return BrainFailureKind.TIMEOUT
    if isinstance(error, BrainProviderConfigurationError):
        return BrainFailureKind.INVALID_REQUEST
    return BrainFailureKind.EXECUTION_ERROR
