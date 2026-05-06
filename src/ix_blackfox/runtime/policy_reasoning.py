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
    build_wave1_operating_catalog,
)
from ix_blackfox.brains.providers import (
    BrainProvider,
    BrainProviderConfigurationError,
    BrainProviderInvocation,
    BrainProviderTimeoutError,
    BrainProviderUnavailableError,
)
from ix_blackfox.config import RuntimeConfig
from ix_blackfox.governance import (
    PolicyAdvisoryAssessment,
    PolicyAdvisoryDisposition,
    PolicyAdvisoryNote,
)
from ix_blackfox.kernel import TaskRecord
from ix_blackfox.switchboard import RoutingDecision


@dataclass(frozen=True, slots=True)
class PolicyReasoningPlan:
    """
    Planned policy reasoning invocation prepared beside runtime execution.

    Attributes
    ----------
    manifest:
        Selected policy reasoning manifest.
    request:
        Normalized invocation request.
    rendered_prompt:
        Rendered policy advisory prompt envelope.
    source_pack_name:
        Pack whose execution is being policy-reviewed.
    route_capability_name:
        Capability route that led to this policy reasoning side-check.
    candidate_output:
        Optional output under policy review.
    """

    manifest: BrainManifest
    request: BrainInvocationRequest
    rendered_prompt: str
    source_pack_name: str
    route_capability_name: str
    candidate_output: str | None = None


@dataclass(frozen=True, slots=True)
class PolicyReasoningOutcome:
    """
    Result of attempting to invoke the policy reasoning lane.
    """

    plan: PolicyReasoningPlan
    provider_name: str | None = None
    result: BrainInvocationResult | None = None
    receipt: BrainInvocationReceipt | None = None
    assessment: PolicyAdvisoryAssessment | None = None
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
        Return True when invocation succeeded and produced an assessment.
        """
        return (
            self.result is not None
            and self.result.succeeded
            and self.assessment is not None
        )


class PolicyReasoningRuntime:
    """
    Prepare and optionally invoke the advisory policy reasoning lane.

    Wave 1 keeps this path deliberately bounded:
    - one dedicated policy reasoning manifest
    - one strict JSON response contract
    - advisory rationale only
    - deterministic governance remains authoritative
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
        self._catalog = build_wave1_operating_catalog()
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
        candidate_output: str | None = None,
        vision_observation: str | None = None,
    ) -> PolicyReasoningPlan:
        """
        Build the advisory policy reasoning plan for a task.
        """
        policy_brain_name = self._catalog.metadata.get("policy_brain_name")
        if policy_brain_name is None:
            raise RuntimeError("Wave 1 operating catalog does not declare a policy brain.")

        manifest = self._registry.get(policy_brain_name) or self._catalog.get_manifest(policy_brain_name)
        if manifest is None:
            raise RuntimeError("Wave 1 policy advisory manifest is not available.")

        prompt = self._build_prompt(
            task=task,
            route=route,
            pack_name=pack_name,
            candidate_output=candidate_output,
            vision_observation=vision_observation,
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
                "policy_advisory_schema_version": "1",
            },
        )
        rendered_prompt = self._renderer.render_request(
            request,
            developer_prompt=_policy_developer_prompt(),
            normalizer=self._normalizer,
        )
        return PolicyReasoningPlan(
            manifest=manifest,
            request=request,
            rendered_prompt=rendered_prompt,
            source_pack_name=pack_name.strip().lower().replace(" ", "-"),
            route_capability_name=route.capability_name,
            candidate_output=_normalize_optional_text(candidate_output),
        )

    def invoke(
        self,
        *,
        plan: PolicyReasoningPlan,
        providers: Mapping[str, BrainProvider],
        receipt_ledger: BrainInvocationReceiptLedger | None = None,
    ) -> PolicyReasoningOutcome:
        """
        Attempt to invoke the policy reasoning lane.
        """
        provider = providers.get(plan.manifest.provider_name)
        if provider is None:
            return PolicyReasoningOutcome(
                plan=plan,
                provider_name=plan.manifest.provider_name,
                failure_message="Policy reasoning provider is not configured for this runtime.",
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
            return PolicyReasoningOutcome(
                plan=plan,
                provider_name=plan.manifest.provider_name,
                result=failure_result,
                receipt=receipt,
                assessment=None,
                failure_message=str(error),
                skipped=False,
            )

        if _looks_like_safeguard_schema(response.result.output_text):
            return PolicyReasoningOutcome(
                plan=plan,
                provider_name=response.provider_name,
                result=response.result,
                receipt=None,
                assessment=None,
                failure_message=(
                    "Policy reasoning provider returned safeguard-lane schema, "
                    "so the policy advisory lane was treated as skipped."
                ),
                skipped=True,
            )

        assessment = _normalize_assessment(plan=plan, result=response.result)

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
                safety_labels=() if assessment is None else assessment.policy_tags(),
                metadata=response.metadata,
            )

        return PolicyReasoningOutcome(
            plan=plan,
            provider_name=response.provider_name,
            result=response.result,
            receipt=receipt,
            assessment=assessment,
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
        candidate_output: str | None,
        vision_observation: str | None,
    ) -> str:
        lines = [
            "Review the request for advisory policy interpretation beside deterministic governance.",
            "",
            "Return strict JSON with this shape:",
            "{",
            '  "advisory_disposition": "allow|review|block",',
            '  "rationale": "one concise rationale",',
            '  "notes": [',
            "    {",
            '      "code": "short-code",',
            '      "summary": "human summary",',
            '      "policy_tags": ["tag"],',
            '      "confidence": 0.0',
            "    }",
            "  ],",
            '  "metadata": {"note": "optional"}',
            "}",
            "",
            f"Task kind: {task.request.kind.value}",
            f"Route capability: {route.capability_name}",
            f"Pack name: {pack_name}",
            f"Labels: {', '.join(task.request.labels) if task.request.labels else '(none)'}",
            "",
            "User request:",
            task.request.input.prompt.strip(),
        ]

        normalized_candidate_output = _normalize_optional_text(candidate_output)
        if normalized_candidate_output is not None:
            lines.extend(
                [
                    "",
                    "Candidate output under policy review:",
                    normalized_candidate_output,
                ]
            )

        normalized_vision_observation = _normalize_optional_text(vision_observation)
        if normalized_vision_observation is not None:
            lines.extend(
                [
                    "",
                    "Vision observation context:",
                    normalized_vision_observation,
                ]
            )

        return "\n".join(lines)


def _normalize_assessment(
    *,
    plan: PolicyReasoningPlan,
    result: BrainInvocationResult,
) -> PolicyAdvisoryAssessment | None:
    if result.status is BrainInvocationStatus.FAILED:
        return None

    if result.status is BrainInvocationStatus.REFUSED:
        return PolicyAdvisoryAssessment.create(
            brain_name=plan.manifest.brain_name,
            invocation_id=plan.request.invocation_id,
            advisory_disposition=PolicyAdvisoryDisposition.BLOCK,
            rationale=(
                result.failure.message
                if result.failure is not None
                else "Policy provider refused to review the request."
            ),
            notes=(
                PolicyAdvisoryNote.create(
                    code="policy-provider-refusal",
                    summary=(
                        result.failure.message
                        if result.failure is not None
                        else "Policy provider refused to review the request."
                    ),
                    policy_tags=("provider-refusal", "policy-review"),
                    confidence=0.9,
                ),
            ),
            metadata={"source": "provider_refusal"},
        )

    payload = _parse_json_object(result.output_text)
    if payload is None:
        return PolicyAdvisoryAssessment.create(
            brain_name=plan.manifest.brain_name,
            invocation_id=plan.request.invocation_id,
            advisory_disposition=PolicyAdvisoryDisposition.REVIEW,
            rationale="Policy advisory output was not parseable as structured JSON.",
            notes=(
                PolicyAdvisoryNote.create(
                    code="unparseable-policy-advisory",
                    summary="Policy advisory output was not parseable as structured JSON.",
                    policy_tags=("unparseable-output", "policy-review"),
                    confidence=0.75,
                ),
            ),
            metadata={"source": "fallback_unparseable"},
        )

    rationale = _normalize_optional_text(payload.get("rationale")) or "Policy advisory rationale was not provided."
    notes = _parse_notes(payload.get("notes"))
    disposition = _parse_disposition(payload.get("advisory_disposition"))

    if not notes and disposition is not PolicyAdvisoryDisposition.ALLOW:
        notes = (
            PolicyAdvisoryNote.create(
                code="implicit-policy-disposition",
                summary="Policy advisory disposition was returned without explicit notes.",
                policy_tags=("implicit-disposition", disposition.value),
                confidence=0.65,
            ),
        )

    metadata = dict(payload.get("metadata", {})) if isinstance(payload.get("metadata"), dict) else {}
    return PolicyAdvisoryAssessment.create(
        brain_name=plan.manifest.brain_name,
        invocation_id=plan.request.invocation_id,
        advisory_disposition=disposition,
        rationale=rationale,
        notes=notes,
        metadata=metadata,
    )


def _looks_like_safeguard_schema(value: str | None) -> bool:
    payload = _parse_json_object(value)
    if payload is None:
        return False
    if "notes" in payload or "rationale" in payload:
        return False
    return "findings" in payload


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


def _parse_notes(value: Any) -> tuple[PolicyAdvisoryNote, ...]:
    if not isinstance(value, list):
        return ()

    notes: list[PolicyAdvisoryNote] = []
    for item in value:
        if not isinstance(item, dict):
            continue

        code = _normalize_optional_text(item.get("code"))
        summary = _normalize_optional_text(item.get("summary"))
        if code is None or summary is None:
            continue

        notes.append(
            PolicyAdvisoryNote.create(
                code=code,
                summary=summary,
                policy_tags=_parse_strings(item.get("policy_tags")),
                confidence=_parse_probability(item.get("confidence"), default=0.5),
                metadata=dict(item.get("metadata", {})) if isinstance(item.get("metadata"), dict) else {},
            )
        )

    return tuple(notes)


def _parse_strings(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()

    raw_items: tuple[Any, ...]
    if isinstance(value, str):
        raw_items = (value,)
    elif isinstance(value, list | tuple):
        raw_items = tuple(value)
    else:
        return ()

    normalized: list[str] = []
    seen: set[str] = set()
    for item in raw_items:
        cleaned = _normalize_optional_text(item)
        if cleaned is None:
            continue
        normalized_item = cleaned.strip().lower().replace(" ", "-")
        if normalized_item not in seen:
            normalized.append(normalized_item)
            seen.add(normalized_item)

    return tuple(normalized)


def _parse_disposition(value: Any) -> PolicyAdvisoryDisposition:
    normalized = _normalize_optional_text(value)
    if normalized is None:
        return PolicyAdvisoryDisposition.REVIEW

    cleaned = normalized.lower()
    mapping = {
        PolicyAdvisoryDisposition.ALLOW.value: PolicyAdvisoryDisposition.ALLOW,
        PolicyAdvisoryDisposition.REVIEW.value: PolicyAdvisoryDisposition.REVIEW,
        PolicyAdvisoryDisposition.BLOCK.value: PolicyAdvisoryDisposition.BLOCK,
    }
    return mapping.get(cleaned, PolicyAdvisoryDisposition.REVIEW)


def _parse_probability(value: Any, *, default: float) -> float:
    if value is None:
        return default
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return default
    return min(max(numeric, 0.0), 1.0)


def _policy_developer_prompt() -> str:
    return (
        "Operate as the BlackFox advisory policy reasoning coprocessor. "
        "Return strict JSON only. Provide structured rationale beside deterministic governance. "
        "Do not claim final policy authority."
    )


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
