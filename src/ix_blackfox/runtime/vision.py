from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ix_blackfox.brains import (
    BrainCapability,
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
    BrainModality,
    BrainRole,
    BrainRouter,
    BrainRoutingRequest,
    HarmonyRenderer,
    build_wave1_extended_brain_catalog,
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
class VisionPlan:
    """
    Planned multimodal vision invocation prepared before execution.

    Attributes
    ----------
    manifest:
        Selected multimodal brain manifest.
    request:
        Normalized invocation request.
    rendered_prompt:
        Rendered multimodal prompt envelope.
    source_pack_name:
        Pack whose work is being supported by vision analysis.
    route_capability_name:
        Capability route that led to this vision side-check.
    image_count:
        Number of images attached to the request.
    """

    manifest: BrainManifest
    request: BrainInvocationRequest
    rendered_prompt: str
    source_pack_name: str
    route_capability_name: str
    image_count: int


@dataclass(frozen=True, slots=True)
class VisionOutcome:
    """
    Result of attempting to invoke the vision lane.
    """

    plan: VisionPlan
    provider_name: str | None = None
    result: BrainInvocationResult | None = None
    receipt: BrainInvocationReceipt | None = None
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
        Return True when the provider invocation succeeded.
        """
        return self.result is not None and self.result.succeeded

    @property
    def observation_text(self) -> str | None:
        """
        Return normalized observation text when present.
        """
        if self.result is None:
            return None
        return self.result.output_text


class VisionRuntime:
    """
    Prepare and optionally invoke the multimodal vision lane.

    Wave 1 keeps this path deliberately bounded:
    - one explicit multimodal role
    - image-plus-text inputs only
    - deterministic manifest selection
    - optional receipt capture when a provider call really happened
    """

    def __init__(
        self,
        *,
        config: RuntimeConfig,
        registry: BrainManifestRegistry | None = None,
        router: BrainRouter | None = None,
        normalizer: BrainMessageNormalizer | None = None,
        renderer: HarmonyRenderer | None = None,
    ) -> None:
        self._config = config
        self._catalog = build_wave1_extended_brain_catalog()
        self._registry = registry or BrainManifestRegistry()
        self._normalizer = normalizer or BrainMessageNormalizer()
        self._renderer = renderer or HarmonyRenderer()

        for manifest in self._catalog.manifests:
            self._registry.register(manifest)
        for manifest in config.brains.manifests:
            self._registry.register(manifest)

        self._router = router or BrainRouter(self._registry)

    def plan(
        self,
        *,
        task: TaskRecord,
        route: RoutingDecision,
        pack_name: str,
        images: tuple[str, ...],
        question: str | None = None,
    ) -> VisionPlan:
        """
        Build the multimodal vision plan for a task and attached images.
        """
        normalized_images = _normalize_images(images)
        if not normalized_images:
            raise ValueError("Vision planning requires at least one image.")

        decision = self._router.route(
            BrainRoutingRequest(
                required_role=BrainRole.MULTIMODAL,
                required_capabilities=(
                    BrainCapability.VISION_ANALYSIS,
                    BrainCapability.STRUCTURED_OUTPUT,
                ),
                pack_name=pack_name,
                preferred_labels=task.request.labels,
            )
        )

        manifest = decision.selected
        if manifest is None:
            catalog_brain_name = self._catalog.brain_for_role(BrainRole.MULTIMODAL)
            if catalog_brain_name is None:
                raise RuntimeError("Wave 1 vision default is not available.")
            manifest = self._catalog.get_manifest(catalog_brain_name)
            if manifest is None:
                raise RuntimeError("Wave 1 vision manifest is not available.")

        prompt = _build_prompt(
            task=task,
            route=route,
            pack_name=pack_name,
            question=question,
            image_count=len(normalized_images),
        )
        request = BrainInvocationRequest.create(
            brain_name=manifest.brain_name,
            role=BrainRole.MULTIMODAL,
            prompt=prompt,
            task_id=task.request.task_id,
            pack_name=pack_name,
            labels=task.request.labels,
            input_modalities=(BrainModality.TEXT, BrainModality.IMAGE),
            metadata={
                "images": normalized_images,
                "route_capability_name": route.capability_name,
                "route_confidence": route.confidence,
                "route_reason": route.reason.value,
                "task_kind": task.request.kind.value,
                "response_format": {"type": "json_object"},
                "vision_schema_version": "1",
                "image_count": len(normalized_images),
            },
        )
        rendered_prompt = self._renderer.render_request(
            request,
            developer_prompt=_vision_developer_prompt(),
            normalizer=self._normalizer,
        )
        return VisionPlan(
            manifest=manifest,
            request=request,
            rendered_prompt=rendered_prompt,
            source_pack_name=pack_name.strip().lower().replace(" ", "-"),
            route_capability_name=route.capability_name,
            image_count=len(normalized_images),
        )

    def invoke(
        self,
        *,
        plan: VisionPlan,
        providers: Mapping[str, BrainProvider],
        receipt_ledger: BrainInvocationReceiptLedger | None = None,
    ) -> VisionOutcome:
        """
        Attempt to invoke the multimodal vision lane.
        """
        provider = providers.get(plan.manifest.provider_name)
        if provider is None:
            return VisionOutcome(
                plan=plan,
                provider_name=plan.manifest.provider_name,
                failure_message="Vision provider is not configured for this runtime.",
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
            return VisionOutcome(
                plan=plan,
                provider_name=plan.manifest.provider_name,
                result=failure_result,
                receipt=receipt,
                failure_message=str(error),
                skipped=False,
            )

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

        return VisionOutcome(
            plan=plan,
            provider_name=response.provider_name,
            result=response.result,
            receipt=receipt,
            failure_message=None
            if response.result.succeeded
            else response.result.failure.message
            if response.result.failure
            else None,
            skipped=False,
        )


def _build_prompt(
    *,
    task: TaskRecord,
    route: RoutingDecision,
    pack_name: str,
    question: str | None,
    image_count: int,
) -> str:
    normalized_question = _normalize_optional_text(question)
    lines = [
        "Inspect the attached screenshot(s) or UI image(s) and return a concise technical analysis.",
        "",
        "Return strict JSON with this shape:",
        "{",
        '  "summary": "one short summary",',
        '  "observations": ["clear observation"],',
        '  "risks": ["optional risk"],',
        '  "recommended_next_checks": ["optional next check"],',
        '  "metadata": {"optional": "fields"}',
        "}",
        "",
        f"Task kind: {task.request.kind.value}",
        f"Route capability: {route.capability_name}",
        f"Pack name: {pack_name}",
        f"Image count: {image_count}",
        f"Labels: {', '.join(task.request.labels) if task.request.labels else '(none)'}",
        "",
        "User request:",
        task.request.input.prompt.strip(),
    ]

    if normalized_question is not None:
        lines.extend(
            [
                "",
                "Specific question:",
                normalized_question,
            ]
        )

    return "\n".join(lines)


def _vision_developer_prompt() -> str:
    return (
        "Operate as the BlackFox multimodal vision coprocessor. "
        "Inspect screenshots or UI states carefully, return strict JSON only, "
        "and prefer precise observable evidence over speculation."
    )


def _normalize_images(images: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    for image in images:
        cleaned = image.strip()
        if cleaned:
            normalized.append(cleaned)
    return tuple(normalized)


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _failure_kind_from_error(error: Exception) -> BrainFailureKind:
    if isinstance(error, BrainProviderUnavailableError):
        return BrainFailureKind.PROVIDER_UNAVAILABLE
    if isinstance(error, BrainProviderTimeoutError):
        return BrainFailureKind.TIMEOUT
    if isinstance(error, BrainProviderConfigurationError):
        return BrainFailureKind.INVALID_REQUEST
    return BrainFailureKind.EXECUTION_ERROR
