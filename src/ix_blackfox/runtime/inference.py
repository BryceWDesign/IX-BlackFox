from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any, Mapping

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
    BrainRole,
    BrainRouter,
    BrainRoutingRequest,
    HarmonyRenderer,
    build_primary_brain_catalog,
)
from ix_blackfox.brains.providers import (
    BrainProvider,
    BrainProviderConfigurationError,
    BrainProviderInvocation,
    BrainProviderTimeoutError,
    BrainProviderUnavailableError,
)
from ix_blackfox.config import RuntimeConfig
from ix_blackfox.kernel import TaskKind, TaskRecord
from ix_blackfox.switchboard import RoutingDecision


class TaskInferenceReason(StrEnum):
    """
    Canonical reasons for a task-kind inference result.
    """

    EXPLICIT_SIGNAL = auto()
    KEYWORD_MATCH = auto()
    LABEL_MATCH = auto()
    NO_SIGNAL = auto()


@dataclass(frozen=True, slots=True)
class TaskInference:
    """
    One deterministic task-kind inference result.

    Attributes
    ----------
    kind:
        Inferred task kind.
    confidence:
        Normalized confidence score from 0.0 to 1.0.
    reason:
        Primary reason class for the inference.
    matched_terms:
        Prompt terms that contributed to the result.
    matched_labels:
        Task labels that contributed to the result.
    """

    kind: TaskKind
    confidence: float
    reason: TaskInferenceReason
    matched_terms: tuple[str, ...] = field(default_factory=tuple)
    matched_labels: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        normalized_confidence = float(self.confidence)
        if not 0.0 <= normalized_confidence <= 1.0:
            raise ValueError("Task inference confidence must be between 0.0 and 1.0.")

        object.__setattr__(self, "confidence", normalized_confidence)
        object.__setattr__(self, "matched_terms", _normalize_identifiers(self.matched_terms))
        object.__setattr__(self, "matched_labels", _normalize_identifiers(self.matched_labels))


@dataclass(frozen=True, slots=True)
class PrimaryBrainPlan:
    """
    Planned primary-brain invocation prepared before pack execution.

    Attributes
    ----------
    manifest:
        Selected brain manifest.
    request:
        Normalized invocation request.
    rendered_prompt:
        Harmony-rendered conversation payload.
    required_capabilities:
        Capabilities used to choose the brain.
    route_capability_name:
        Capability route that led to this brain plan.
    """

    manifest: BrainManifest
    request: BrainInvocationRequest
    rendered_prompt: str
    required_capabilities: tuple[BrainCapability, ...]
    route_capability_name: str


@dataclass(frozen=True, slots=True)
class PrimaryBrainOutcome:
    """
    Result of attempting to invoke the primary brain lane.

    Attributes
    ----------
    plan:
        Planned invocation envelope.
    provider_name:
        Effective provider used for invocation, if any.
    result:
        Normalized invocation result when a provider call happened.
    receipt:
        Auditable brain receipt when a provider call happened.
    failure_message:
        Human-readable invocation failure summary when the call did not succeed.
    skipped:
        Whether the invocation path was skipped rather than attempted.
    """

    plan: PrimaryBrainPlan
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


class DeterministicTaskClassifier:
    """
    Deterministic prompt and label classifier for BlackFox task kinds.

    The goal is not to be clever. The goal is to make unknown task intake
    usable without introducing opaque routing behavior.
    """

    _TERM_MAP: dict[TaskKind, tuple[str, ...]] = {
        TaskKind.PROGRAMMING: (
            "bug",
            "build",
            "code",
            "debug",
            "fix",
            "function",
            "patch",
            "profile",
            "python",
            "refactor",
            "regression",
            "repo",
            "test",
            "tests",
        ),
        TaskKind.ARCHITECTURE: (
            "architecture",
            "boundary",
            "component",
            "design",
            "interface",
            "module",
            "orchestration",
            "runtime",
            "state model",
            "subsystem",
            "system design",
        ),
        TaskKind.ANALYSIS: (
            "analyze",
            "analysis",
            "audit",
            "explain",
            "inspect",
            "inspection",
            "review",
            "walk through",
        ),
        TaskKind.RESEARCH: (
            "compare",
            "investigate",
            "literature",
            "research",
            "survey",
            "study",
        ),
        TaskKind.EVALUATION: (
            "benchmark",
            "evaluate",
            "evaluation",
            "grade",
            "measure",
            "metric",
            "score",
            "validate",
            "verification",
            "verify",
        ),
        TaskKind.OPERATIONS: (
            "deploy",
            "incident",
            "monitor",
            "oncall",
            "operations",
            "release",
            "runbook",
            "service",
        ),
    }

    _LABEL_MAP: dict[TaskKind, tuple[str, ...]] = {
        TaskKind.PROGRAMMING: (
            "code",
            "patching",
            "profiling",
            "testing",
        ),
        TaskKind.ARCHITECTURE: (
            "architecture",
            "boundary",
            "design",
            "interfaces",
            "state",
        ),
        TaskKind.ANALYSIS: (
            "analysis",
            "audit",
            "inspection",
        ),
        TaskKind.RESEARCH: (
            "research",
            "survey",
        ),
        TaskKind.EVALUATION: (
            "benchmark",
            "evaluation",
            "verification",
        ),
        TaskKind.OPERATIONS: (
            "deploy",
            "ops",
            "operations",
            "runbook",
        ),
    }

    def infer(
        self,
        *,
        prompt: str,
        labels: tuple[str, ...] = (),
    ) -> TaskInference:
        """
        Infer a task kind from prompt text and optional labels.
        """
        normalized_prompt = prompt.strip().lower()
        normalized_labels = _normalize_identifiers(labels)

        if not normalized_prompt and not normalized_labels:
            return TaskInference(
                kind=TaskKind.UNKNOWN,
                confidence=0.0,
                reason=TaskInferenceReason.NO_SIGNAL,
            )

        best_kind = TaskKind.UNKNOWN
        best_score = 0.0
        best_terms: tuple[str, ...] = ()
        best_labels: tuple[str, ...] = ()
        best_reason = TaskInferenceReason.NO_SIGNAL

        for kind, terms in self._TERM_MAP.items():
            matched_terms = tuple(term for term in terms if term in normalized_prompt)
            label_terms = self._LABEL_MAP.get(kind, ())
            matched_labels = tuple(label for label in normalized_labels if label in label_terms)

            score = (len(matched_terms) * 0.18) + (len(matched_labels) * 0.27)
            score = min(score, 0.99)

            if score <= 0.0:
                continue

            if score > best_score:
                best_kind = kind
                best_score = score
                best_terms = matched_terms
                best_labels = matched_labels
                best_reason = (
                    TaskInferenceReason.LABEL_MATCH
                    if matched_labels and not matched_terms
                    else TaskInferenceReason.KEYWORD_MATCH
                )

        if best_kind == TaskKind.UNKNOWN:
            return TaskInference(
                kind=TaskKind.UNKNOWN,
                confidence=0.0,
                reason=TaskInferenceReason.NO_SIGNAL,
            )

        if len(best_terms) >= 2 or len(best_labels) >= 2:
            best_score = max(best_score, 0.6)

        return TaskInference(
            kind=best_kind,
            confidence=min(best_score, 1.0),
            reason=best_reason,
            matched_terms=best_terms,
            matched_labels=best_labels,
        )


class PrimaryBrainRuntime:
    """
    Prepare and optionally invoke the default primary-brain lane.

    Wave 1 keeps this path deliberately bounded:
    - it plans one default `gpt-oss-20b` style invocation
    - it only calls a provider when one is actually configured
    - it records receipts when a provider call really happened
    - it never fabricates model output when no provider exists
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
        self._catalog = build_primary_brain_catalog()
        self._registry = registry or BrainManifestRegistry()
        self._normalizer = normalizer or BrainMessageNormalizer()
        self._renderer = renderer or HarmonyRenderer()

        manifests = config.brains.manifests or self._catalog.manifests
        for manifest in manifests:
            self._registry.register(manifest)

        self._router = router or BrainRouter(self._registry)

    def plan(
        self,
        *,
        task: TaskRecord,
        route: RoutingDecision,
        pack_name: str,
    ) -> PrimaryBrainPlan:
        """
        Build the default primary-brain invocation plan for a task.
        """
        required_capabilities = _required_capabilities_for_pack(pack_name)
        decision = self._router.route(
            BrainRoutingRequest(
                required_role=BrainRole.PRIMARY,
                required_capabilities=required_capabilities,
                pack_name=pack_name,
                preferred_labels=task.request.labels,
            )
        )

        manifest = decision.selected or self._catalog.default_manifest()
        request = BrainInvocationRequest.create(
            brain_name=manifest.brain_name,
            role=BrainRole.PRIMARY,
            prompt=task.request.input.prompt,
            task_id=task.request.task_id,
            pack_name=pack_name,
            labels=task.request.labels,
            metadata={
                "route_capability_name": route.capability_name,
                "route_confidence": route.confidence,
                "route_reason": route.reason.value,
                "required_capabilities": tuple(
                    capability.value for capability in required_capabilities
                ),
                "task_kind": task.request.kind.value,
            },
        )
        rendered_prompt = self._renderer.render_request(
            request,
            developer_prompt=_developer_prompt_for_pack(pack_name),
            normalizer=self._normalizer,
        )
        return PrimaryBrainPlan(
            manifest=manifest,
            request=request,
            rendered_prompt=rendered_prompt,
            required_capabilities=required_capabilities,
            route_capability_name=route.capability_name,
        )

    def invoke(
        self,
        *,
        plan: PrimaryBrainPlan,
        providers: Mapping[str, BrainProvider],
        receipt_ledger: BrainInvocationReceiptLedger | None = None,
    ) -> PrimaryBrainOutcome:
        """
        Attempt to invoke the selected primary brain.
        """
        provider = providers.get(plan.manifest.provider_name)
        if provider is None:
            return PrimaryBrainOutcome(
                plan=plan,
                provider_name=plan.manifest.provider_name,
                failure_message=(
                    "Primary brain provider is not configured for this runtime."
                ),
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
                    escalation_reason=None,
                    metadata={"failure_stage": "provider_invoke"},
                )
            return PrimaryBrainOutcome(
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

        return PrimaryBrainOutcome(
            plan=plan,
            provider_name=response.provider_name,
            result=response.result,
            receipt=receipt,
            failure_message=None if response.result.succeeded else response.result.failure.message if response.result.failure else None,
            skipped=False,
        )

    def build_providers(self) -> dict[str, BrainProvider]:
        """
        Build provider instances for brain-enabled runtime execution.

        Wave 1 intentionally keeps this registry conservative. Providers
        are only instantiated from typed config. No secret resolution or
        transport wiring happens here yet, so unavailable providers remain
        visibly absent instead of being faked.
        """
        providers: dict[str, BrainProvider] = {}
        for provider_config in self._config.brains.providers:
            if not provider_config.enabled:
                continue
            _ = provider_config
        return providers


def _required_capabilities_for_pack(pack_name: str) -> tuple[BrainCapability, ...]:
    normalized_pack_name = pack_name.strip().lower().replace(" ", "-")
    if normalized_pack_name == "programming":
        return (
            BrainCapability.TEXT_GENERATION,
            BrainCapability.CODE_GENERATION,
            BrainCapability.TOOL_PLANNING,
        )
    if normalized_pack_name == "architecture":
        return (
            BrainCapability.TEXT_GENERATION,
            BrainCapability.LONG_CONTEXT_REASONING,
            BrainCapability.STRUCTURED_OUTPUT,
        )
    return (BrainCapability.TEXT_GENERATION,)


def _developer_prompt_for_pack(pack_name: str) -> str:
    normalized_pack_name = pack_name.strip().lower().replace(" ", "-")
    if normalized_pack_name == "programming":
        return (
            "Operate as the default BlackFox primary programming brain. "
            "Prefer repository inspection, bounded patch planning, test awareness, "
            "and explicit assumptions."
        )
    if normalized_pack_name == "architecture":
        return (
            "Operate as the default BlackFox primary architecture brain. "
            "Prefer explicit boundaries, decision rationale, interface clarity, "
            "and verification-oriented thinking."
        )
    return "Operate as the default BlackFox primary reasoning brain."


def _failure_kind_from_error(error: Exception) -> BrainFailureKind:
    if isinstance(error, BrainProviderUnavailableError):
        return BrainFailureKind.PROVIDER_UNAVAILABLE
    if isinstance(error, BrainProviderTimeoutError):
        return BrainFailureKind.TIMEOUT
    if isinstance(error, BrainProviderConfigurationError):
        return BrainFailureKind.INVALID_REQUEST
    return BrainFailureKind.EXECUTION_ERROR


def _normalize_identifiers(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = value.strip().lower()
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)
