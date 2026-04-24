from __future__ import annotations

import json
from dataclasses import dataclass
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
    SafeguardAssessment,
    SafeguardDisposition,
    SafeguardEvidenceKind,
    SafeguardEvidenceRef,
    SafeguardFinding,
    SafeguardFindingSeverity,
    build_wave1_core_brain_catalog,
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
class SafeguardPlan:
    """
    Planned safeguard invocation prepared before policy merge.

    Attributes
    ----------
    manifest:
        Selected safeguard brain manifest.
    request:
        Normalized invocation request.
    rendered_prompt:
        Rendered safety prompt envelope.
    source_pack_name:
        Pack whose work is being safety-classified.
    route_capability_name:
        Capability route that led to the safeguard side-check.
    candidate_output:
        Optional candidate pack or brain output being reviewed.
    """

    manifest: BrainManifest
    request: BrainInvocationRequest
    rendered_prompt: str
    source_pack_name: str
    route_capability_name: str
    candidate_output: str | None = None


@dataclass(frozen=True, slots=True)
class SafeguardOutcome:
    """
    Result of attempting to invoke the safeguard lane.

    Attributes
    ----------
    plan:
        Planned safeguard invocation.
    provider_name:
        Effective provider used, if any.
    result:
        Normalized provider result when a call was attempted.
    receipt:
        Auditable brain receipt when a call was attempted.
    assessment:
        Structured semantic-safety assessment when normalization succeeded.
    failure_message:
        Human-readable invocation failure summary when invocation did not succeed.
    skipped:
        Whether safeguard invocation was skipped rather than attempted.
    """

    plan: SafeguardPlan
    provider_name: str | None = None
    result: BrainInvocationResult | None = None
    receipt: BrainInvocationReceipt | None = None
    assessment: SafeguardAssessment | None = None
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


class SafeguardRuntime:
    """
    Prepare and optionally invoke the semantic safeguard lane.

    Wave 1 keeps this path deliberately bounded:
    - one explicit safety role
    - one structured JSON-oriented prompt contract
    - advisory findings only
    - deterministic normalization into safeguard assessment objects
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
        self._catalog = build_wave1_core_brain_catalog()
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
        candidate_output: str | None = None,
    ) -> SafeguardPlan:
        """
        Build the safeguard side-check plan for a task and optional output.
        """
        decision = self._router.route(
            BrainRoutingRequest(
                required_role=BrainRole.SAFETY,
                required_capabilities=(
                    BrainCapability.SAFETY_CLASSIFICATION,
                    BrainCapability.STRUCTURED_OUTPUT,
                ),
                pack_name=pack_name,
                preferred_labels=task.request.labels,
            )
        )

        manifest = decision.selected
        if manifest is None:
            catalog_brain_name = self._catalog.brain_for_role(BrainRole.SAFETY)
            if catalog_brain_name is None:
                raise RuntimeError("Wave 1 safeguard default is not available.")
            manifest = self._catalog.get_manifest(catalog_brain_name)
            if manifest is None:
                raise RuntimeError("Wave 1 safeguard manifest is not available.")

        prompt = self._build_prompt(
            task=task,
            route=route,
            pack_name=pack_name,
            candidate_output=candidate_output,
        )
        request = BrainInvocationRequest.create(
            brain_name=manifest.brain_name,
            role=BrainRole.SAFETY,
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
                "safeguard_schema_version": "1",
            },
        )
        rendered_prompt = self._renderer.render_request(
            request,
            developer_prompt=_safeguard_developer_prompt(),
            normalizer=self._normalizer,
        )
        return SafeguardPlan(
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
        plan: SafeguardPlan,
        providers: Mapping[str, BrainProvider],
        receipt_ledger: BrainInvocationReceiptLedger | None = None,
    ) -> SafeguardOutcome:
        """
        Attempt to invoke the safeguard side-check.
        """
        provider = providers.get(plan.manifest.provider_name)
        if provider is None:
            return SafeguardOutcome(
                plan=plan,
                provider_name=plan.manifest.provider_name,
                failure_message="Safeguard provider is not configured for this runtime.",
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
            return SafeguardOutcome(
                plan=plan,
                provider_name=plan.manifest.provider_name,
                result=failure_result,
                receipt=receipt,
                assessment=None,
                failure_message=str(error),
                skipped=False,
            )

        assessment = _normalize_assessment(
            plan=plan,
            result=response.result,
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
                safety_labels=() if assessment is None else assessment.policy_tags(),
                metadata=response.metadata,
            )

        return SafeguardOutcome(
            plan=plan,
            provider_name=response.provider_name,
            result=response.result,
            receipt=receipt,
            assessment=assessment,
            failure_message=None if response.result.succeeded else response.result.failure.message if response.result.failure else None,
            skipped=False,
        )

    def _build_prompt(
        self,
        *,
        task: TaskRecord,
        route: RoutingDecision,
        pack_name: str,
        candidate_output: str | None,
    ) -> str:
        lines = [
            "Classify the request for semantic safety risk.",
            "",
            "Return strict JSON with this shape:",
            '{',
            '  "advisory_disposition": "allow|review|block",',
            '  "findings": [',
            "    {",
            '      "code": "short-code",',
            '      "severity": "info|low|moderate|high|critical",',
            '      "summary": "human summary",',
            '      "policy_tags": ["tag"],',
            '      "evidence": [{"kind": "text_span", "value": "quoted signal"}],',
            '      "confidence": 0.0,',
            '      "uncertainty": 0.0',
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
                    "Candidate output under review:",
                    normalized_candidate_output,
                ]
            )

        return "\n".join(lines)

def _normalize_assessment(
    *,
    plan: SafeguardPlan,
    result: BrainInvocationResult,
) -> SafeguardAssessment | None:
    if result.status is BrainInvocationStatus.FAILED:
        return None

    if result.status is BrainInvocationStatus.REFUSED:
        refusal_message = (
            result.failure.message
            if result.failure is not None
            else "Safeguard provider refused the request."
        )
        finding = SafeguardFinding.create(
            code="safeguard-provider-refusal",
            severity=SafeguardFindingSeverity.HIGH,
            summary=refusal_message,
            policy_tags=("provider-refusal", "safety-block"),
            evidence=(
                SafeguardEvidenceRef(
                    kind=SafeguardEvidenceKind.PROVIDER_MESSAGE,
                    value=refusal_message,
                ),
            ),
            confidence=0.9,
            uncertainty=0.05,
        )
        return SafeguardAssessment.from_findings(
            brain_name=plan.manifest.brain_name,
            invocation_id=plan.request.invocation_id,
            findings=(finding,),
            metadata={"source": "provider_refusal"},
        )

    payload = _parse_json_object(result.output_text)
    if payload is None:
        finding = SafeguardFinding.create(
            code="unparseable-safeguard-output",
            severity=SafeguardFindingSeverity.MODERATE,
            summary="Safeguard output was not parseable as structured JSON.",
            policy_tags=("unparseable-output", "review"),
            evidence=(
                SafeguardEvidenceRef(
                    kind=SafeguardEvidenceKind.MODEL_RATIONALE,
                    value=_truncate_text(result.output_text or "(empty output)"),
                    excerpt=_truncate_text(result.output_text or "(empty output)"),
                ),
            ),
            confidence=0.75,
            uncertainty=0.2,
        )
        return SafeguardAssessment.from_findings(
            brain_name=plan.manifest.brain_name,
            invocation_id=plan.request.invocation_id,
            findings=(finding,),
            metadata={"source": "fallback_unparseable"},
        )

    findings = _parse_findings(payload.get("findings"))
    metadata = dict(payload.get("metadata", {})) if isinstance(payload.get("metadata"), dict) else {}
    parsed_disposition = _parse_disposition(payload.get("advisory_disposition"))

    if not findings:
        if parsed_disposition is SafeguardDisposition.ALLOW:
            return SafeguardAssessment(
                brain_name=plan.manifest.brain_name,
                invocation_id=plan.request.invocation_id,
                advisory_disposition=SafeguardDisposition.ALLOW,
                findings=(),
                metadata=metadata,
            )

        synthesized_finding = SafeguardFinding.create(
            code="implicit-safeguard-disposition",
            severity=_severity_for_disposition(parsed_disposition),
            summary="Structured safeguard disposition was returned without explicit findings.",
            policy_tags=("implicit-disposition", parsed_disposition.value),
            evidence=(
                SafeguardEvidenceRef(
                    kind=SafeguardEvidenceKind.STRUCTURED_SIGNAL,
                    value=parsed_disposition.value,
                ),
            ),
            confidence=0.65,
            uncertainty=0.25,
        )
        findings = (synthesized_finding,)

    inferred = SafeguardAssessment.from_findings(
        brain_name=plan.manifest.brain_name,
        invocation_id=plan.request.invocation_id,
        findings=findings,
        metadata=metadata,
    )
    merged_disposition = _max_disposition(
        parsed_disposition,
        inferred.advisory_disposition,
    )
    return SafeguardAssessment(
        brain_name=inferred.brain_name,
        invocation_id=inferred.invocation_id,
        advisory_disposition=merged_disposition,
        findings=inferred.findings,
        metadata=inferred.metadata,
    )


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


def _parse_findings(value: Any) -> tuple[SafeguardFinding, ...]:
    if not isinstance(value, list):
        return ()

    findings: list[SafeguardFinding] = []
    for item in value:
        if not isinstance(item, dict):
            continue

        code = _normalize_optional_text(item.get("code"))
        summary = _normalize_optional_text(item.get("summary"))
        severity = _parse_severity(item.get("severity"))

        if code is None or summary is None:
            continue

        findings.append(
            SafeguardFinding.create(
                code=code,
                severity=severity,
                summary=summary,
                policy_tags=_parse_strings(item.get("policy_tags")),
                evidence=_parse_evidence(item.get("evidence")),
                confidence=_parse_probability(item.get("confidence"), default=0.5),
                uncertainty=_parse_probability(item.get("uncertainty"), default=0.0),
                metadata=dict(item.get("metadata", {})) if isinstance(item.get("metadata"), dict) else {},
            )
        )

    return tuple(findings)


def _parse_evidence(value: Any) -> tuple[SafeguardEvidenceRef, ...]:
    if not isinstance(value, list):
        return ()

    evidence_items: list[SafeguardEvidenceRef] = []
    for item in value:
        if not isinstance(item, dict):
            continue

        kind = _parse_evidence_kind(item.get("kind"))
        evidence_value = _normalize_optional_text(item.get("value"))
        if evidence_value is None:
            continue

        evidence_items.append(
            SafeguardEvidenceRef(
                kind=kind,
                value=evidence_value,
                locator=_normalize_optional_text(item.get("locator")),
                excerpt=_normalize_optional_text(item.get("excerpt")),
                metadata=dict(item.get("metadata", {})) if isinstance(item.get("metadata"), dict) else {},
            )
        )

    return tuple(evidence_items)


def _parse_strings(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()

    raw_items: tuple[Any, ...]
    if isinstance(value, str):
        raw_items = (value,)
    elif isinstance(value, (list, tuple)):
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


def _parse_disposition(value: Any) -> SafeguardDisposition:
    normalized = _normalize_optional_text(value)
    if normalized is None:
        return SafeguardDisposition.ALLOW

    cleaned = normalized.lower()
    mapping = {
        SafeguardDisposition.ALLOW.value: SafeguardDisposition.ALLOW,
        SafeguardDisposition.REVIEW.value: SafeguardDisposition.REVIEW,
        SafeguardDisposition.BLOCK.value: SafeguardDisposition.BLOCK,
    }
    return mapping.get(cleaned, SafeguardDisposition.REVIEW)


def _parse_severity(value: Any) -> SafeguardFindingSeverity:
    normalized = _normalize_optional_text(value)
    if normalized is None:
        return SafeguardFindingSeverity.MODERATE

    cleaned = normalized.lower()
    mapping = {
        SafeguardFindingSeverity.INFO.value: SafeguardFindingSeverity.INFO,
        SafeguardFindingSeverity.LOW.value: SafeguardFindingSeverity.LOW,
        SafeguardFindingSeverity.MODERATE.value: SafeguardFindingSeverity.MODERATE,
        SafeguardFindingSeverity.HIGH.value: SafeguardFindingSeverity.HIGH,
        SafeguardFindingSeverity.CRITICAL.value: SafeguardFindingSeverity.CRITICAL,
    }
    return mapping.get(cleaned, SafeguardFindingSeverity.MODERATE)


def _parse_evidence_kind(value: Any) -> SafeguardEvidenceKind:
    normalized = _normalize_optional_text(value)
    if normalized is None:
        return SafeguardEvidenceKind.STRUCTURED_SIGNAL

    cleaned = normalized.lower()
    mapping = {
        kind.value: kind for kind in SafeguardEvidenceKind
    }
    return mapping.get(cleaned, SafeguardEvidenceKind.STRUCTURED_SIGNAL)


def _parse_probability(value: Any, *, default: float) -> float:
    if value is None:
        return default
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return default
    return min(max(numeric, 0.0), 1.0)


def _severity_for_disposition(
    disposition: SafeguardDisposition,
) -> SafeguardFindingSeverity:
    if disposition is SafeguardDisposition.BLOCK:
        return SafeguardFindingSeverity.HIGH
    if disposition is SafeguardDisposition.REVIEW:
        return SafeguardFindingSeverity.MODERATE
    return SafeguardFindingSeverity.LOW


def _max_disposition(
    left: SafeguardDisposition,
    right: SafeguardDisposition,
) -> SafeguardDisposition:
    order = {
        SafeguardDisposition.ALLOW: 1,
        SafeguardDisposition.REVIEW: 2,
        SafeguardDisposition.BLOCK: 3,
    }
    return left if order[left] >= order[right] else right


def _failure_kind_from_error(error: Exception) -> BrainFailureKind:
    if isinstance(error, BrainProviderUnavailableError):
        return BrainFailureKind.PROVIDER_UNAVAILABLE
    if isinstance(error, BrainProviderTimeoutError):
        return BrainFailureKind.TIMEOUT
    if isinstance(error, BrainProviderConfigurationError):
        return BrainFailureKind.INVALID_REQUEST
    return BrainFailureKind.EXECUTION_ERROR


def _safeguard_developer_prompt() -> str:
    return (
        "Operate as the BlackFox semantic safety coprocessor. "
        "Return strict JSON only. Produce advisory semantic findings, "
        "not final policy authority. Deterministic governance remains sovereign."
    )


def _normalize_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def _truncate_text(value: str, *, limit: int = 240) -> str:
    if len(value) <= limit:
        return value
    return f"{value[: limit - 1].rstrip()}…"
