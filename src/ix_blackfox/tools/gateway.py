from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, Self

from ix_blackfox.tools.contracts import (
    ToolFailure,
    ToolFailureKind,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolInvocationStatus,
)
from ix_blackfox.tools.manifest import ToolManifest, ToolManifestRegistry
from ix_blackfox.tools.policy import (
    ToolPolicyDecision,
    ToolPolicyEvaluation,
    ToolPolicyEvaluator,
)
from ix_blackfox.tools.policy_file import ToolPolicyDocument
from ix_blackfox.tools.receipts import ToolInvocationReceiptLedger


class ToolGatewayError(RuntimeError):
    """
    Raised when the governed tool gateway cannot resolve or execute a tool.
    """


class ToolInvoker(Protocol):
    """
    Runtime protocol implemented by concrete governed tools.
    """

    @property
    def manifest(self) -> ToolManifest:
        """
        Return the tool manifest exposed through the gateway.
        """
        ...

    def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        """
        Execute the tool request after gateway policy allows execution.
        """
        ...


@dataclass(frozen=True, slots=True)
class ToolGatewayInvocationReport:
    """
    Complete report for one governed tool gateway invocation.

    This report is the operator-facing bridge between:
    - the tool request
    - the selected manifest
    - deterministic policy evaluation
    - terminal tool result
    - receipt-chain verification status
    """

    request: ToolInvocationRequest
    manifest: ToolManifest
    policy_evaluation: ToolPolicyEvaluation
    result: ToolInvocationResult
    receipt_chain_verified: bool
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def allowed_by_policy(self) -> bool:
        return self.policy_evaluation.decision is ToolPolicyDecision.ALLOW

    @property
    def blocked_by_policy(self) -> bool:
        return self.policy_evaluation.decision is ToolPolicyDecision.BLOCK

    @property
    def review_required_by_policy(self) -> bool:
        return self.policy_evaluation.decision is ToolPolicyDecision.REVIEW_REQUIRED

    @property
    def succeeded(self) -> bool:
        return self.result.status is ToolInvocationStatus.SUCCEEDED

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request.to_dict(),
            "manifest": self.manifest.to_dict(),
            "policy_evaluation": self.policy_evaluation.to_dict(),
            "result": self.result.to_dict(),
            "allowed_by_policy": self.allowed_by_policy,
            "blocked_by_policy": self.blocked_by_policy,
            "review_required_by_policy": self.review_required_by_policy,
            "receipt_chain_verified": self.receipt_chain_verified,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class GovernedToolGateway:
    """
    Deterministic gateway for governed BlackFox tool invocation.

    The gateway is deliberately boring:
    1. Resolve the manifest.
    2. Evaluate policy.
    3. Record policy receipts.
    4. Return BLOCKED / REVIEW_REQUIRED without executing when policy says so.
    5. Invoke the concrete tool only when policy allows.
    6. Record terminal tool result and emitted artifacts.
    7. Verify the invocation receipt chain.

    This gives Wave 2 a real control plane instead of letting tools be called
    ad hoc from scattered runtime code.
    """

    registry: ToolManifestRegistry = field(default_factory=ToolManifestRegistry)
    policy_evaluator: ToolPolicyEvaluator = field(default_factory=ToolPolicyEvaluator)
    receipt_ledger: ToolInvocationReceiptLedger = field(
        default_factory=ToolInvocationReceiptLedger
    )
    _invokers: dict[str, ToolInvoker] = field(default_factory=dict)

    @classmethod
    def from_policy_document(
        cls,
        *,
        policy_document: ToolPolicyDocument,
        invokers: tuple[ToolInvoker, ...] = (),
        receipt_ledger: ToolInvocationReceiptLedger | None = None,
    ) -> Self:
        gateway = cls(
            policy_evaluator=ToolPolicyEvaluator(
                config=policy_document.to_tool_policy_evaluator_config()
            ),
            receipt_ledger=receipt_ledger or ToolInvocationReceiptLedger(),
        )

        for invoker in invokers:
            gateway.register_tool(invoker)

        return gateway

    def register_tool(
        self,
        invoker: ToolInvoker,
        *,
        replace_existing: bool = False,
    ) -> None:
        manifest = invoker.manifest
        self.registry.register(manifest, replace_existing=replace_existing)

        if manifest.tool_id in self._invokers and not replace_existing:
            raise ValueError(f"Tool invoker already registered: {manifest.tool_id!r}.")

        self._invokers[manifest.tool_id] = invoker

    def contains_tool(self, tool_id: str) -> bool:
        return self.registry.contains(tool_id) and tool_id in self._invokers

    def list_tool_ids(self) -> tuple[str, ...]:
        return self.registry.list_tool_ids()

    def invoke(self, request: ToolInvocationRequest) -> ToolGatewayInvocationReport:
        manifest = self._resolve_manifest(request)
        evaluation = self.policy_evaluator.evaluate(
            manifest=manifest,
            request=request,
        )
        self.receipt_ledger.record_policy_evaluation(
            evaluation=evaluation,
            request=request,
            actor="tools.gateway",
        )

        if evaluation.decision is ToolPolicyDecision.BLOCK:
            result = self._blocked_result(
                request=request,
                evaluation=evaluation,
            )
            self.receipt_ledger.record_invocation_result(
                result=result,
                request=request,
                actor="tools.gateway",
            )
            return self._report(
                request=request,
                manifest=manifest,
                evaluation=evaluation,
                result=result,
                metadata={"gateway_decision": "blocked_without_execution"},
            )

        if evaluation.decision is ToolPolicyDecision.REVIEW_REQUIRED:
            result = self._review_required_result(
                request=request,
                evaluation=evaluation,
            )
            self.receipt_ledger.record_invocation_result(
                result=result,
                request=request,
                actor="tools.gateway",
            )
            return self._report(
                request=request,
                manifest=manifest,
                evaluation=evaluation,
                result=result,
                metadata={"gateway_decision": "review_required_without_execution"},
            )

        invoker = self._resolve_invoker(request.tool_id)
        self.receipt_ledger.record_invocation_started(
            request=request,
            actor="tools.gateway",
            metadata={"manifest_version": manifest.version},
        )

        try:
            result = invoker.invoke(request)
        except TimeoutError as exc:
            result = ToolInvocationResult.failed(
                request=request,
                status=ToolInvocationStatus.TIMED_OUT,
                failure=ToolFailure(
                    kind=ToolFailureKind.TIMEOUT,
                    message=f"Tool invocation timed out: {exc}",
                    retryable=True,
                ),
            )
        except Exception as exc:
            result = ToolInvocationResult.failed(
                request=request,
                status=ToolInvocationStatus.FAILED,
                failure=ToolFailure(
                    kind=ToolFailureKind.EXECUTION_ERROR,
                    message=f"Tool invocation failed: {exc}",
                    retryable=False,
                    metadata={"exception_type": type(exc).__name__},
                ),
            )

        self.receipt_ledger.record_invocation_result(
            result=result,
            request=request,
            actor="tools.gateway",
        )

        for artifact in result.artifacts:
            self.receipt_ledger.record_artifact_emitted(
                result=result,
                artifact_name=artifact.name,
                artifact_uri=artifact.uri,
                actor="tools.gateway",
                metadata={
                    "artifact_id": artifact.artifact_id,
                    "media_type": artifact.media_type,
                    "sha256": artifact.sha256,
                },
            )

        return self._report(
            request=request,
            manifest=manifest,
            evaluation=evaluation,
            result=result,
            metadata={"gateway_decision": "executed"},
        )

    def evaluate_only(self, request: ToolInvocationRequest) -> ToolPolicyEvaluation:
        manifest = self._resolve_manifest(request)
        return self.policy_evaluator.evaluate(
            manifest=manifest,
            request=request,
        )

    def _resolve_manifest(self, request: ToolInvocationRequest) -> ToolManifest:
        try:
            return self.registry.get(request.tool_id)
        except KeyError as exc:
            synthetic_manifest = ToolManifest(
                tool_id=request.tool_id,
                name="Unknown Tool",
                version="0.0.0",
                summary="Synthetic manifest for unknown tool failure reporting.",
                capabilities=(request.capability,),
            )
            evaluation = self.policy_evaluator.evaluate(
                manifest=synthetic_manifest,
                request=request,
            )
            self.receipt_ledger.record_policy_evaluation(
                evaluation=evaluation,
                request=request,
                actor="tools.gateway",
                metadata={"resolution_error": str(exc)},
            )
            raise ToolGatewayError(f"Unknown tool requested: {request.tool_id!r}.") from exc

    def _resolve_invoker(self, tool_id: str) -> ToolInvoker:
        try:
            return self._invokers[tool_id]
        except KeyError as exc:
            raise ToolGatewayError(
                f"No concrete invoker registered for tool: {tool_id!r}."
            ) from exc

    def _blocked_result(
        self,
        *,
        request: ToolInvocationRequest,
        evaluation: ToolPolicyEvaluation,
    ) -> ToolInvocationResult:
        return ToolInvocationResult.failed(
            request=request,
            status=ToolInvocationStatus.BLOCKED,
            failure=ToolFailure(
                kind=ToolFailureKind.POLICY_BLOCKED,
                message="Tool invocation blocked by gateway policy.",
                retryable=False,
                metadata={
                    "decision": evaluation.decision.value,
                    "reason_codes": list(evaluation.reason_codes),
                    "risk_level": evaluation.risk_assessment.level.value,
                    "risk_score": evaluation.risk_assessment.score,
                },
            ),
            output={
                "policy_decision": evaluation.decision.value,
                "reason_codes": list(evaluation.reason_codes),
                "risk_assessment": evaluation.risk_assessment.to_dict(),
            },
        )

    def _review_required_result(
        self,
        *,
        request: ToolInvocationRequest,
        evaluation: ToolPolicyEvaluation,
    ) -> ToolInvocationResult:
        return ToolInvocationResult.failed(
            request=request,
            status=ToolInvocationStatus.REVIEW_REQUIRED,
            failure=ToolFailure(
                kind=ToolFailureKind.APPROVAL_REQUIRED,
                message="Tool invocation requires operator review before execution.",
                retryable=False,
                metadata={
                    "decision": evaluation.decision.value,
                    "reason_codes": list(evaluation.reason_codes),
                    "risk_level": evaluation.risk_assessment.level.value,
                    "risk_score": evaluation.risk_assessment.score,
                },
            ),
            output={
                "policy_decision": evaluation.decision.value,
                "reason_codes": list(evaluation.reason_codes),
                "risk_assessment": evaluation.risk_assessment.to_dict(),
            },
        )

    def _report(
        self,
        *,
        request: ToolInvocationRequest,
        manifest: ToolManifest,
        evaluation: ToolPolicyEvaluation,
        result: ToolInvocationResult,
        metadata: Mapping[str, Any],
    ) -> ToolGatewayInvocationReport:
        return ToolGatewayInvocationReport(
            request=request,
            manifest=manifest,
            policy_evaluation=evaluation,
            result=result,
            receipt_chain_verified=self.receipt_ledger.verify_invocation_chain(
                request.invocation_id
            ),
            metadata=dict(metadata),
        )
