from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum, auto
import json
import os
from pathlib import Path
from typing import Any
from uuid import uuid4

from ix_blackfox.bus import InMemoryEventBus
from ix_blackfox.config import RuntimeConfig, load_runtime_config
from ix_blackfox.eval import (
    EvaluationContext,
    EvaluationFinding,
    EvaluationResult,
    EvaluationSeverity,
    EvidenceRecorder,
    OutputVerifier,
    RuleBasedEvaluator,
    VerificationContext,
    VerificationReport,
)
from ix_blackfox.kernel import (
    BlackFoxKernel,
    SharedStateStore,
    TaskKind,
    TaskPriority,
    TaskRecord,
    TaskRequest,
)
from ix_blackfox.memory import (
    ArtifactMemoryStore,
    EpisodicMemoryStore,
    SemanticMemoryStore,
    TraceMemoryStore,
)
from ix_blackfox.observability import JsonlStructuredLogger, LogLevel
from ix_blackfox.packs import BasePack, LoadedPack, PackContext, PackLoader, PackManifestRegistry
from ix_blackfox.packs.architecture import build_architecture_manifest
from ix_blackfox.packs.programming import build_programming_manifest
from ix_blackfox.sentinel import (
    ContradictionCheck,
    FailureLoopCheck,
    FailureLoopWindow,
    PolicyGuardrailCheck,
    PolicyObservation,
    SentinelContext,
    SentinelReport,
    SentinelRuntime,
    SentinelSeverity,
)
from ix_blackfox.switchboard import CapabilityRoute, CapabilitySwitchboard, RoutingDecision
from ix_blackfox.vault import (
    ProvenanceLedger,
    VaultStateStore,
    fingerprint_bytes,
)

from ix_blackfox.runtime.approval import (
    RuntimeApprovalResolution,
    RuntimeApprovalResolver,
)
from ix_blackfox.runtime.governance import (
    RuntimeGovernancePreflightEngine,
    RuntimeGovernancePreflightResult,
)
from ix_blackfox.runtime.inference import DeterministicTaskClassifier, TaskInference
from ix_blackfox.runtime.replay import ReplayObservation, TaskReplayGuard


class RuntimeRunStatus(StrEnum):
    """
    High-level run outcome classification.
    """

    PASSED = auto()
    NEEDS_REVIEW = auto()
    FAILED = auto()


@dataclass(frozen=True, slots=True)
class RuntimeRunReport:
    """
    Immutable end-to-end runtime run report.
    """

    session_id: str
    run_id: str
    task_id: str
    task_kind: TaskKind
    status: RuntimeRunStatus
    route: RoutingDecision | None
    pack_name: str | None
    task_summary: str
    evaluation_result: EvaluationResult
    verification_report: VerificationReport
    sentinel_report: SentinelReport
    replay_observation: ReplayObservation
    task_inference: TaskInference | None = None
    governance_preflight: RuntimeGovernancePreflightResult | None = None
    approval_resolution: RuntimeApprovalResolution | None = None
    produced_artifacts: tuple[str, ...] = field(default_factory=tuple)
    artifact_paths: dict[str, str] = field(default_factory=dict)
    trace_ids: tuple[str, ...] = field(default_factory=tuple)
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    report_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        route = None
        if self.route is not None:
            route = {
                "capability_name": self.route.capability_name,
                "confidence": self.route.confidence,
                "reason": self.route.reason.value,
                "task_id": self.route.task_id,
                "matched_labels": self.route.matched_labels,
            }

        inference = None
        if self.task_inference is not None:
            inference = {
                "kind": self.task_inference.kind.value,
                "confidence": self.task_inference.confidence,
                "reason": self.task_inference.reason.value,
                "matched_terms": self.task_inference.matched_terms,
                "matched_labels": self.task_inference.matched_labels,
            }

        governance_preflight = None
        if self.governance_preflight is not None:
            governance_preflight = self.governance_preflight.to_dict()

        approval_resolution = None
        if self.approval_resolution is not None:
            approval_resolution = self.approval_resolution.to_dict()

        return {
            "session_id": self.session_id,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "task_kind": self.task_kind.value,
            "status": self.status.value,
            "route": route,
            "pack_name": self.pack_name,
            "task_summary": self.task_summary,
            "evaluation_result": _evaluation_to_dict(self.evaluation_result),
            "verification_report": _verification_to_dict(self.verification_report),
            "sentinel_report": _sentinel_to_dict(self.sentinel_report),
            "replay_observation": asdict(self.replay_observation),
            "task_inference": inference,
            "governance_preflight": governance_preflight,
            "approval_resolution": approval_resolution,
            "produced_artifacts": self.produced_artifacts,
            "artifact_paths": self.artifact_paths,
            "trace_ids": self.trace_ids,
            "evidence_ids": self.evidence_ids,
            "report_path": self.report_path,
        }


class BlackFoxRuntime:
    """
    End-to-end deterministic runtime composition for IX-BlackFox.

    This is the missing execution spine that turns the existing sovereign
    subsystems into one auditable run path.
    """

    def __init__(
        self,
        *,
        config: RuntimeConfig,
        kernel: BlackFoxKernel,
        bus: InMemoryEventBus,
        shared_state: SharedStateStore,
        switchboard: CapabilitySwitchboard,
        manifest_registry: PackManifestRegistry,
        pack_loader: PackLoader,
        trace_memory: TraceMemoryStore,
        artifact_memory: ArtifactMemoryStore,
        episodic_memory: EpisodicMemoryStore,
        semantic_memory: SemanticMemoryStore,
        sentinel: SentinelRuntime,
        evidence: EvidenceRecorder,
        verifier: OutputVerifier,
        logger: JsonlStructuredLogger,
        provenance: ProvenanceLedger,
        state_store: VaultStateStore,
        replay_guard: TaskReplayGuard,
        classifier: DeterministicTaskClassifier,
        governance_preflight: RuntimeGovernancePreflightEngine,
        approval_resolver: RuntimeApprovalResolver,
    ) -> None:
        self._config = config
        self._kernel = kernel
        self._bus = bus
        self._shared_state = shared_state
        self._switchboard = switchboard
        self._manifest_registry = manifest_registry
        self._pack_loader = pack_loader
        self._trace_memory = trace_memory
        self._artifact_memory = artifact_memory
        self._episodic_memory = episodic_memory
        self._semantic_memory = semantic_memory
        self._sentinel = sentinel
        self._evidence = evidence
        self._verifier = verifier
        self._logger = logger
        self._provenance = provenance
        self._state_store = state_store
        self._replay_guard = replay_guard
        self._classifier = classifier
        self._governance_preflight = governance_preflight
        self._approval_resolver = approval_resolver
        self._session_id = f"session-{uuid4().hex}"
        self._loaded_packs: dict[str, BasePack] = {}

    @classmethod
    def create_default(
        cls,
        *,
        root_dir: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> BlackFoxRuntime:
        """
        Build a default fully-wired BlackFox runtime.
        """
        config = load_runtime_config(root_dir=root_dir, env=env or {})
        kernel = BlackFoxKernel(config)
        bus = InMemoryEventBus()
        shared_state = SharedStateStore()
        switchboard = CapabilitySwitchboard()
        registry = PackManifestRegistry()
        loader = PackLoader()
        trace_memory = TraceMemoryStore()
        artifact_memory = ArtifactMemoryStore()
        episodic_memory = EpisodicMemoryStore()
        semantic_memory = SemanticMemoryStore()
        sentinel = SentinelRuntime()
        evidence = EvidenceRecorder()
        verifier = OutputVerifier()
        logger = JsonlStructuredLogger(config)
        provenance = ProvenanceLedger()
        state_secret = os.environ.get(
            "BLACKFOX_STATE_SECRET",
            f"{config.app_name}:{config.environment}:state",
        )
        state_store = VaultStateStore(
            root_dir=config.paths.state_dir / "vault-runs",
            secret=state_secret,
            purpose_namespace="blackfox-runs",
        )
        replay_guard = TaskReplayGuard(window_size=128)
        classifier = DeterministicTaskClassifier()
        governance_preflight = RuntimeGovernancePreflightEngine()
        approval_resolver = RuntimeApprovalResolver()

        runtime = cls(
            config=config,
            kernel=kernel,
            bus=bus,
            shared_state=shared_state,
            switchboard=switchboard,
            manifest_registry=registry,
            pack_loader=loader,
            trace_memory=trace_memory,
            artifact_memory=artifact_memory,
            episodic_memory=episodic_memory,
            semantic_memory=semantic_memory,
            sentinel=sentinel,
            evidence=evidence,
            verifier=verifier,
            logger=logger,
            provenance=provenance,
            state_store=state_store,
            replay_guard=replay_guard,
            classifier=classifier,
            governance_preflight=governance_preflight,
            approval_resolver=approval_resolver,
        )
        runtime._register_builtin_packs()
        runtime._register_builtin_checks()
        return runtime

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def config(self) -> RuntimeConfig:
        return self._config

    def run_prompt(
        self,
        *,
        prompt: str,
        kind: TaskKind = TaskKind.UNKNOWN,
        priority: TaskPriority = TaskPriority.NORMAL,
        labels: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
        attachments: tuple[str, ...] = (),
    ) -> RuntimeRunReport:
        """
        Create and execute a task request from a prompt.
        """
        request = TaskRequest.create(
            prompt=prompt,
            kind=kind,
            priority=priority,
            labels=labels,
            metadata=metadata,
            attachments=attachments,
        )
        return self.run_task(request)

    def run_task(self, request: TaskRequest) -> RuntimeRunReport:
        """
        Execute one task through the BlackFox runtime spine.
        """
        self._kernel.start()
        self._shared_state.put("runtime", "session_id", self._session_id, source="runtime")

        inference: TaskInference | None = None
        normalized_request = request
        if request.kind == TaskKind.UNKNOWN:
            inference = self._classifier.infer(
                prompt=request.input.prompt,
                labels=request.labels,
            )
            if inference.kind != TaskKind.UNKNOWN:
                normalized_request = replace(request, kind=inference.kind)

        task = TaskRecord(request=normalized_request).mark_ready().mark_running()
        replay_observation = self._replay_guard.observe(task.request)
        route = self._switchboard.route(task.request)

        self._append_trace(
            correlation_id=task.request.task_id,
            stage="intake",
            message="Accepted task into runtime.",
            source="runtime",
            data={
                "task_kind": task.request.kind.value,
                "priority": int(task.request.priority),
                "labels": task.request.labels,
            },
        )

        if inference is not None:
            self._append_trace(
                correlation_id=task.request.task_id,
                stage="inference",
                message=(
                    f"Inferred task kind '{inference.kind.value}' with confidence "
                    f"{inference.confidence:.2f}."
                ),
                source="runtime",
                data={
                    "kind": inference.kind.value,
                    "confidence": inference.confidence,
                    "reason": inference.reason.value,
                    "matched_terms": inference.matched_terms,
                    "matched_labels": inference.matched_labels,
                },
            )

        if route is None:
            self._append_trace(
                correlation_id=task.request.task_id,
                stage="routing",
                message="No capability route matched the task.",
                level="error",
                source="runtime",
            )
            sentinel_report = self._sentinel.evaluate(
                SentinelContext(task=task, trace_records=self._task_traces(task.request.task_id))
            )
            evaluation = self._evaluate_run(
                task=task,
                route=None,
                artifacts=(),
                replay_observation=replay_observation,
                sentinel_report=sentinel_report,
                governance_preflight=None,
                approval_resolution=None,
            )
            verification = self._verifier.verify(
                VerificationContext(
                    subject_id=task.request.task_id,
                    expected_artifacts=(),
                    produced_artifacts=(),
                    evaluation_results=(evaluation,),
                )
            )
            return self._finalize_run(
                task=task.mark_failed(error="No capability route matched task."),
                route=None,
                pack_name=None,
                pack_result=None,
                replay_observation=replay_observation,
                task_inference=inference,
                sentinel_report=sentinel_report,
                evaluation=evaluation,
                verification=verification,
                governance_preflight=None,
                approval_resolution=None,
            )

        self._append_trace(
            correlation_id=task.request.task_id,
            stage="routing",
            message=(
                f"Routed task to '{route.capability_name}' with confidence "
                f"{route.confidence:.2f}."
            ),
            source="runtime",
            data={
                "capability_name": route.capability_name,
                "confidence": route.confidence,
                "reason": route.reason.value,
                "matched_labels": route.matched_labels,
            },
        )

        governance_preflight = self._governance_preflight.evaluate(
            task=task,
            route=route,
        )
        self._append_trace(
            correlation_id=task.request.task_id,
            stage="governance",
            message=(
                "Governance preflight produced decision "
                f"'{governance_preflight.decision.decision.value}' at risk "
                f"level '{governance_preflight.risk.risk_level.value}'."
            ),
            level=(
                "error"
                if governance_preflight.blocked
                else "warning"
                if governance_preflight.requires_review
                else "info"
            ),
            source="runtime",
            data={
                "action_kind": governance_preflight.intent.action_kind.value,
                "risk_level": governance_preflight.risk.risk_level.value,
                "policy_decision": governance_preflight.decision.decision.value,
                "policy_reason": governance_preflight.decision.reason.value,
                "ticket_id": governance_preflight.ticket.ticket_id,
                "ticket_disposition": governance_preflight.ticket.disposition.value,
                "factor_codes": governance_preflight.risk.factor_codes(),
            },
        )

        approval_resolution = self._approval_resolver.resolve(
            task=task,
            preflight=governance_preflight,
        )
        if governance_preflight.requires_review:
            self._append_trace(
                correlation_id=task.request.task_id,
                stage="approval",
                message=(
                    "Runtime approval resolution "
                    f"{'satisfied' if approval_resolution.satisfied else 'did not satisfy'} "
                    "the review gate."
                ),
                level="info" if approval_resolution.satisfied else "warning",
                source="runtime",
                data={
                    "required": approval_resolution.required,
                    "satisfied": approval_resolution.satisfied,
                    "approval_ids": approval_resolution.approval_ids,
                    "issues": approval_resolution.issues,
                },
            )

        if governance_preflight.blocked:
            failed_task = task.mark_failed(error=governance_preflight.decision.rationale)
            sentinel_report = self._sentinel.evaluate(
                SentinelContext(
                    task=failed_task,
                    trace_records=self._task_traces(task.request.task_id),
                )
            )
            evaluation = self._evaluate_run(
                task=failed_task,
                route=route,
                artifacts=(),
                replay_observation=replay_observation,
                sentinel_report=sentinel_report,
                governance_preflight=governance_preflight,
                approval_resolution=approval_resolution,
            )
            verification = self._verifier.verify(
                VerificationContext(
                    subject_id=task.request.task_id,
                    expected_artifacts=(),
                    produced_artifacts=(),
                    evaluation_results=(evaluation,),
                )
            )
            return self._finalize_run(
                task=failed_task,
                route=route,
                pack_name=None,
                pack_result=None,
                replay_observation=replay_observation,
                task_inference=inference,
                sentinel_report=sentinel_report,
                evaluation=evaluation,
                verification=verification,
                governance_preflight=governance_preflight,
                approval_resolution=approval_resolution,
            )

        if governance_preflight.requires_review and not approval_resolution.satisfied:
            paused_task = task.mark_completed(
                result_summary="Run paused pending governance approval."
            )
            sentinel_report = self._sentinel.evaluate(
                SentinelContext(
                    task=paused_task,
                    trace_records=self._task_traces(task.request.task_id),
                )
            )
            evaluation = self._evaluate_run(
                task=paused_task,
                route=route,
                artifacts=(),
                replay_observation=replay_observation,
                sentinel_report=sentinel_report,
                governance_preflight=governance_preflight,
                approval_resolution=approval_resolution,
            )
            verification = self._verifier.verify(
                VerificationContext(
                    subject_id=task.request.task_id,
                    expected_artifacts=(),
                    produced_artifacts=(),
                    evaluation_results=(evaluation,),
                )
            )
            return self._finalize_run(
                task=paused_task,
                route=route,
                pack_name=None,
                pack_result=None,
                replay_observation=replay_observation,
                task_inference=inference,
                sentinel_report=sentinel_report,
                evaluation=evaluation,
                verification=verification,
                governance_preflight=governance_preflight,
                approval_resolution=approval_resolution,
            )

        manifest = self._manifest_registry.get(route.capability_name)
        if manifest is None:
            raise RuntimeError(f"Route target '{route.capability_name}' has no registered manifest.")

        pack = self._load_pack(manifest.pack_name)
        pack_context = PackContext(
            config=self._config,
            bus=self._bus,
            shared_state=self._shared_state,
            metadata={
                "route_confidence": route.confidence,
                "route_reason": route.reason.value,
                "session_id": self._session_id,
                "approval_ids": approval_resolution.approval_ids,
            },
        )

        try:
            pack_result = pack.execute(task=task, context=pack_context)
        except Exception as exc:
            self._append_trace(
                correlation_id=task.request.task_id,
                stage="pack",
                message=f"Pack execution failed: {exc}",
                level="error",
                source=route.capability_name,
            )
            failed_task = task.mark_failed(error=str(exc))
            sentinel_report = self._sentinel.evaluate(
                SentinelContext(task=failed_task, trace_records=self._task_traces(task.request.task_id))
            )
            evaluation = self._evaluate_run(
                task=failed_task,
                route=route,
                artifacts=(),
                replay_observation=replay_observation,
                sentinel_report=sentinel_report,
                governance_preflight=governance_preflight,
                approval_resolution=approval_resolution,
            )
            verification = self._verifier.verify(
                VerificationContext(
                    subject_id=task.request.task_id,
                    expected_artifacts=(),
                    produced_artifacts=(),
                    evaluation_results=(evaluation,),
                )
            )
            return self._finalize_run(
                task=failed_task,
                route=route,
                pack_name=pack.pack_name,
                pack_result=None,
                replay_observation=replay_observation,
                task_inference=inference,
                sentinel_report=sentinel_report,
                evaluation=evaluation,
                verification=verification,
                governance_preflight=governance_preflight,
                approval_resolution=approval_resolution,
            )

        self._append_trace(
            correlation_id=task.request.task_id,
            stage="pack",
            message=pack_result.summary,
            source=pack.pack_name,
            data={
                "artifact_count": len(pack_result.artifacts),
                "metrics": pack_result.metrics,
            },
        )

        policy_observations = self._build_policy_observations(pack_name=pack.pack_name, pack_result=pack_result)
        sentinel_report = self._sentinel.evaluate(
            SentinelContext(
                task=task,
                trace_records=self._task_traces(task.request.task_id),
                metadata={
                    "assertions": self._build_assertions(task=task, route=route, pack_name=pack.pack_name),
                    "policy_observations": policy_observations,
                },
            )
        )
        evaluation = self._evaluate_run(
            task=task,
            route=route,
            artifacts=pack_result.artifacts,
            replay_observation=replay_observation,
            sentinel_report=sentinel_report,
            governance_preflight=governance_preflight,
            approval_resolution=approval_resolution,
        )
        verification = self._verifier.verify(
            VerificationContext(
                subject_id=task.request.task_id,
                expected_artifacts=pack_result.artifacts,
                produced_artifacts=pack_result.artifacts,
                evaluation_results=(evaluation,),
            )
        )

        completed_task = task.mark_completed(result_summary=pack_result.summary)
        return self._finalize_run(
            task=completed_task,
            route=route,
            pack_name=pack.pack_name,
            pack_result=pack_result,
            replay_observation=replay_observation,
            task_inference=inference,
            sentinel_report=sentinel_report,
            evaluation=evaluation,
            verification=verification,
            governance_preflight=governance_preflight,
            approval_resolution=approval_resolution,
        )

    def _register_builtin_packs(self) -> None:
        manifests = (
            build_programming_manifest(),
            build_architecture_manifest(),
        )
        for manifest in manifests:
            self._manifest_registry.register(manifest)
            self._switchboard.register(
                CapabilityRoute(
                    capability_name=manifest.pack_name,
                    supported_kinds=manifest.supported_kinds,
                    labels=manifest.labels,
                    description=manifest.description,
                    is_fallback=manifest.is_default,
                )
            )

    def _register_builtin_checks(self) -> None:
        self._sentinel.register(ContradictionCheck(critical_predicates=("policy_state",)))
        self._sentinel.register(
            FailureLoopCheck(
                window=FailureLoopWindow(
                    lookback_limit=20,
                    trigger_count=3,
                )
            )
        )
        self._sentinel.register(
            PolicyGuardrailCheck(
                blocked_actions=("destructive-host-mutation",),
                high_risk_actions=("patch-application", "workspace-command"),
            )
        )

    def _load_pack(self, pack_name: str) -> BasePack:
        normalized_name = pack_name.strip().lower()
        if normalized_name in self._loaded_packs:
            return self._loaded_packs[normalized_name]

        manifest = self._manifest_registry.get(normalized_name)
        if manifest is None:
            raise RuntimeError(f"Pack '{normalized_name}' is not registered.")

        loaded = self._pack_loader.load(manifest)
        pack = _coerce_pack(loaded)
        self._loaded_packs[normalized_name] = pack
        return pack

    def _evaluate_run(
        self,
        *,
        task: TaskRecord,
        route: RoutingDecision | None,
        artifacts: tuple[str, ...],
        replay_observation: ReplayObservation,
        sentinel_report: SentinelReport,
        governance_preflight: RuntimeGovernancePreflightResult | None,
        approval_resolution: RuntimeApprovalResolution | None,
    ) -> EvaluationResult:
        evaluator = RuleBasedEvaluator(
            evaluator_name="runtime_run_quality",
            rules=(
                lambda context: _route_rule(context),
                lambda context: _artifact_rule(context),
                lambda context: _replay_rule(context),
                lambda context: _sentinel_rule(context),
                lambda context: _governance_rule(context),
                lambda context: _approval_rule(context),
            ),
            passing_score=1.0,
            review_score=0.6,
            failing_score=0.0,
        )
        return evaluator.evaluate(
            EvaluationContext(
                task=task,
                artifacts=artifacts,
                metadata={
                    "route": route,
                    "replay_observation": replay_observation,
                    "sentinel_report": sentinel_report,
                    "governance_preflight": governance_preflight,
                    "approval_resolution": approval_resolution,
                },
            )
        )

    def _finalize_run(
        self,
        *,
        task: TaskRecord,
        route: RoutingDecision | None,
        pack_name: str | None,
        pack_result: Any | None,
        replay_observation: ReplayObservation,
        task_inference: TaskInference | None,
        sentinel_report: SentinelReport,
        evaluation: EvaluationResult,
        verification: VerificationReport,
        governance_preflight: RuntimeGovernancePreflightResult | None,
        approval_resolution: RuntimeApprovalResolution | None,
    ) -> RuntimeRunReport:
        artifact_paths: dict[str, str] = {}
        produced_artifacts: list[str] = []

        if pack_result is not None:
            materialized = self._materialize_pack_artifacts(
                task=task,
                pack_name=pack_name or "unknown",
                pack_result=pack_result,
            )
            artifact_paths.update({name: str(path) for name, path in materialized.items()})
            produced_artifacts.extend(materialized)

        self._record_evidence(
            task=task,
            route=route,
            pack_name=pack_name,
            evaluation=evaluation,
            verification=verification,
            sentinel_report=sentinel_report,
            replay_observation=replay_observation,
            produced_artifacts=tuple(produced_artifacts),
            governance_preflight=governance_preflight,
            approval_resolution=approval_resolution,
        )

        run_report = RuntimeRunReport(
            session_id=self._session_id,
            run_id=f"run-{uuid4().hex}",
            task_id=task.request.task_id,
            task_kind=task.request.kind,
            status=_status_from_verification(verification),
            route=route,
            pack_name=pack_name,
            task_summary=task.result_summary or task.error or "Run finished.",
            evaluation_result=evaluation,
            verification_report=verification,
            sentinel_report=sentinel_report,
            replay_observation=replay_observation,
            task_inference=task_inference,
            governance_preflight=governance_preflight,
            approval_resolution=approval_resolution,
            produced_artifacts=tuple(produced_artifacts),
            artifact_paths=artifact_paths,
            trace_ids=tuple(record.trace_id for record in self._task_traces(task.request.task_id)),
            evidence_ids=tuple(
                record.evidence_id
                for record in self._evidence.snapshot().filter_by_subject(task.request.task_id)
            ),
        )

        report_path = self._persist_run_report(run_report)
        self._append_trace(
            correlation_id=task.request.task_id,
            stage="persistence",
            message="Persisted run report and state capsule.",
            source="runtime",
            data={"report_path": str(report_path)},
        )

        final_report = replace(run_report, report_path=str(report_path))
        self._logger.log(
            level=_log_level_for_status(final_report.status),
            event="runtime.run_completed",
            message=f"Completed BlackFox run with status '{final_report.status.value}'.",
            source="runtime",
            correlation_id=task.request.task_id,
            data={
                "task_kind": final_report.task_kind.value,
                "status": final_report.status.value,
                "pack_name": final_report.pack_name,
                "verification_status": final_report.verification_report.status.value,
                "sentinel_issue_count": len(final_report.sentinel_report.issues),
                "report_path": final_report.report_path,
            },
        )

        self._episodic_memory.create(
            session_id=self._session_id,
            task_id=task.request.task_id,
            title=f"{task.request.kind.value} run",
            summary=final_report.task_summary,
            outcome=final_report.status.value,
            tags=(task.request.kind.value, final_report.status.value),
            metadata={
                "pack_name": final_report.pack_name,
                "verification_status": final_report.verification_report.status.value,
                "report_path": final_report.report_path,
            },
        )
        self._semantic_memory.upsert(
            key="last_selected_pack",
            value=final_report.pack_name or "none",
            fact_type="runtime_fact",
            confidence=1.0,
            source="runtime",
            tags=("runtime", "pack-selection"),
            aliases=("current pack",),
        )
        self._shared_state.put(
            "runtime",
            "last_task_status",
            final_report.status.value,
            source="runtime",
        )
        return final_report

    def _record_evidence(
        self,
        *,
        task: TaskRecord,
        route: RoutingDecision | None,
        pack_name: str | None,
        evaluation: EvaluationResult,
        verification: VerificationReport,
        sentinel_report: SentinelReport,
        replay_observation: ReplayObservation,
        produced_artifacts: tuple[str, ...],
        governance_preflight: RuntimeGovernancePreflightResult | None,
        approval_resolution: RuntimeApprovalResolution | None,
    ) -> None:
        trace_ids = tuple(record.trace_id for record in self._task_traces(task.request.task_id))
        self._evidence.record(
            subject_id=task.request.task_id,
            evidence_type="route",
            summary="Recorded routing outcome for task.",
            source="runtime",
            trace_ids=trace_ids,
            metadata={
                "route": None
                if route is None
                else {
                    "capability_name": route.capability_name,
                    "confidence": route.confidence,
                    "reason": route.reason.value,
                },
                "pack_name": pack_name,
            },
        )
        self._evidence.record(
            subject_id=task.request.task_id,
            evidence_type="evaluation",
            summary="Recorded evaluation and verification outcome.",
            source="runtime",
            artifact_refs=produced_artifacts,
            metadata={
                "evaluation_status": evaluation.status.value,
                "verification_status": verification.status.value,
                "score": evaluation.score,
            },
        )
        if governance_preflight is not None:
            self._evidence.record(
                subject_id=task.request.task_id,
                evidence_type="governance",
                summary="Recorded governance preflight outcome.",
                source="runtime",
                trace_ids=trace_ids,
                metadata={
                    "action_kind": governance_preflight.intent.action_kind.value,
                    "risk_level": governance_preflight.risk.risk_level.value,
                    "policy_decision": governance_preflight.decision.decision.value,
                    "policy_reason": governance_preflight.decision.reason.value,
                    "ticket_id": governance_preflight.ticket.ticket_id,
                    "ticket_disposition": governance_preflight.ticket.disposition.value,
                    "approval_required": (
                        False if approval_resolution is None else approval_resolution.required
                    ),
                    "approval_satisfied": (
                        False if approval_resolution is None else approval_resolution.satisfied
                    ),
                    "approval_ids": (
                        () if approval_resolution is None else approval_resolution.approval_ids
                    ),
                },
            )

        if approval_resolution is not None and approval_resolution.required:
            self._evidence.record(
                subject_id=task.request.task_id,
                evidence_type="approval",
                summary="Recorded runtime approval resolution outcome.",
                source="runtime",
                trace_ids=trace_ids,
                metadata=approval_resolution.to_dict(),
            )

        self._evidence.record(
            subject_id=task.request.task_id,
            evidence_type="sentinel",
            summary="Recorded sentinel and replay observations.",
            source="runtime",
            trace_ids=trace_ids,
            metadata={
                "sentinel_issue_count": len(sentinel_report.issues),
                "duplicate_detected": replay_observation.duplicate_detected,
                "seen_count": replay_observation.seen_count,
            },
        )

    def _materialize_pack_artifacts(
        self,
        *,
        task: TaskRecord,
        pack_name: str,
        pack_result: Any,
    ) -> dict[str, Path]:
        root_dir = self._config.paths.artifacts_dir / "runs" / task.request.task_id
        root_dir.mkdir(parents=True, exist_ok=True)
        materialized: dict[str, Path] = {}

        payload = {
            "task_id": task.request.task_id,
            "task_kind": task.request.kind.value,
            "pack_name": pack_name,
            "summary": pack_result.summary,
            "metrics": pack_result.metrics,
            "data": pack_result.data,
            "created_at": _utc_now().isoformat(),
        }
        content = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False)
        digest = fingerprint_bytes(content.encode("utf-8"))

        for logical_name in pack_result.artifacts:
            path = root_dir / logical_name
            path.write_text(content, encoding="utf-8")
            self._artifact_memory.upsert(
                logical_name=logical_name,
                path=path,
                artifact_type="report",
                digest=digest,
                source=pack_name,
                tags=(task.request.kind.value, pack_name),
                metadata={"task_id": task.request.task_id},
            )
            self._provenance.append(
                subject=logical_name,
                action="created",
                fingerprint=digest,
                actor=pack_name,
                metadata={"task_id": task.request.task_id, "path": str(path)},
            )
            materialized[logical_name] = path

        return materialized

    def _persist_run_report(self, report: RuntimeRunReport) -> Path:
        root_dir = self._config.paths.artifacts_dir / "runs" / report.task_id
        root_dir.mkdir(parents=True, exist_ok=True)
        report_path = root_dir / "blackfox-run-report.json"
        report_payload = report.to_dict()
        report_text = json.dumps(report_payload, sort_keys=True, indent=2, ensure_ascii=False)
        report_path.write_text(report_text, encoding="utf-8")

        digest = fingerprint_bytes(report_text.encode("utf-8"))
        self._artifact_memory.upsert(
            logical_name=f"run-report-{report.task_id}",
            path=report_path,
            artifact_type="report",
            digest=digest,
            source="runtime",
            tags=(report.task_kind.value, report.status.value),
            metadata={"task_id": report.task_id, "run_id": report.run_id},
        )
        self._provenance.append(
            subject=f"run-report:{report.task_id}",
            action="created",
            fingerprint=digest,
            actor="runtime",
            metadata={"path": str(report_path), "status": report.status.value},
        )
        self._state_store.put(
            key=report.task_id,
            payload=report_payload,
        )
        return report_path

    def _build_assertions(
        self,
        *,
        task: TaskRecord,
        route: RoutingDecision,
        pack_name: str,
    ) -> tuple[dict[str, object], ...]:
        return (
            {
                "subject": "runtime",
                "predicate": "selected_route",
                "value": route.capability_name,
                "source": "switchboard",
            },
            {
                "subject": "runtime",
                "predicate": "selected_pack",
                "value": pack_name,
                "source": "packs",
            },
            {
                "subject": task.request.task_id,
                "predicate": "task_kind",
                "value": task.request.kind.value,
                "source": "kernel",
            },
        )

    def _build_policy_observations(
        self,
        *,
        pack_name: str,
        pack_result: Any,
    ) -> tuple[PolicyObservation, ...]:
        raw_steps = pack_result.data.get("steps", ())
        observations: list[PolicyObservation] = []

        if isinstance(raw_steps, list):
            for step in raw_steps:
                if not isinstance(step, dict):
                    continue
                action = str(step.get("action", "unknown"))
                decision = "allowed"
                if action in {"prepare-patch", "profile-execution"}:
                    decision = "review_required"
                observations.append(
                    PolicyObservation(
                        action=action,
                        decision=decision,
                        executed=False,
                        approved=False,
                        source=pack_name,
                        reason="Pack produced a plan artifact only; action not executed.",
                    )
                )

        return tuple(observations)

    def _append_trace(
        self,
        *,
        correlation_id: str,
        stage: str,
        message: str,
        level: str = "info",
        source: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        self._trace_memory.append(
            correlation_id=correlation_id,
            stage=stage,
            message=message,
            level=level,
            source=source,
            tags=(stage,),
            data=data or {},
        )

    def _task_traces(self, task_id: str) -> tuple[Any, ...]:
        return self._trace_memory.snapshot().filter_by_correlation(task_id)


def _coerce_pack(loaded: LoadedPack) -> BasePack:
    implementation = loaded.implementation
    if isinstance(implementation, BasePack):
        return implementation
    if isinstance(implementation, type):
        instance = implementation()
        if not isinstance(instance, BasePack):
            raise TypeError(
                f"Loaded pack '{loaded.manifest.pack_name}' did not instantiate to BasePack."
            )
        return instance
    raise TypeError(
        f"Loaded pack '{loaded.manifest.pack_name}' is neither a BasePack instance nor class."
    )


def _route_rule(context: EvaluationContext) -> EvaluationFinding | None:
    route = context.metadata.get("route")
    if route is None:
        return EvaluationFinding(
            code="runtime.route_missing",
            severity=EvaluationSeverity.ERROR,
            summary="No route was available for the task.",
        )
    if route.confidence < 0.4:
        return EvaluationFinding(
            code="runtime.low_route_confidence",
            severity=EvaluationSeverity.WARNING,
            summary="Route confidence is low and should be reviewed.",
            details=f"confidence={route.confidence}",
        )
    return None


def _artifact_rule(context: EvaluationContext) -> EvaluationFinding | None:
    if context.task is None:
        return None
    if context.task.state == context.task.state.FAILED:
        return EvaluationFinding(
            code="runtime.task_failed",
            severity=EvaluationSeverity.ERROR,
            summary="Task entered a failed state during execution.",
            details=context.task.error,
        )
    if not context.artifacts:
        return EvaluationFinding(
            code="runtime.no_artifacts",
            severity=EvaluationSeverity.WARNING,
            summary="Run produced no declared artifacts.",
        )
    return None


def _replay_rule(context: EvaluationContext) -> EvaluationFinding | None:
    observation = context.metadata.get("replay_observation")
    if not isinstance(observation, ReplayObservation):
        return None
    if observation.duplicate_detected:
        return EvaluationFinding(
            code="runtime.duplicate_task_replayed",
            severity=EvaluationSeverity.WARNING,
            summary="A recent duplicate task fingerprint was observed.",
            details=f"seen_count={observation.seen_count}",
            data={"fingerprint": observation.fingerprint},
        )
    return None


def _sentinel_rule(context: EvaluationContext) -> EvaluationFinding | None:
    report = context.metadata.get("sentinel_report")
    if not isinstance(report, SentinelReport):
        return None

    if any(issue.severity in {SentinelSeverity.ERROR, SentinelSeverity.CRITICAL} for issue in report.issues):
        return EvaluationFinding(
            code="runtime.sentinel_error",
            severity=EvaluationSeverity.ERROR,
            summary="Sentinel reported a blocking runtime issue.",
            details=f"issue_count={len(report.issues)}",
        )
    if report.issues:
        return EvaluationFinding(
            code="runtime.sentinel_warning",
            severity=EvaluationSeverity.WARNING,
            summary="Sentinel reported review-worthy runtime issues.",
            details=f"issue_count={len(report.issues)}",
        )
    return None


def _governance_rule(context: EvaluationContext) -> EvaluationFinding | None:
    preflight = context.metadata.get("governance_preflight")
    if not isinstance(preflight, RuntimeGovernancePreflightResult):
        return None

    if preflight.blocked:
        return EvaluationFinding(
            code="runtime.governance_blocked",
            severity=EvaluationSeverity.ERROR,
            summary="Governance preflight blocked runtime execution.",
            details=preflight.decision.rationale,
            data={
                "risk_level": preflight.risk.risk_level.value,
                "policy_decision": preflight.decision.decision.value,
            },
        )

    return None


def _approval_rule(context: EvaluationContext) -> EvaluationFinding | None:
    resolution = context.metadata.get("approval_resolution")
    if not isinstance(resolution, RuntimeApprovalResolution):
        return None

    if resolution.required and not resolution.satisfied:
        return EvaluationFinding(
            code="runtime.approval_pending",
            severity=EvaluationSeverity.WARNING,
            summary="Runtime execution is waiting on governance approval.",
            details="Review-gated work cannot proceed until an approval artifact resolves it.",
            data={
                "approval_ids": resolution.approval_ids,
                "issues": resolution.issues,
            },
        )

    return None


def _status_from_verification(report: VerificationReport) -> RuntimeRunStatus:
    if report.status.value == "failed":
        return RuntimeRunStatus.FAILED
    if report.status.value == "needs_review":
        return RuntimeRunStatus.NEEDS_REVIEW
    return RuntimeRunStatus.PASSED


def _log_level_for_status(status: RuntimeRunStatus) -> LogLevel:
    if status == RuntimeRunStatus.FAILED:
        return LogLevel.ERROR
    if status == RuntimeRunStatus.NEEDS_REVIEW:
        return LogLevel.WARNING
    return LogLevel.INFO


def _evaluation_to_dict(result: EvaluationResult) -> dict[str, Any]:
    return {
        "evaluator_name": result.evaluator_name,
        "evaluated_at": result.evaluated_at.isoformat(),
        "status": result.status.value,
        "score": result.score,
        "findings": [
            {
                "code": finding.code,
                "severity": finding.severity.value,
                "summary": finding.summary,
                "details": finding.details,
                "data": finding.data,
            }
            for finding in result.findings
        ],
    }


def _verification_to_dict(report: VerificationReport) -> dict[str, Any]:
    return {
        "subject_id": report.subject_id,
        "verified_at": report.verified_at.isoformat(),
        "status": report.status.value,
        "issues": [
            {
                "code": issue.code,
                "severity": issue.severity.value,
                "summary": issue.summary,
                "details": issue.details,
            }
            for issue in report.issues
        ],
    }


def _sentinel_to_dict(report: SentinelReport) -> dict[str, Any]:
    return {
        "evaluated_at": report.evaluated_at.isoformat(),
        "check_count": report.check_count,
        "issues": [
            {
                "code": issue.code,
                "severity": issue.severity.value,
                "summary": issue.summary,
                "source": issue.source,
                "details": issue.details,
                "data": issue.data,
            }
            for issue in report.issues
        ],
    }


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
