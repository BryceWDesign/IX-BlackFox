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
from ix_blackfox.governance import GovernanceReceiptLedger
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
    GovernanceConsistencyCheck,
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
from ix_blackfox.runtime.receipts import (
    RuntimeGovernanceReceiptRecorder,
    RuntimeGovernanceReceiptReport,
)
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
    governance_receipts: RuntimeGovernanceReceiptReport | None = None
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

        governance_receipts = None
        if self.governance_receipts is not None:
            governance_receipts = self.governance_receipts.to_dict()

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
            "governance_receipts": governance_receipts,
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
        receipt_recorder: RuntimeGovernanceReceiptRecorder,
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
        self._receipt_recorder = receipt_recorder
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
            "blackfox-development-state-secret",
        )
        state_store = VaultStateStore(secret=state_secret)
        replay_guard = TaskReplayGuard()
        classifier = DeterministicTaskClassifier()
        governance_preflight = RuntimeGovernancePreflightEngine()
        approval_resolver = RuntimeApprovalResolver()
        receipt_recorder = RuntimeGovernanceReceiptRecorder()

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
            receipt_recorder=receipt_recorder,
        )
        runtime._register_default_manifests()
        return runtime

    def run_prompt(
        self,
        *,
        prompt: str,
        kind: TaskKind,
        labels: tuple[str, ...] = (),
        metadata: dict[str, object] | None = None,
        priority: TaskPriority = TaskPriority.NORMAL,
    ) -> RuntimeRunReport:
        """
        Convenience API to create and execute a task in one call.
        """
        task_id = f"task-{uuid4().hex}"
        request = TaskRequest(
            task_id=task_id,
            task_kind=kind,
            prompt=prompt,
            labels=labels,
            priority=priority,
            metadata=metadata or {},
        )
        task = self._kernel.create_task(request)
        return self.execute_task(task)

    def execute_task(self, task: TaskRecord) -> RuntimeRunReport:
        """
        Execute one task end-to-end through the runtime.
        """
        replay_observation = self._replay_guard.observe(task)
        if replay_observation.is_duplicate:
            self._append_trace(
                correlation_id=task.request.task_id,
                stage="runtime",
                message="Replay guard flagged duplicate task fingerprint.",
                level="warning",
                source="runtime",
            )

        inference = self._classifier.classify(task.request)
        self._append_trace(
            correlation_id=task.request.task_id,
            stage="inference",
            message=(
                f"Classified task as {inference.kind.value} "
                f"(reason={inference.reason.value}, confidence={inference.confidence:.2f})."
            ),
            level="info",
            source="classifier",
        )

        route = self._switchboard.route(
            task.request.task_id,
            labels=task.request.labels,
            prompt=task.request.prompt,
            inferred_kind=inference.kind,
        )
        if route is None:
            raise RuntimeError("No capability route matched the submitted task.")

        self._append_trace(
            correlation_id=task.request.task_id,
            stage="routing",
            message=(
                f"Routed task to capability '{route.capability_name}' "
                f"(confidence={route.confidence:.2f}, reason={route.reason.value})."
            ),
            level="info",
            source="switchboard",
        )

        governance_preflight = self._governance_preflight.evaluate(task=task, route=route)
        approval_resolution = self._approval_resolver.resolve(
            task=task,
            preflight=governance_preflight,
        )
        governance_receipt_ledger = GovernanceReceiptLedger(intent_id=governance_preflight.intent.intent_id)

        self._receipt_recorder.record_preflight(
            ledger=governance_receipt_ledger,
            preflight=governance_preflight,
        )

        if approval_resolution.required and approval_resolution.approvals:
            self._receipt_recorder.record_approval(
                ledger=governance_receipt_ledger,
                approvals=approval_resolution.approvals,
            )

        self._append_trace(
            correlation_id=task.request.task_id,
            stage="governance",
            message=(
                f"Preflight decision={governance_preflight.decision.decision.value}, "
                f"risk={governance_preflight.risk.risk_level.value}, "
                f"approval_required={approval_resolution.required}, "
                f"approval_satisfied={approval_resolution.satisfied}."
            ),
            level="info",
            source="governance",
        )

        if governance_preflight.blocked:
            failed_task = task.mark_failed(error=governance_preflight.decision.rationale)
            sentinel_report = self._sentinel.evaluate(
                SentinelContext(
                    task=failed_task,
                    trace_records=self._task_traces(task.request.task_id),
                    metadata={
                        "governance_observations": _build_governance_observations(
                            governance_preflight=governance_preflight,
                            approval_resolution=approval_resolution,
                            executed=False,
                        ),
                    },
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
            (
                required_signals,
                observed_signals,
                governance_chain_verified,
                approval_required,
                approval_satisfied,
            ) = _verification_signal_state(
                governance_preflight=governance_preflight,
                approval_resolution=approval_resolution,
                governance_receipt_ledger=governance_receipt_ledger,
            )
            verification = self._verifier.verify(
                VerificationContext(
                    subject_id=task.request.task_id,
                    expected_artifacts=(),
                    produced_artifacts=(),
                    evaluation_results=(evaluation,),
                    required_signals=required_signals,
                    observed_signals=observed_signals,
                    governance_chain_verified=governance_chain_verified,
                    approval_required=approval_required,
                    approval_satisfied=approval_satisfied,
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
                governance_receipt_ledger=governance_receipt_ledger,
            )

        if governance_preflight.requires_review and not approval_resolution.satisfied:
            paused_task = task.mark_completed(
                result_summary="Run paused pending governance approval."
            )
            sentinel_report = self._sentinel.evaluate(
                SentinelContext(
                    task=paused_task,
                    trace_records=self._task_traces(task.request.task_id),
                    metadata={
                        "governance_observations": _build_governance_observations(
                            governance_preflight=governance_preflight,
                            approval_resolution=approval_resolution,
                            executed=False,
                        ),
                    },
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
            (
                required_signals,
                observed_signals,
                governance_chain_verified,
                approval_required,
                approval_satisfied,
            ) = _verification_signal_state(
                governance_preflight=governance_preflight,
                approval_resolution=approval_resolution,
                governance_receipt_ledger=governance_receipt_ledger,
            )
            verification = self._verifier.verify(
                VerificationContext(
                    subject_id=task.request.task_id,
                    expected_artifacts=(),
                    produced_artifacts=(),
                    evaluation_results=(evaluation,),
                    required_signals=required_signals,
                    observed_signals=observed_signals,
                    governance_chain_verified=governance_chain_verified,
                    approval_required=approval_required,
                    approval_satisfied=approval_satisfied,
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
                governance_receipt_ledger=governance_receipt_ledger,
            )

        manifest = self._manifest_registry.get(route.capability_name)
        if manifest is None:
            raise RuntimeError(f"Route target '{route.capability_name}' has no registered manifest.")

        pack = self._load_pack(manifest.pack_name)
        self._receipt_recorder.record_execution_started(
            ledger=governance_receipt_ledger,
            preflight=governance_preflight,
            pack_name=pack.pack_name,
        )

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
            self._receipt_recorder.record_execution_failed(
                ledger=governance_receipt_ledger,
                preflight=governance_preflight,
                pack_name=pack.pack_name,
                error=str(exc),
            )
            self._append_trace(
                correlation_id=task.request.task_id,
                stage="pack",
                message=f"Pack execution failed: {exc}",
                level="error",
                source=route.capability_name,
            )
            failed_task = task.mark_failed(error=str(exc))
            sentinel_report = self._sentinel.evaluate(
                SentinelContext(
                    task=failed_task,
                    trace_records=self._task_traces(task.request.task_id),
                    metadata={
                        "governance_observations": _build_governance_observations(
                            governance_preflight=governance_preflight,
                            approval_resolution=approval_resolution,
                            executed=True,
                        ),
                    },
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
            (
                required_signals,
                observed_signals,
                governance_chain_verified,
                approval_required,
                approval_satisfied,
            ) = _verification_signal_state(
                governance_preflight=governance_preflight,
                approval_resolution=approval_resolution,
                governance_receipt_ledger=governance_receipt_ledger,
            )
            verification = self._verifier.verify(
                VerificationContext(
                    subject_id=task.request.task_id,
                    expected_artifacts=(),
                    produced_artifacts=(),
                    evaluation_results=(evaluation,),
                    required_signals=required_signals,
                    observed_signals=observed_signals,
                    governance_chain_verified=governance_chain_verified,
                    approval_required=approval_required,
                    approval_satisfied=approval_satisfied,
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
                governance_receipt_ledger=governance_receipt_ledger,
            )

        completed_task = task.mark_completed(result_summary=pack_result.summary)
        self._append_trace(
            correlation_id=task.request.task_id,
            stage="pack",
            message=(
                f"Pack '{pack.pack_name}' completed with "
                f"{len(pack_result.artifacts)} artifact(s)."
            ),
            level="info",
            source=route.capability_name,
        )

        sentinel_report = self._sentinel.evaluate(
            SentinelContext(
                task=completed_task,
                trace_records=self._task_traces(task.request.task_id),
                metadata={
                    "governance_observations": _build_governance_observations(
                        governance_preflight=governance_preflight,
                        approval_resolution=approval_resolution,
                        executed=True,
                    ),
                },
            )
        )
        evaluation = self._evaluate_run(
            task=completed_task,
            route=route,
            artifacts=pack_result.artifacts,
            replay_observation=replay_observation,
            sentinel_report=sentinel_report,
            governance_preflight=governance_preflight,
            approval_resolution=approval_resolution,
        )
        (
            required_signals,
            observed_signals,
            governance_chain_verified,
            approval_required,
            approval_satisfied,
        ) = _verification_signal_state(
            governance_preflight=governance_preflight,
            approval_resolution=approval_resolution,
            governance_receipt_ledger=governance_receipt_ledger,
        )
        verification = self._verifier.verify(
            VerificationContext(
                subject_id=task.request.task_id,
                expected_artifacts=tuple(artifact.name for artifact in pack_result.artifacts),
                produced_artifacts=tuple(artifact.name for artifact in pack_result.artifacts),
                evaluation_results=(evaluation,),
                required_signals=required_signals,
                observed_signals=observed_signals,
                governance_chain_verified=governance_chain_verified,
                approval_required=approval_required,
                approval_satisfied=approval_satisfied,
            )
        )
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
            governance_receipt_ledger=governance_receipt_ledger,
        )

    def _finalize_run(
        self,
        *,
        task: TaskRecord,
        route: RoutingDecision | None,
        pack_name: str | None,
        pack_result: Any | None,
        replay_observation: ReplayObservation,
        task_inference: TaskInference,
        sentinel_report: SentinelReport,
        evaluation: EvaluationResult,
        verification: VerificationReport,
        governance_preflight: RuntimeGovernancePreflightResult,
        approval_resolution: RuntimeApprovalResolution,
        governance_receipt_ledger: GovernanceReceiptLedger,
    ) -> RuntimeRunReport:
        status = _status_from_reports(
            evaluation=evaluation,
            verification=verification,
            sentinel=sentinel_report,
        )

        if verification.status.value == "passed":
            self._receipt_recorder.record_verification_passed(
                ledger=governance_receipt_ledger,
                verifier_name=verification.verifier_name,
            )
        else:
            self._receipt_recorder.record_verification_failed(
                ledger=governance_receipt_ledger,
                verifier_name=verification.verifier_name,
                status=verification.status.value,
            )

        governance_receipts = self._persist_governance_receipts(
            task=task,
            governance_preflight=governance_preflight,
            approval_resolution=approval_resolution,
            governance_receipt_ledger=governance_receipt_ledger,
        )

        produced_artifacts: list[str] = []
        artifact_paths: dict[str, str] = {}
        evidence_ids: list[str] = []
        if pack_result is not None:
            for artifact in pack_result.artifacts:
                produced_artifacts.append(artifact.name)
                artifact_paths[artifact.name] = str(artifact.path)
                evidence_record = self._evidence.record(
                    artifact_name=artifact.name,
                    artifact_path=artifact.path,
                )
                evidence_ids.append(evidence_record.evidence_id)
                self._artifact_memory.store(
                    name=artifact.name,
                    path=artifact.path,
                    metadata={"task_id": task.request.task_id},
                )

        if governance_receipts is not None and governance_receipts.artifact_path is not None:
            receipt_name = Path(governance_receipts.artifact_path).name
            if receipt_name not in artifact_paths:
                produced_artifacts.append(receipt_name)
                artifact_paths[receipt_name] = governance_receipts.artifact_path

        report = RuntimeRunReport(
            session_id=self._session_id,
            run_id=f"run-{uuid4().hex}",
            task_id=task.request.task_id,
            task_kind=task.request.task_kind,
            status=status,
            route=route,
            pack_name=pack_name,
            task_summary=self._build_summary(task, evaluation, verification),
            evaluation_result=evaluation,
            verification_report=verification,
            sentinel_report=sentinel_report,
            replay_observation=replay_observation,
            task_inference=task_inference,
            governance_preflight=governance_preflight,
            approval_resolution=approval_resolution,
            governance_receipts=governance_receipts,
            produced_artifacts=tuple(produced_artifacts),
            artifact_paths=artifact_paths,
            trace_ids=self._task_trace_ids(task.request.task_id),
            evidence_ids=tuple(evidence_ids),
        )

        report_path = self._write_run_report(report)
        report = replace(report, report_path=str(report_path))
        self._append_trace(
            correlation_id=task.request.task_id,
            stage="runtime",
            message=f"Run finalized with status={report.status.value}.",
            level="info",
            source="runtime",
        )
        return report

    def _persist_governance_receipts(
        self,
        *,
        task: TaskRecord,
        governance_preflight: RuntimeGovernancePreflightResult,
        approval_resolution: RuntimeApprovalResolution,
        governance_receipt_ledger: GovernanceReceiptLedger,
    ) -> RuntimeGovernanceReceiptReport:
        receipts_root = self._config.artifacts_dir / "governance"
        receipt_path = receipts_root / task.request.task_id / "blackfox-governance-receipts.json"
        receipt_report = self._receipt_recorder.persist(
            ledger=governance_receipt_ledger,
            path=receipt_path,
            preflight=governance_preflight,
            approval_resolution=approval_resolution,
        )
        self._artifact_memory.store(
            name=receipt_path.name,
            path=receipt_path,
            metadata={
                "task_id": task.request.task_id,
                "kind": "governance_receipt",
            },
        )
        self._trace_memory.append(
            correlation_id=task.request.task_id,
            stage="governance",
            message=(
                f"Persisted governance receipt chain with "
                f"{receipt_report.receipt_count} record(s)."
            ),
            level="info",
            source="receipt_recorder",
        )
        return receipt_report

    def _evaluate_run(
        self,
        *,
        task: TaskRecord,
        route: RoutingDecision | None,
        artifacts: tuple[Any, ...],
        replay_observation: ReplayObservation,
        sentinel_report: SentinelReport,
        governance_preflight: RuntimeGovernancePreflightResult | None,
        approval_resolution: RuntimeApprovalResolution | None,
    ) -> EvaluationResult:
        findings: list[EvaluationFinding] = []

        if replay_observation.is_duplicate:
            findings.append(
                EvaluationFinding(
                    rule_id="replay_guard",
                    severity=EvaluationSeverity.WARNING,
                    message="Replay guard detected a duplicate task fingerprint.",
                    metadata={"fingerprint": replay_observation.fingerprint},
                )
            )

        if governance_preflight is not None:
            findings.append(
                EvaluationFinding(
                    rule_id="governance_decision",
                    severity=(
                        EvaluationSeverity.ERROR
                        if governance_preflight.blocked
                        else (
                            EvaluationSeverity.WARNING
                            if governance_preflight.requires_review
                            else EvaluationSeverity.INFO
                        )
                    ),
                    message=governance_preflight.decision.rationale,
                    metadata={
                        "policy_decision": governance_preflight.decision.decision.value,
                        "risk_level": governance_preflight.risk.risk_level.value,
                        "ticket_id": governance_preflight.ticket.ticket_id,
                        "approval_required": (
                            False
                            if approval_resolution is None
                            else approval_resolution.required
                        ),
                        "approval_satisfied": (
                            False
                            if approval_resolution is None
                            else approval_resolution.satisfied
                        ),
                    },
                )
            )

        if route is None:
            findings.append(
                EvaluationFinding(
                    rule_id="routing",
                    severity=EvaluationSeverity.ERROR,
                    message="Runtime did not resolve a capability route.",
                )
            )
        else:
            findings.append(
                EvaluationFinding(
                    rule_id="routing",
                    severity=EvaluationSeverity.INFO,
                    message=(
                        f"Task routed to capability '{route.capability_name}' "
                        f"with confidence {route.confidence:.2f}."
                    ),
                    metadata={
                        "capability_name": route.capability_name,
                        "reason": route.reason.value,
                    },
                )
            )

        if sentinel_report.highest_severity in {SentinelSeverity.CRITICAL, SentinelSeverity.ERROR}:
            findings.append(
                EvaluationFinding(
                    rule_id="sentinel",
                    severity=EvaluationSeverity.ERROR,
                    message="Sentinel reported a blocking runtime issue.",
                    metadata={"highest_severity": sentinel_report.highest_severity.value},
                )
            )

        if task.status.is_failure:
            findings.append(
                EvaluationFinding(
                    rule_id="task_outcome",
                    severity=EvaluationSeverity.ERROR,
                    message=task.error_summary or "Task failed during runtime execution.",
                )
            )
        elif (
            task.status.is_completed
            and governance_preflight is not None
            and governance_preflight.requires_review
            and approval_resolution is not None
            and not approval_resolution.satisfied
        ):
            findings.append(
                EvaluationFinding(
                    rule_id="approval_gate",
                    severity=EvaluationSeverity.WARNING,
                    message="Execution paused pending governance approval.",
                )
            )
        else:
            findings.append(
                EvaluationFinding(
                    rule_id="task_outcome",
                    severity=EvaluationSeverity.INFO,
                    message="Task completed successfully.",
                )
            )

        for artifact in artifacts:
            findings.append(
                EvaluationFinding(
                    rule_id="artifact",
                    severity=EvaluationSeverity.INFO,
                    message=f"Produced artifact '{artifact.name}'.",
                )
            )

        evaluator = RuleBasedEvaluator()
        return evaluator.evaluate(
            EvaluationContext(
                subject_id=task.request.task_id,
                findings=tuple(findings),
                artifacts=tuple(artifact.name for artifact in artifacts),
            )
        )

    def _register_default_manifests(self) -> None:
        architecture = build_architecture_manifest()
        programming = build_programming_manifest()
        self._manifest_registry.register(architecture)
        self._manifest_registry.register(programming)
        self._switchboard.register_route(
            CapabilityRoute(
                capability_name=architecture.capability_name,
                labels=("architecture", "diagram", "system", "design", "flowchart"),
                keywords=("architecture", "system", "design", "diagram", "flow"),
            )
        )
        self._switchboard.register_route(
            CapabilityRoute(
                capability_name=programming.capability_name,
                labels=("code", "patching", "tests", "programming", "refactor"),
                keywords=("code", "python", "test", "patch", "refactor", "program"),
            )
        )

    def _load_pack(self, pack_name: str) -> BasePack:
        if pack_name in self._loaded_packs:
            return self._loaded_packs[pack_name]

        loaded = self._pack_loader.load(pack_name)
        pack = loaded.pack_factory()
        self._loaded_packs[pack_name] = pack
        return pack

    def _append_trace(
        self,
        *,
        correlation_id: str,
        stage: str,
        message: str,
        level: str,
        source: str,
    ) -> None:
        self._trace_memory.append(
            correlation_id=correlation_id,
            stage=stage,
            message=message,
            level=level,
            source=source,
        )

    def _task_traces(self, task_id: str) -> tuple[Any, ...]:
        return self._trace_memory.list(correlation_id=task_id)

    def _task_trace_ids(self, task_id: str) -> tuple[str, ...]:
        return tuple(record.trace_id for record in self._task_traces(task_id))

    def _build_summary(
        self,
        task: TaskRecord,
        evaluation: EvaluationResult,
        verification: VerificationReport,
    ) -> str:
        if task.status.is_failure:
            return task.error_summary or "Task failed during runtime execution."
        if verification.status.value == "needs_review":
            return "Run paused pending governance approval."
        if task.result_summary:
            return task.result_summary
        return evaluation.summary

    def _write_run_report(self, report: RuntimeRunReport) -> Path:
        reports_dir = self._config.artifacts_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_path = reports_dir / f"{report.task_id}.json"
        report_path.write_text(
            json.dumps(report.to_dict(), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return report_path


def _status_from_reports(
    *,
    evaluation: EvaluationResult,
    verification: VerificationReport,
    sentinel: SentinelReport,
) -> RuntimeRunStatus:
    if sentinel.highest_severity in {SentinelSeverity.CRITICAL, SentinelSeverity.ERROR}:
        return RuntimeRunStatus.FAILED
    if verification.status.value == "failed":
        return RuntimeRunStatus.FAILED
    if verification.status.value == "needs_review":
        return RuntimeRunStatus.NEEDS_REVIEW
    return RuntimeRunStatus.PASSED


def _verification_signal_state(
    *,
    governance_preflight: RuntimeGovernancePreflightResult,
    approval_resolution: RuntimeApprovalResolution,
    governance_receipt_ledger: GovernanceReceiptLedger,
) -> tuple[tuple[str, ...], tuple[str, ...], bool, bool, bool]:
    required_signals = ["policy_preflight"]
    observed_signals = ["policy_preflight"]

    if governance_preflight.requires_review:
        required_signals.append("policy_review_required")
        observed_signals.append("policy_review_required")
        if approval_resolution.satisfied:
            required_signals.append("approval_recorded")
            observed_signals.append("approval_recorded")

    if governance_preflight.blocked:
        required_signals.append("verification_failed")
        observed_signals.append("verification_failed")
    else:
        required_signals.append("execution_started")
        required_signals.append("execution_completed")
        observed_signals.extend(["execution_started", "execution_completed"])

    governance_chain_verified = governance_receipt_ledger.verify()

    return (
        tuple(required_signals),
        tuple(observed_signals),
        governance_chain_verified,
        approval_resolution.required,
        approval_resolution.satisfied,
    )


def _evaluation_to_dict(result: EvaluationResult) -> dict[str, Any]:
    return {
        "evaluator_name": result.evaluator_name,
        "status": result.status.value,
        "summary": result.summary,
        "score": result.score,
        "findings": [
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "message": finding.message,
                "metadata": finding.metadata,
            }
            for finding in result.findings
        ],
        "created_at": result.created_at.isoformat(),
    }


def _verification_to_dict(report: VerificationReport) -> dict[str, Any]:
    return {
        "verifier_name": report.verifier_name,
        "status": report.status.value,
        "details": report.details,
        "required_signals": list(report.required_signals),
        "observed_signals": list(report.observed_signals),
        "missing_signals": list(report.missing_signals),
        "artifact_count": report.artifact_count,
        "governance_chain_verified": report.governance_chain_verified,
        "approval_required": report.approval_required,
        "approval_satisfied": report.approval_satisfied,
        "verified_at": report.verified_at.isoformat(),
    }


def _sentinel_to_dict(report: SentinelReport) -> dict[str, Any]:
    return {
        "runtime_name": report.runtime_name,
        "issue_count": report.issue_count,
        "highest_severity": report.highest_severity.value,
        "issued_at": report.issued_at.isoformat(),
        "issues": [
            {
                "code": issue.code,
                "severity": issue.severity.value,
                "summary": issue.summary,
                "details": issue.details,
                "source": issue.source,
                "data": issue.data,
            }
            for issue in report.issues
        ],
    }


def _artifact_stem(path: Path) -> str:
    return path.stem.lower()


def _safe_json_dump(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _json_path(base_dir: Path, relative: str) -> Path:
    normalized = relative.strip("/").replace("\\", "/")
    if normalized.endswith(".json"):
        return base_dir / normalized
    return base_dir / f"{normalized}.json"


def _label_set(task: TaskRecord) -> set[str]:
    return {label.lower() for label in task.request.labels}


def _build_governance_observations(
    *,
    governance_preflight: RuntimeGovernancePreflightResult | None,
    approval_resolution: RuntimeApprovalResolution | None,
    executed: bool,
) -> tuple[dict[str, object], ...]:
    if governance_preflight is None:
        return ()

    approval_required = False if approval_resolution is None else approval_resolution.required
    approval_satisfied = False if approval_resolution is None else approval_resolution.satisfied

    if not approval_required:
        approval_satisfied = False

    return (
        {
            "action": "runtime_pack_dispatch",
            "decision": governance_preflight.decision.decision.value,
            "executed": executed,
            "approval_required": approval_required,
            "approval_satisfied": approval_satisfied,
            "source": "runtime",
            "reason": governance_preflight.decision.rationale,
        },
    )


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
