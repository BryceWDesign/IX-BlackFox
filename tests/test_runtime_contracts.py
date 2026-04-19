from __future__ import annotations

from pathlib import Path

from ix_blackfox.bus import EventTopic, InMemoryEventBus
from ix_blackfox.config import load_runtime_config
from ix_blackfox.eval import (
    BenchmarkCase,
    BenchmarkSuite,
    BenchmarkSuiteRegistry,
    EvaluationContext,
    EvaluationSeverity,
    EvidenceRecorder,
    OutputVerifier,
    RuleBasedEvaluator,
    VerificationContext,
    VerificationStatus,
)
from ix_blackfox.kernel import SharedStateStore, TaskKind, TaskRecord, TaskRequest
from ix_blackfox.memory import (
    ArtifactMemoryStore,
    EpisodicMemoryStore,
    SemanticMemoryStore,
    TraceMemoryStore,
    WorkingMemoryStore,
)
from ix_blackfox.observability import JsonlStructuredLogger, LogLevel
from ix_blackfox.packs import PackContext, PackLoader, PackManifestRegistry
from ix_blackfox.packs.architecture import build_architecture_manifest
from ix_blackfox.packs.programming import build_programming_manifest
from ix_blackfox.sentinel import (
    ContradictionCheck,
    FailureLoopCheck,
    FailureLoopWindow,
    PolicyGuardrailCheck,
    SentinelContext,
    SentinelRuntime,
    SentinelSeverity,
)
from ix_blackfox.switchboard import CapabilityRoute, CapabilitySwitchboard
from ix_blackfox.vault import ProvenanceLedger, VaultStateStore


def test_runtime_contracts_cover_core_subsystem_interop(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    bus = InMemoryEventBus()
    shared_state = SharedStateStore()

    programming_manifest = build_programming_manifest()
    architecture_manifest = build_architecture_manifest()

    registry = PackManifestRegistry()
    registry.register(programming_manifest)
    registry.register(architecture_manifest)

    switchboard = CapabilitySwitchboard()
    switchboard.register(
        CapabilityRoute(
            capability_name=programming_manifest.pack_name,
            supported_kinds=programming_manifest.supported_kinds,
            labels=programming_manifest.labels,
            description=programming_manifest.description,
            is_fallback=programming_manifest.is_default,
        )
    )
    switchboard.register(
        CapabilityRoute(
            capability_name=architecture_manifest.pack_name,
            supported_kinds=architecture_manifest.supported_kinds,
            labels=architecture_manifest.labels,
            description=architecture_manifest.description,
            is_fallback=architecture_manifest.is_default,
        )
    )

    programming_task = TaskRecord(
        request=TaskRequest.create(
            prompt="Fix the failing tests and patch the code.",
            kind=TaskKind.PROGRAMMING,
            labels=("code", "tests"),
        )
    ).mark_running()
    architecture_task = TaskRecord(
        request=TaskRequest.create(
            prompt="Design the runtime interface and state architecture.",
            kind=TaskKind.ARCHITECTURE,
            labels=("design", "state"),
        )
    ).mark_running()

    programming_route = switchboard.route(programming_task.request)
    architecture_route = switchboard.route(architecture_task.request)

    assert programming_route is not None
    assert architecture_route is not None
    assert programming_route.capability_name == "programming"
    assert architecture_route.capability_name == "architecture"

    loader = PackLoader()
    programming_pack = loader.load(programming_manifest).implementation()
    architecture_pack = loader.load(architecture_manifest).implementation()

    context = PackContext(
        config=config,
        bus=bus,
        shared_state=shared_state,
    )

    programming_result = programming_pack.execute(
        task=programming_task,
        context=context,
    )
    architecture_result = architecture_pack.execute(
        task=architecture_task,
        context=context,
    )

    assert programming_result.artifacts == ("programming-plan.json",)
    assert architecture_result.artifacts == ("architecture-plan.json",)

    history = bus.history()
    assert len(history) == 2
    assert history[0].topic == EventTopic.PACK
    assert history[1].topic == EventTopic.PACK

    sentinel = SentinelRuntime()
    sentinel.register(ContradictionCheck(critical_predicates=("policy_state",)))
    sentinel.register(FailureLoopCheck(window=FailureLoopWindow(trigger_count=3)))
    sentinel.register(
        PolicyGuardrailCheck(
            blocked_actions=("delete workspace",),
            high_risk_actions=("network egress",),
        )
    )

    traces = TraceMemoryStore()
    traces.append(
        correlation_id=programming_task.request.task_id,
        stage="forge",
        message="Patch execution failed.",
        level="error",
        source="forge",
    )
    traces.append(
        correlation_id=programming_task.request.task_id,
        stage="forge",
        message="Retry patch execution failed.",
        level="error",
        source="forge",
    )
    traces.append(
        correlation_id=programming_task.request.task_id,
        stage="eval",
        message="Regression verification failed.",
        level="critical",
        source="eval",
    )

    sentinel_report = sentinel.evaluate(
        SentinelContext(
            task=programming_task,
            trace_records=traces.snapshot().records,
            metadata={
                "assertions": [
                    {
                        "subject": "runtime",
                        "predicate": "policy_state",
                        "value": "allowed",
                        "source": "policy",
                    },
                    {
                        "subject": "runtime",
                        "predicate": "policy_state",
                        "value": "blocked",
                        "source": "sentinel",
                    },
                ],
                "policy_observations": [
                    {
                        "action": "network egress",
                        "decision": "allowed",
                        "executed": True,
                        "approved": False,
                        "source": "policy",
                    }
                ],
            },
        )
    )

    assert len(sentinel_report.issues) == 3

    evaluator = RuleBasedEvaluator(
        evaluator_name="artifact_quality",
        rules=(
            lambda context: None,
            lambda context: (
                None
                if "architecture-plan.json" in context.artifacts
                else None
            ),
        ),
    )
    evaluation = evaluator.evaluate(
        EvaluationContext(
            task=architecture_task,
            artifacts=architecture_result.artifacts,
        )
    )
    assert evaluation.passed() is True

    verifier = OutputVerifier()
    verification = verifier.verify(
        VerificationContext(
            subject_id=architecture_task.request.task_id,
            expected_artifacts=("architecture-plan.json",),
            produced_artifacts=architecture_result.artifacts,
            evaluation_results=(evaluation,),
        )
    )
    assert verification.status == VerificationStatus.PASSED

    evidence = EvidenceRecorder()
    evidence_record = evidence.record(
        subject_id=programming_task.request.task_id,
        evidence_type="trace",
        summary="Captured repeated failure loop traces.",
        source="sentinel",
        trace_ids=tuple(record.trace_id for record in traces.snapshot().records),
        metadata={"issue_count": len(sentinel_report.issues)},
    )
    assert evidence.snapshot().get(evidence_record.evidence_id) == evidence_record

    working_memory = WorkingMemoryStore()
    episodic_memory = EpisodicMemoryStore()
    semantic_memory = SemanticMemoryStore()
    artifact_memory = ArtifactMemoryStore()

    working_memory.put("planner", "mode", "strict", source="kernel", tags=("plan",))
    episode = episodic_memory.create(
        session_id="session-001",
        task_id=programming_task.request.task_id,
        title="Programming run",
        summary="Programming pack produced a deterministic plan.",
        outcome="success",
        tags=("pack", "programming"),
    )
    semantic_memory.upsert(
        key="runtime mode",
        value="strict",
        fact_type="constraint",
        confidence=1.0,
        source="kernel",
        tags=("runtime", "constraint"),
        aliases=("planner mode",),
    )
    artifact_record = artifact_memory.upsert(
        logical_name="architecture plan",
        path=tmp_path / "architecture-plan.json",
        artifact_type="report",
        source="architecture",
        tags=("architecture", "plan"),
    )

    assert working_memory.snapshot().get("planner", "mode") is not None
    assert episodic_memory.snapshot().get(episode.episode_id) == episode
    assert semantic_memory.get("planner mode") is not None
    assert artifact_memory.snapshot().get("architecture plan") == artifact_record

    vault_state = VaultStateStore(
        root_dir=tmp_path / "vault-state",
        secret="blackfox-secret",
    )
    stored_state = vault_state.put(
        "runtime-status",
        {"status": "ready", "mode": "strict"},
    )
    fetched_state = vault_state.get("runtime-status")
    assert fetched_state is not None
    assert fetched_state.payload_dict() == {"mode": "strict", "status": "ready"}

    provenance = ProvenanceLedger()
    first_prov = provenance.append(
        subject="architecture plan",
        action="created",
        fingerprint="abc123",
        actor="architecture",
    )
    second_prov = provenance.append(
        subject="architecture plan",
        action="verified",
        fingerprint="def456",
        actor="eval",
    )
    assert first_prov.previous_record_id is None
    assert second_prov.previous_record_id == first_prov.record_id
    assert provenance.verify_subject_chain("architecture plan") is True

    benchmarks = BenchmarkSuiteRegistry()
    suite = BenchmarkSuite(
        suite_name="core",
        version="0.1.0",
        cases=(
            BenchmarkCase.create(
                title="Programming case",
                prompt="Fix the failing tests.",
                expected_artifacts=("programming-plan.json",),
                minimum_score=1.0,
                tags=("programming",),
            ),
            BenchmarkCase.create(
                title="Architecture case",
                prompt="Design the runtime boundary.",
                expected_artifacts=("architecture-plan.json",),
                minimum_score=1.0,
                tags=("architecture",),
            ),
        ),
    )
    benchmarks.register(suite)
    assert benchmarks.snapshot().get("core") == suite

    logger = JsonlStructuredLogger(config)
    log_record = logger.log(
        level=LogLevel.INFO,
        event="contracts.runtime_validated",
        message="Validated cross-subsystem runtime contracts.",
        source="tests",
        correlation_id=stored_state.key,
        data={
            "registered_packs": registry.snapshot().names(),
            "sentinel_issue_count": len(sentinel_report.issues),
            "verification_status": verification.status.value,
        },
    )

    snapshot = logger.read()
    assert snapshot.records == (log_record,)
    assert snapshot.filter_by_level(LogLevel.INFO) == (log_record,)
    assert snapshot.filter_by_event("contracts.runtime_validated") == (log_record,)
    assert log_record.data["registered_packs"] == ("programming", "architecture")
    assert len(sentinel_report.filter_by_severity(SentinelSeverity.ERROR)) == 2
    assert len(sentinel_report.filter_by_severity(SentinelSeverity.WARNING)) == 1
    assert sentinel_report.filter_by_severity(SentinelSeverity.CRITICAL) == ()
