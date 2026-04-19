from __future__ import annotations

from pathlib import Path

from ix_blackfox.bus import InMemoryEventBus
from ix_blackfox.config import load_runtime_config
from ix_blackfox.eval import (
    EvaluationContext,
    OutputVerifier,
    RuleBasedEvaluator,
    VerificationContext,
    VerificationStatus,
)
from ix_blackfox.kernel import BlackFoxKernel, SharedStateStore, TaskKind, TaskRecord, TaskRequest
from ix_blackfox.memory import TraceMemoryStore
from ix_blackfox.observability import JsonlStructuredLogger, LogLevel
from ix_blackfox.packs import PackContext, PackLoader, PackManifestRegistry
from ix_blackfox.packs.programming import build_programming_manifest
from ix_blackfox.sentinel import FailureLoopCheck, FailureLoopWindow, SentinelContext, SentinelRuntime
from ix_blackfox.switchboard import CapabilityRoute, CapabilitySwitchboard
from ix_blackfox.eval import EvidenceRecorder


def test_smoke_programming_runtime_flow(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    kernel = BlackFoxKernel(config)
    kernel.start()

    bus = InMemoryEventBus()
    shared_state = SharedStateStore()
    logger = JsonlStructuredLogger(config)
    traces = TraceMemoryStore()
    evidence = EvidenceRecorder()

    manifest = build_programming_manifest()
    registry = PackManifestRegistry()
    registry.register(manifest)

    switchboard = CapabilitySwitchboard()
    switchboard.register(
        CapabilityRoute(
            capability_name=manifest.pack_name,
            supported_kinds=manifest.supported_kinds,
            labels=manifest.labels,
            description=manifest.description,
            is_fallback=manifest.is_default,
        )
    )

    request = TaskRequest.create(
        prompt="Fix the failing tests, prepare a patch, and run regression checks.",
        kind=TaskKind.PROGRAMMING,
        labels=("code", "tests", "patching"),
    )
    task = TaskRecord(request=request).mark_ready().mark_running()

    route = switchboard.route(task.request)
    assert route is not None
    assert route.capability_name == "programming"

    loaded = PackLoader().load(manifest)
    pack_type = loaded.implementation
    pack = pack_type()
    result = pack.execute(
        task=task,
        context=PackContext(
            config=config,
            bus=bus,
            shared_state=shared_state,
        ),
    )

    traces.append(
        correlation_id=task.request.task_id,
        stage="pack",
        message=result.summary,
        level="info",
        source="programming",
        tags=("pack", "programming"),
    )

    sentinel = SentinelRuntime()
    sentinel.register(
        FailureLoopCheck(
            window=FailureLoopWindow(
                lookback_limit=5,
                trigger_count=3,
            )
        )
    )
    sentinel_report = sentinel.evaluate(
        SentinelContext(
            task=task,
            trace_records=traces.snapshot().records,
        )
    )

    evaluator = RuleBasedEvaluator(
        evaluator_name="pack_output_quality",
        rules=(lambda context: None,),
    )
    evaluation = evaluator.evaluate(
        EvaluationContext(
            task=task,
            artifacts=result.artifacts,
            metadata={"step_count": result.metrics["step_count"]},
        )
    )

    evidence_record = evidence.record(
        subject_id=task.request.task_id,
        evidence_type="artifact",
        summary="Captured programming pack artifact output.",
        source="programming",
        artifact_refs=result.artifacts,
        metadata={"step_count": result.metrics["step_count"]},
    )

    verification = OutputVerifier().verify(
        VerificationContext(
            subject_id=task.request.task_id,
            expected_artifacts=("programming-plan.json",),
            produced_artifacts=result.artifacts,
            evaluation_results=(evaluation,),
        )
    )

    log_record = logger.log(
        level=LogLevel.INFO,
        event="smoke.runtime_flow",
        message="Completed programming runtime smoke flow.",
        source="tests",
        correlation_id=task.request.task_id,
        data={
            "pack": manifest.pack_name,
            "route": route.capability_name,
            "artifact_count": len(result.artifacts),
            "verification_status": verification.status.value,
        },
    )

    assert kernel.status.value == "running"
    assert registry.snapshot().names() == ("programming",)
    assert shared_state.get("packs", "last_executed") is not None
    assert shared_state.get("packs", "last_executed").value == "programming"
    assert len(bus.history()) == 1
    assert sentinel_report.issues == ()
    assert evaluation.passed() is True
    assert evidence_record.artifact_refs == ("programming-plan.json",)
    assert evidence.snapshot().filter_by_subject(task.request.task_id) == (evidence_record,)
    assert verification.status == VerificationStatus.PASSED
    assert logger.read().records == (log_record,)
