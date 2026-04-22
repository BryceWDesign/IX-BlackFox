from __future__ import annotations

from datetime import UTC, datetime

from ix_blackfox.forge import (
    ForgePatchIntentBridge,
    PatchOperation,
    PatchOperationType,
    PatchPlan,
    PatchPriority,
)
from ix_blackfox.governance import ActionKind, RiskLevel


def test_patch_intent_bridge_builds_low_risk_docs_bundle() -> None:
    plan = PatchPlan(
        plan_id="plan-docs",
        summary="Docs-only patch plan.",
        created_at=datetime.now(tz=UTC),
        operations=(
            PatchOperation(
                operation_type=PatchOperationType.UPDATE,
                relative_path="docs/system-architecture.md",
                priority=PatchPriority.LOW,
                summary="Refresh system architecture note.",
                rationale="Documentation should reflect the governed runtime boundary.",
            ),
        ),
    )

    bundle = ForgePatchIntentBridge().build_bundles(
        task_id="task-docs",
        plan=plan,
        requested_by="packs.architecture",
    )[0]

    assert bundle.operation.relative_path == "docs/system-architecture.md"
    assert bundle.intent.task_id == "task-docs"
    assert bundle.intent.action_kind == ActionKind.FILE_WRITE
    assert bundle.intent.requested_by == "packs.architecture"
    assert bundle.intent.metadata["plan_id"] == "plan-docs"
    assert bundle.intent.metadata["operation_type"] == "update"
    assert bundle.risk.risk_level == RiskLevel.LOW
    assert bundle.risk.requires_approval is False
    assert "scope-docs" in bundle.risk.tags


def test_patch_intent_bridge_builds_moderate_source_update_bundle() -> None:
    plan = PatchPlan(
        plan_id="plan-source",
        summary="Source mutation patch plan.",
        created_at=datetime.now(tz=UTC),
        operations=(
            PatchOperation(
                operation_type=PatchOperationType.UPDATE,
                relative_path="src/ix_blackfox/runtime/orchestrator.py",
                priority=PatchPriority.NORMAL,
                summary="Refine orchestrator flow.",
                rationale="Runtime flow needs stronger governed mediation.",
            ),
        ),
    )

    bundle = ForgePatchIntentBridge().build_bundles(
        task_id="task-source",
        plan=plan,
        labels=("runtime", "forge"),
        metadata={"origin": "planner"},
    )[0]

    assert bundle.intent.target_locator == "src/ix_blackfox/runtime/orchestrator.py"
    assert bundle.intent.labels == (
        "patch-plan",
        "forge-patch",
        "update",
        "normal",
        "runtime",
        "forge",
    )
    assert bundle.intent.metadata["origin"] == "planner"
    assert bundle.risk.risk_level == RiskLevel.MODERATE
    assert bundle.risk.requires_approval is False
    assert "tracked-source-mutation" in bundle.risk.factor_codes()
    assert "scope-source" in bundle.risk.tags


def test_patch_intent_bridge_requires_approval_for_destructive_source_delete() -> None:
    plan = PatchPlan(
        plan_id="plan-delete",
        summary="Destructive source patch plan.",
        created_at=datetime.now(tz=UTC),
        operations=(
            PatchOperation(
                operation_type=PatchOperationType.DELETE,
                relative_path="src/ix_blackfox/legacy_module.py",
                priority=PatchPriority.HIGH,
                summary="Delete legacy module.",
                rationale="Retire superseded runtime code path.",
            ),
        ),
    )

    bundle = ForgePatchIntentBridge().build_bundles(
        task_id="task-delete",
        plan=plan,
    )[0]

    assert bundle.risk.risk_level == RiskLevel.HIGH
    assert bundle.risk.requires_approval is True
    assert "destructive-file-mutation" in bundle.risk.factor_codes()
    assert "review-sensitive-mutation" in bundle.risk.factor_codes()
    assert "op-delete" in bundle.risk.tags


def test_patch_intent_bridge_escalates_critical_source_update_to_high_risk() -> None:
    plan = PatchPlan(
        plan_id="plan-critical",
        summary="Critical source patch plan.",
        created_at=datetime.now(tz=UTC),
        operations=(
            PatchOperation(
                operation_type=PatchOperationType.UPDATE,
                relative_path="src/ix_blackfox/kernel/runtime.py",
                priority=PatchPriority.CRITICAL,
                summary="Repair runtime syntax break.",
                rationale="Critical parser-visible defect requires immediate repair.",
            ),
        ),
    )

    bundle = ForgePatchIntentBridge().build_bundles(
        task_id="task-critical",
        plan=plan,
    )[0]

    assert bundle.risk.risk_level == RiskLevel.HIGH
    assert bundle.risk.requires_approval is True
    assert "critical-patch-priority" in bundle.risk.factor_codes()


def test_patch_intent_bridge_returns_one_bundle_per_operation() -> None:
    plan = PatchPlan(
        plan_id="plan-multi",
        summary="Multi-operation patch plan.",
        created_at=datetime.now(tz=UTC),
        operations=(
            PatchOperation(
                operation_type=PatchOperationType.CREATE,
                relative_path="tests/test_runtime_governance.py",
                priority=PatchPriority.NORMAL,
                summary="Add governance runtime test.",
                rationale="Extend runtime coverage for governed actions.",
            ),
            PatchOperation(
                operation_type=PatchOperationType.UPDATE,
                relative_path="docs/fusion-audit.md",
                priority=PatchPriority.LOW,
                summary="Refresh fusion audit notes.",
                rationale="Document the governed execution evolution.",
            ),
        ),
    )

    bundles = ForgePatchIntentBridge().build_bundles(
        task_id="task-multi",
        plan=plan,
    )

    assert len(bundles) == 2
    assert bundles[0].intent.metadata["operation_index"] == 0
    assert bundles[1].intent.metadata["operation_index"] == 1
