from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ix_blackfox.forge.patch_plan import (
    PatchOperation,
    PatchOperationType,
    PatchPlan,
    PatchPriority,
)
from ix_blackfox.governance import (
    ActionIntent,
    ActionKind,
    ActionRiskProfile,
    RiskFactor,
    RiskLevel,
)


@dataclass(frozen=True, slots=True)
class GovernedPatchIntentBundle:
    """
    One patch-plan operation translated into governance-ready intent and risk.

    The bundle is intentionally operation-scoped instead of plan-scoped so a
    mixed plan can allow a low-risk docs change while still requiring review for
    a destructive source mutation in the same generated plan.
    """

    plan: PatchPlan
    operation: PatchOperation
    intent: ActionIntent
    risk: ActionRiskProfile
    operation_index: int
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.operation_index < 0:
            raise ValueError("operation_index must be zero or greater.")
        if self.risk.intent_id != self.intent.intent_id:
            raise ValueError("Patch intent bundle risk must reference the intent id.")
        object.__setattr__(self, "metadata", dict(self.metadata))


GovernedPatchIntent = GovernedPatchIntentBundle


class ForgePatchIntentBridge:
    """
    Convert forge patch plans into explicit governance action intents.

    This bridge does not apply patches and does not approve them. It translates
    patch-planner output into the same governance model used by the runtime so
    generated repairs stay policy-visible, auditable, and reviewable.
    """

    def build_bundles(
        self,
        *,
        task_id: str,
        plan: PatchPlan,
        requested_by: str | None = None,
        labels: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> tuple[GovernedPatchIntentBundle, ...]:
        """
        Build one governance bundle for each operation in a patch plan.
        """
        base_metadata = dict(metadata or {})
        return tuple(
            self._build_bundle(
                task_id=task_id,
                plan=plan,
                operation=operation,
                operation_index=operation_index,
                requested_by=requested_by,
                labels=labels,
                metadata=base_metadata,
            )
            for operation_index, operation in enumerate(plan.operations)
        )

    def build(
        self,
        *,
        task_id: str,
        plan: PatchPlan,
        requested_by: str | None = None,
        labels: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> GovernedPatchIntentBundle:
        """
        Build a single bundle for a one-operation patch plan.
        """
        bundles = self.build_bundles(
            task_id=task_id,
            plan=plan,
            requested_by=requested_by,
            labels=labels,
            metadata=metadata,
        )
        if len(bundles) != 1:
            raise ValueError(
                "build() requires a patch plan with exactly one operation."
            )
        return bundles[0]

    def _build_bundle(
        self,
        *,
        task_id: str,
        plan: PatchPlan,
        operation: PatchOperation,
        operation_index: int,
        requested_by: str | None,
        labels: tuple[str, ...],
        metadata: dict[str, Any],
    ) -> GovernedPatchIntentBundle:
        intent_metadata: dict[str, Any] = {
            **metadata,
            "plan_id": plan.plan_id,
            "plan_summary": plan.summary,
            "operation_index": operation_index,
            "operation_type": operation.operation_type.value,
            "operation_priority": operation.priority.value,
            "operation_summary": operation.summary,
            "operation_rationale": operation.rationale,
        }
        intent = ActionIntent.create(
            task_id=task_id,
            action_kind=ActionKind.FILE_WRITE,
            summary=operation.summary,
            rationale=operation.rationale,
            target_locator=operation.relative_path,
            requested_by=requested_by,
            labels=self._labels_for_operation(operation=operation, extra_labels=labels),
            metadata=intent_metadata,
        )
        risk = self._risk_for_operation(intent=intent, operation=operation)
        return GovernedPatchIntentBundle(
            plan=plan,
            operation=operation,
            intent=intent,
            risk=risk,
            operation_index=operation_index,
            metadata={
                "plan_id": plan.plan_id,
                "operation_type": operation.operation_type.value,
                "operation_priority": operation.priority.value,
            },
        )

    def _labels_for_operation(
        self,
        *,
        operation: PatchOperation,
        extra_labels: tuple[str, ...],
    ) -> tuple[str, ...]:
        labels = (
            "patch-plan",
            "forge-patch",
            operation.operation_type.value,
            operation.priority.value,
            *extra_labels,
        )
        return _normalize_labels(labels)

    def _risk_for_operation(
        self,
        *,
        intent: ActionIntent,
        operation: PatchOperation,
    ) -> ActionRiskProfile:
        scope = _scope_for_path(operation.relative_path)
        risk_level = _risk_level_for_operation(operation=operation, scope=scope)
        requires_approval = _requires_approval(
            operation=operation,
            risk_level=risk_level,
            scope=scope,
        )
        factors = _risk_factors_for_operation(
            operation=operation,
            risk_level=risk_level,
            scope=scope,
            requires_approval=requires_approval,
        )
        tags = _risk_tags_for_operation(operation=operation, scope=scope)
        return ActionRiskProfile(
            intent_id=intent.intent_id,
            risk_level=risk_level,
            requires_approval=requires_approval,
            factors=factors,
            tags=tags,
        )


class GovernedPatchIntentBuilder:
    """
    Backward-compatible facade for older forge callers.
    """

    def __init__(self, *, bridge: ForgePatchIntentBridge | None = None) -> None:
        self._bridge = bridge or ForgePatchIntentBridge()

    def build(
        self,
        patch_plan: PatchPlan,
        *,
        task_id: str | None = None,
        requested_by: str | None = None,
        labels: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> GovernedPatchIntentBundle:
        return self._bridge.build(
            task_id=task_id or patch_plan.plan_id,
            plan=patch_plan,
            requested_by=requested_by,
            labels=labels,
            metadata=metadata,
        )

    def build_many(
        self,
        patch_plans: tuple[PatchPlan, ...],
        *,
        task_id: str | None = None,
        requested_by: str | None = None,
        labels: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> tuple[GovernedPatchIntentBundle, ...]:
        bundles: list[GovernedPatchIntentBundle] = []
        for patch_plan in patch_plans:
            bundles.extend(
                self._bridge.build_bundles(
                    task_id=task_id or patch_plan.plan_id,
                    plan=patch_plan,
                    requested_by=requested_by,
                    labels=labels,
                    metadata=metadata,
                )
            )
        return tuple(bundles)


def _risk_level_for_operation(*, operation: PatchOperation, scope: str) -> RiskLevel:
    if operation.priority is PatchPriority.CRITICAL:
        return RiskLevel.HIGH
    if operation.operation_type is PatchOperationType.DELETE:
        return RiskLevel.HIGH
    if (
        operation.priority is PatchPriority.HIGH
        and scope in {"source", "config", "unknown"}
    ):
        return RiskLevel.HIGH
    if scope == "docs" and operation.priority is PatchPriority.LOW:
        return RiskLevel.LOW
    return RiskLevel.MODERATE


def _requires_approval(
    *,
    operation: PatchOperation,
    risk_level: RiskLevel,
    scope: str,
) -> bool:
    if risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
        return True
    if operation.operation_type is PatchOperationType.DELETE:
        return True
    if operation.priority is PatchPriority.CRITICAL:
        return True
    if scope in {"config", "secrets", "unknown"}:
        return True
    return False


def _risk_factors_for_operation(
    *,
    operation: PatchOperation,
    risk_level: RiskLevel,
    scope: str,
    requires_approval: bool,
) -> tuple[RiskFactor, ...]:
    factors: list[RiskFactor] = [
        RiskFactor(
            code="filesystem-write",
            description="Patch operation writes or mutates a workspace file.",
        )
    ]

    if scope == "docs":
        factors.append(
            RiskFactor(
                code="documentation-only-change",
                description="Patch target is inside documentation scope.",
            )
        )
    elif scope == "tests":
        factors.append(
            RiskFactor(
                code="test-suite-mutation",
                description="Patch target is inside test-suite scope.",
            )
        )
    elif scope == "source":
        factors.append(
            RiskFactor(
                code="tracked-source-mutation",
                description="Patch target is inside source-code scope.",
            )
        )
    elif scope == "config":
        factors.append(
            RiskFactor(
                code="configuration-mutation",
                description="Patch target is inside configuration scope.",
            )
        )
    elif scope == "secrets":
        factors.append(
            RiskFactor(
                code="sensitive-path-mutation",
                description="Patch target references a sensitive path segment.",
            )
        )
    else:
        factors.append(
            RiskFactor(
                code="unclassified-path-mutation",
                description="Patch target is outside known low-risk repository scopes.",
            )
        )

    if operation.operation_type is PatchOperationType.CREATE:
        factors.append(
            RiskFactor(
                code="file-creation",
                description="Patch operation creates a new workspace file.",
            )
        )
    elif operation.operation_type is PatchOperationType.UPDATE:
        factors.append(
            RiskFactor(
                code="file-update",
                description="Patch operation updates an existing workspace file.",
            )
        )
    elif operation.operation_type is PatchOperationType.DELETE:
        factors.append(
            RiskFactor(
                code="destructive-file-mutation",
                description="Patch operation deletes a workspace file.",
            )
        )

    if operation.priority is PatchPriority.CRITICAL:
        factors.append(
            RiskFactor(
                code="critical-patch-priority",
                description="Patch operation is marked critical priority.",
            )
        )
    elif operation.priority is PatchPriority.HIGH:
        factors.append(
            RiskFactor(
                code="high-patch-priority",
                description="Patch operation is marked high priority.",
            )
        )

    if requires_approval:
        factors.append(
            RiskFactor(
                code="review-sensitive-mutation",
                description="Patch operation requires review before execution.",
            )
        )
    if risk_level is RiskLevel.CRITICAL:
        factors.append(
            RiskFactor(
                code="critical-risk-classification",
                description="Patch operation was classified as critical risk.",
            )
        )

    return _dedupe_risk_factors(tuple(factors))


def _risk_tags_for_operation(
    *,
    operation: PatchOperation,
    scope: str,
) -> tuple[str, ...]:
    return _normalize_labels(
        (
            f"scope-{scope}",
            f"op-{operation.operation_type.value}",
            f"priority-{operation.priority.value}",
        )
    )


def _scope_for_path(relative_path: str) -> str:
    normalized = relative_path.strip().replace("\\", "/").lower()
    parts = tuple(part for part in normalized.split("/") if part)
    if not parts:
        return "unknown"
    if any(part in {"secret", "secrets", ".ssh"} for part in parts):
        return "secrets"
    if parts[0] == "docs" or normalized.endswith((".md", ".rst", ".txt")):
        return "docs"
    if parts[0] == "tests" or any(part == "tests" for part in parts):
        return "tests"
    if parts[0] == "src":
        return "source"
    if parts[0] in {"config", "configs", ".github"} or normalized.endswith(
        (".toml", ".yaml", ".yml", ".json")
    ):
        return "config"
    return "unknown"


def _normalize_labels(labels: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_label in labels:
        cleaned = raw_label.strip().lower()
        if not cleaned:
            continue
        if cleaned in seen:
            continue
        normalized.append(cleaned)
        seen.add(cleaned)
    return tuple(normalized)


def _dedupe_risk_factors(factors: tuple[RiskFactor, ...]) -> tuple[RiskFactor, ...]:
    deduped: list[RiskFactor] = []
    seen: set[str] = set()
    for factor in factors:
        if factor.code in seen:
            continue
        deduped.append(factor)
        seen.add(factor.code)
    return tuple(deduped)
