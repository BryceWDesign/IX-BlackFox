from __future__ import annotations

from dataclasses import dataclass, field

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
    One governed patch-operation bundle.

    This bundle keeps the original patch operation adjacent to the
    normalized governance artifacts that later policy and execution
    layers will consume.
    """

    operation: PatchOperation
    intent: ActionIntent
    risk: ActionRiskProfile


class ForgePatchIntentBridge:
    """
    Deterministic bridge from patch plans to governed action intents.

    The bridge does not execute anything. It converts each patch
    operation into a normalized action intent and a first-pass risk
    profile so governance policy can reason about file mutations in a
    stable, explicit way.
    """

    def build_bundles(
        self,
        *,
        task_id: str,
        plan: PatchPlan,
        requested_by: str | None = None,
        labels: tuple[str, ...] = (),
        metadata: dict[str, object] | None = None,
    ) -> tuple[GovernedPatchIntentBundle, ...]:
        """
        Convert one patch plan into governed action bundles.
        """
        bundles: list[GovernedPatchIntentBundle] = []
        normalized_metadata = dict(metadata or {})

        for index, operation in enumerate(plan.operations):
            intent_metadata = {
                **normalized_metadata,
                "plan_id": plan.plan_id,
                "operation_index": index,
                "operation_type": operation.operation_type.value,
                "patch_priority": operation.priority.value,
            }
            intent = ActionIntent.create(
                task_id=task_id,
                action_kind=ActionKind.FILE_WRITE,
                summary=operation.summary,
                rationale=operation.rationale,
                target_locator=operation.relative_path,
                requested_by=requested_by,
                labels=_bundle_labels(operation=operation, labels=labels),
                metadata=intent_metadata,
            )
            risk = _build_risk_profile(intent=intent, operation=operation)
            bundles.append(
                GovernedPatchIntentBundle(
                    operation=operation,
                    intent=intent,
                    risk=risk,
                )
            )

        return tuple(bundles)


def _build_risk_profile(
    *,
    intent: ActionIntent,
    operation: PatchOperation,
) -> ActionRiskProfile:
    risk_level = _derive_risk_level(operation=operation)
    factors = tuple(_derive_risk_factors(operation=operation, risk_level=risk_level))
    requires_approval = (
        operation.operation_type == PatchOperationType.DELETE
        or risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
    )

    return ActionRiskProfile(
        intent_id=intent.intent_id,
        risk_level=risk_level,
        requires_approval=requires_approval,
        factors=factors,
        tags=_risk_tags(operation=operation, risk_level=risk_level),
    )


def _derive_risk_level(*, operation: PatchOperation) -> RiskLevel:
    base_risk = _base_risk_for_path_and_operation(operation=operation)
    if operation.priority == PatchPriority.CRITICAL:
        return _escalate_risk(base_risk)
    if operation.priority == PatchPriority.HIGH and base_risk == RiskLevel.LOW:
        return RiskLevel.MODERATE
    return base_risk


def _base_risk_for_path_and_operation(*, operation: PatchOperation) -> RiskLevel:
    relative_path = operation.relative_path

    if _is_test_path(relative_path):
        if operation.operation_type == PatchOperationType.DELETE:
            return RiskLevel.MODERATE
        return RiskLevel.LOW

    if _is_docs_path(relative_path):
        if operation.operation_type == PatchOperationType.DELETE:
            return RiskLevel.MODERATE
        return RiskLevel.LOW

    if relative_path.startswith("src/"):
        if operation.operation_type == PatchOperationType.DELETE:
            return RiskLevel.HIGH
        return RiskLevel.MODERATE

    if operation.operation_type == PatchOperationType.DELETE:
        return RiskLevel.HIGH
    return RiskLevel.MODERATE


def _derive_risk_factors(
    *,
    operation: PatchOperation,
    risk_level: RiskLevel,
) -> list[RiskFactor]:
    factors: list[RiskFactor] = [
        RiskFactor(
            code=f"patch-{operation.operation_type.value}",
            description=(
                f"Patch plan proposes a {operation.operation_type.value.lower()} "
                "operation against a tracked workspace path."
            ),
        )
    ]

    if operation.relative_path.startswith("src/"):
        factors.append(
            RiskFactor(
                code="tracked-source-mutation",
                description="Operation targets tracked application source code.",
            )
        )
    elif _is_test_path(operation.relative_path):
        factors.append(
            RiskFactor(
                code="test-scope-mutation",
                description="Operation is limited to test-scope files.",
            )
        )
    elif _is_docs_path(operation.relative_path):
        factors.append(
            RiskFactor(
                code="documentation-mutation",
                description="Operation targets documentation or guidance artifacts.",
            )
        )
    else:
        factors.append(
            RiskFactor(
                code="workspace-mutation",
                description="Operation mutates a tracked workspace path.",
            )
        )

    if operation.priority == PatchPriority.CRITICAL:
        factors.append(
            RiskFactor(
                code="critical-patch-priority",
                description="Patch planner marked the operation as critical priority.",
            )
        )
    elif operation.priority == PatchPriority.HIGH:
        factors.append(
            RiskFactor(
                code="high-patch-priority",
                description="Patch planner marked the operation as high priority.",
            )
        )

    if operation.operation_type == PatchOperationType.DELETE:
        factors.append(
            RiskFactor(
                code="destructive-file-mutation",
                description="Operation deletes a tracked file path.",
            )
        )

    if risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
        factors.append(
            RiskFactor(
                code="review-sensitive-mutation",
                description="Operation crosses the threshold for governed review.",
            )
        )

    return factors


def _bundle_labels(
    *,
    operation: PatchOperation,
    labels: tuple[str, ...],
) -> tuple[str, ...]:
    combined = [
        "patch-plan",
        "forge-patch",
        operation.operation_type.value.lower(),
        operation.priority.value.lower(),
        *labels,
    ]
    normalized: list[str] = []
    seen: set[str] = set()

    for raw_label in combined:
        cleaned = raw_label.strip().lower()
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _risk_tags(
    *,
    operation: PatchOperation,
    risk_level: RiskLevel,
) -> tuple[str, ...]:
    tags = [
        "forge-patch",
        f"risk-{risk_level.value.lower()}",
        f"priority-{operation.priority.value.lower()}",
        f"op-{operation.operation_type.value.lower()}",
    ]
    if operation.relative_path.startswith("src/"):
        tags.append("scope-source")
    elif _is_test_path(operation.relative_path):
        tags.append("scope-tests")
    elif _is_docs_path(operation.relative_path):
        tags.append("scope-docs")
    else:
        tags.append("scope-workspace")

    normalized: list[str] = []
    seen: set[str] = set()

    for raw_tag in tags:
        cleaned = raw_tag.strip().lower()
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _is_test_path(relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/")
    return normalized.startswith("tests/") or "/tests/" in normalized or normalized.startswith(
        "input/tests/"
    )


def _is_docs_path(relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/")
    return normalized.startswith("docs/") or normalized.endswith(".md")


def _escalate_risk(level: RiskLevel) -> RiskLevel:
    if level == RiskLevel.LOW:
        return RiskLevel.MODERATE
    if level == RiskLevel.MODERATE:
        return RiskLevel.HIGH
    return level
