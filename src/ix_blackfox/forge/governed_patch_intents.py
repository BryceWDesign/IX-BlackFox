from __future__ import annotations

from dataclasses import dataclass

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
class GovernedPatchIntent:
    """
    Pair a forge patch plan with deterministic governance intent.

    This is the boundary object that lets the local forge present patch
    work to Wave 2 governance without bypassing policy, receipt, or
    human-review controls.
    """

    patch_plan: PatchPlan
    action_intent: ActionIntent


class GovernedPatchIntentBuilder:
    """
    Convert forge patch plans into explicit governance intents.

    The builder intentionally treats every write-capable patch plan as
    at least medium risk and human-reviewable by default. Later waves can
    tune policy pack thresholds, but the default posture remains
    conservative and auditable.
    """

    def build(self, patch_plan: PatchPlan) -> GovernedPatchIntent:
        """
        Build a governed intent for one patch plan.
        """
        risk_profile = self._risk_profile_for_patch_plan(patch_plan)
        action_intent = ActionIntent(
            action_id=f"patch-plan:{patch_plan.plan_id}",
            actor="ix-blackfox-forge",
            kind=ActionKind.MODIFY_FILE,
            target=patch_plan.target_path,
            description=patch_plan.summary,
            risk_profile=risk_profile,
            metadata={
                "plan_id": patch_plan.plan_id,
                "priority": patch_plan.priority.value,
                "operation_count": str(len(patch_plan.operations)),
            },
        )
        return GovernedPatchIntent(
            patch_plan=patch_plan,
            action_intent=action_intent,
        )

    def build_many(self, patch_plans: tuple[PatchPlan, ...]) -> tuple[GovernedPatchIntent, ...]:
        """
        Build governed intents for many patch plans.
        """
        return tuple(self.build(patch_plan) for patch_plan in patch_plans)

    def _risk_profile_for_patch_plan(self, patch_plan: PatchPlan) -> ActionRiskProfile:
        changed_line_total = sum(
            operation.expected_line_delta for operation in patch_plan.operations
        )
        destructive_operations = tuple(
            operation
            for operation in patch_plan.operations
            if operation.operation_type
            in {
                PatchOperationType.DELETE_RANGE,
                PatchOperationType.REPLACE_RANGE,
                PatchOperationType.REPLACE_FILE,
            }
        )
        creates_file = any(
            operation.operation_type is PatchOperationType.CREATE_FILE
            for operation in patch_plan.operations
        )

        risk_level = self._risk_level(
            patch_plan=patch_plan,
            changed_line_total=changed_line_total,
            destructive_operations=destructive_operations,
            creates_file=creates_file,
        )

        factors: list[RiskFactor] = [
            RiskFactor.FILESYSTEM_WRITE,
        ]
        if destructive_operations:
            factors.append(RiskFactor.DESTRUCTIVE_OPERATION)
        if creates_file:
            factors.append(RiskFactor.EXTERNAL_SIDE_EFFECT)
        if patch_plan.priority is PatchPriority.URGENT:
            factors.append(RiskFactor.IRREVERSIBLE_OPERATION)

        return ActionRiskProfile(
            level=risk_level,
            factors=tuple(dict.fromkeys(factors)),
            requires_human_review=True,
            rationale=self._rationale(
                patch_plan=patch_plan,
                risk_level=risk_level,
                changed_line_total=changed_line_total,
                destructive_operations=destructive_operations,
            ),
        )

    def _risk_level(
        self,
        *,
        patch_plan: PatchPlan,
        changed_line_total: int,
        destructive_operations: tuple[PatchOperation, ...],
        creates_file: bool,
    ) -> RiskLevel:
        if patch_plan.priority is PatchPriority.URGENT:
            return RiskLevel.HIGH
        if any(
            operation.operation_type is PatchOperationType.REPLACE_FILE
            for operation in destructive_operations
        ):
            return RiskLevel.HIGH
        if len(patch_plan.operations) >= 5:
            return RiskLevel.HIGH
        if changed_line_total >= 80:
            return RiskLevel.HIGH
        if destructive_operations:
            return RiskLevel.MEDIUM
        if creates_file:
            return RiskLevel.MEDIUM
        return RiskLevel.MEDIUM

    def _rationale(
        self,
        *,
        patch_plan: PatchPlan,
        risk_level: RiskLevel,
        changed_line_total: int,
        destructive_operations: tuple[PatchOperation, ...],
    ) -> str:
        details = [
            f"Patch plan {patch_plan.plan_id} targets {patch_plan.target_path}.",
            f"Risk level is {risk_level.value}.",
            f"Operation count: {len(patch_plan.operations)}.",
            f"Expected line delta: {changed_line_total}.",
        ]
        if destructive_operations:
            details.append(
                f"Destructive operation count: {len(destructive_operations)}."
            )
        details.append("Human review is required before applying generated patches.")
        return " ".join(details)
