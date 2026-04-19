from __future__ import annotations

from dataclasses import dataclass, field

from ix_blackfox.bus import EventEnvelope, EventTopic
from ix_blackfox.kernel import TaskKind, TaskRecord
from ix_blackfox.packs import (
    BasePack,
    PackCapability,
    PackCapabilityType,
    PackContext,
    PackExecutionResult,
    PackManifest,
)


@dataclass(frozen=True, slots=True)
class ProgrammingPlanStep:
    """
    One deterministic programming-step suggestion.

    Attributes
    ----------
    step_id:
        Stable step identifier within one programming plan.
    action:
        Short machine-friendly action label.
    summary:
        Human-readable description of the step.
    """

    step_id: str
    action: str
    summary: str

    def __post_init__(self) -> None:
        normalized_step_id = _normalize_identifier(self.step_id, label="step id")
        normalized_action = _normalize_identifier(self.action, label="action")
        normalized_summary = _normalize_text(self.summary, label="summary")

        object.__setattr__(self, "step_id", normalized_step_id)
        object.__setattr__(self, "action", normalized_action)
        object.__setattr__(self, "summary", normalized_summary)


class ProgrammingPack(BasePack):
    """
    Built-in pack for programming-oriented tasks.

    This first version is intentionally deterministic. It does not claim
    autonomous code repair. Instead it converts a programming task into a
    structured action plan, publishes a pack event, and records execution
    state so later forge integration can follow a stable contract.
    """

    @property
    def pack_name(self) -> str:
        return "programming"

    def execute(
        self,
        *,
        task: TaskRecord,
        context: PackContext,
    ) -> PackExecutionResult:
        prompt = task.request.input.prompt
        steps = self._plan_steps(prompt)
        summary = self._build_summary(steps)

        context.shared_state.put(
            "packs",
            "last_executed",
            self.pack_name,
            source=self.pack_name,
        )
        context.shared_state.put(
            "programming",
            "last_task_id",
            task.request.task_id,
            source=self.pack_name,
        )
        context.shared_state.put(
            "programming",
            "last_plan_step_count",
            len(steps),
            source=self.pack_name,
        )

        context.bus.publish(
            EventEnvelope.create(
                topic=EventTopic.PACK,
                source=self.pack_name,
                correlation_id=task.request.task_id,
                payload={
                    "pack": self.pack_name,
                    "task_id": task.request.task_id,
                    "step_count": len(steps),
                    "actions": tuple(step.action for step in steps),
                },
                tags=("pack", "programming", "plan"),
            )
        )

        return PackExecutionResult(
            summary=summary,
            artifacts=("programming-plan.json",),
            metrics={
                "step_count": len(steps),
                "has_test_step": any(step.action == "run-tests" for step in steps),
                "has_patch_step": any(step.action == "prepare-patch" for step in steps),
            },
            data={
                "pack": self.pack_name,
                "task_id": task.request.task_id,
                "task_kind": task.request.kind.value,
                "steps": [
                    {
                        "step_id": step.step_id,
                        "action": step.action,
                        "summary": step.summary,
                    }
                    for step in steps
                ],
            },
        )

    def _plan_steps(self, prompt: str) -> tuple[ProgrammingPlanStep, ...]:
        normalized_prompt = prompt.strip().lower()
        steps: list[ProgrammingPlanStep] = []

        steps.append(
            ProgrammingPlanStep(
                step_id="step-1",
                action="inspect-repository",
                summary="Inspect the repository surface before making changes.",
            )
        )

        if _contains_any(
            normalized_prompt,
            ("bug", "fix", "repair", "patch", "broken", "error", "failing"),
        ):
            steps.append(
                ProgrammingPlanStep(
                    step_id=f"step-{len(steps) + 1}",
                    action="prepare-patch",
                    summary="Prepare a focused patch plan for the failing area.",
                )
            )

        if _contains_any(
            normalized_prompt,
            ("test", "tests", "pytest", "regression", "verify", "validation"),
        ):
            steps.append(
                ProgrammingPlanStep(
                    step_id=f"step-{len(steps) + 1}",
                    action="run-tests",
                    summary="Run targeted tests and collect regression evidence.",
                )
            )

        if _contains_any(
            normalized_prompt,
            ("profile", "performance", "slow", "latency", "optimize"),
        ):
            steps.append(
                ProgrammingPlanStep(
                    step_id=f"step-{len(steps) + 1}",
                    action="profile-execution",
                    summary="Profile execution hot spots before optimization.",
                )
            )

        if _contains_any(
            normalized_prompt,
            ("document", "docs", "readme", "explain", "comment"),
        ):
            steps.append(
                ProgrammingPlanStep(
                    step_id=f"step-{len(steps) + 1}",
                    action="document-results",
                    summary="Document the programming changes and resulting behavior.",
                )
            )

        if len(steps) == 1:
            steps.append(
                ProgrammingPlanStep(
                    step_id="step-2",
                    action="analyze-code",
                    summary="Analyze relevant code paths and derive next actions.",
                )
            )

        return tuple(steps)

    def _build_summary(self, steps: tuple[ProgrammingPlanStep, ...]) -> str:
        action_text = ", ".join(step.action for step in steps)
        return (
            f"Programming pack prepared {len(steps)} deterministic step(s): "
            f"{action_text}."
        )


def build_programming_manifest() -> PackManifest:
    """
    Build the manifest for the built-in programming pack.
    """
    return PackManifest(
        pack_name="programming",
        version="0.1.0",
        description=(
            "Deterministic programming pack for repository inspection, patch "
            "planning, testing, profiling, and code-oriented documentation."
        ),
        supported_kinds=(TaskKind.PROGRAMMING,),
        labels=("code", "patching", "testing", "profiling", "documentation"),
        capabilities=(
            PackCapability(
                name="repository inspection",
                capability_type=PackCapabilityType.REASONING,
                description="Plans repository-first inspection for programming tasks.",
            ),
            PackCapability(
                name="patch planning",
                capability_type=PackCapabilityType.REASONING,
                description="Creates deterministic patch-oriented action sequences.",
            ),
            PackCapability(
                name="test orchestration hinting",
                capability_type=PackCapabilityType.VALIDATION,
                description="Signals when testing and regression steps are expected.",
            ),
        ),
        dependencies=(),
        entrypoint="ix_blackfox.packs.programming.runtime:ProgrammingPack",
        is_default=True,
    )


def _contains_any(text: str, terms: tuple[str, ...]) -> bool:
    return any(term in text for term in terms)


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError(f"Programming pack {label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"Programming pack {label} must not be empty.")
    return cleaned
