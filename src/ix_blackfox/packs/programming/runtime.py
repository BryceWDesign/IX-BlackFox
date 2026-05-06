from __future__ import annotations

from dataclasses import dataclass

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
class ProgrammingPackConfig:
    """
    Configuration for the programming pack runtime behavior.

    Attributes
    ----------
    allow_patch_generation:
        Whether the pack may emit patch suggestions.
    require_tests_for_code_changes:
        Whether code-changing work should require test evidence.
    """

    allow_patch_generation: bool = False
    require_tests_for_code_changes: bool = True


class ProgrammingPack(BasePack):
    """
    Conservative programming pack implementation.

    The pack can classify programming tasks and emit deterministic
    planning guidance. It does not modify files directly; generated
    changes must flow through forge, governance, and receipts.
    """

    def __init__(
        self,
        *,
        manifest: PackManifest | None = None,
        config: ProgrammingPackConfig | None = None,
    ) -> None:
        super().__init__(manifest=manifest or build_programming_pack_manifest())
        self._config = config or ProgrammingPackConfig()

    @property
    def config(self) -> ProgrammingPackConfig:
        """
        Return the pack runtime configuration.
        """
        return self._config

    def can_handle(self, task: TaskRecord, context: PackContext) -> bool:
        """
        Return whether this pack should handle a task.
        """
        if task.kind in {TaskKind.CODE, TaskKind.TEST, TaskKind.REFACTOR}:
            return True

        searchable_text = " ".join(
            [
                task.title,
                task.description,
                " ".join(task.tags),
                str(context.metadata.get("pack_hint", "")),
            ]
        ).lower()

        keywords = {
            "bug",
            "ci",
            "code",
            "debug",
            "lint",
            "patch",
            "pytest",
            "refactor",
            "ruff",
            "test",
        }
        return any(keyword in searchable_text for keyword in keywords)

    def handle(self, task: TaskRecord, context: PackContext) -> PackExecutionResult:
        """
        Build deterministic programming-task guidance.
        """
        if not self.can_handle(task, context):
            return PackExecutionResult(
                handled=False,
                summary="Programming pack did not match this task.",
                evidence={
                    "task_kind": task.kind.value,
                    "pack": self.manifest.name,
                },
            )

        recommended_actions = self._recommended_actions(task=task, context=context)
        blocked_actions = self._blocked_actions(task=task)

        return PackExecutionResult(
            handled=True,
            summary=self._summary(task=task),
            recommended_actions=recommended_actions,
            blocked_actions=blocked_actions,
            evidence={
                "task_id": task.id,
                "task_kind": task.kind.value,
                "pack": self.manifest.name,
                "allow_patch_generation": self._config.allow_patch_generation,
                "require_tests_for_code_changes": (
                    self._config.require_tests_for_code_changes
                ),
            },
            emitted_events=(
                EventEnvelope(
                    topic=EventTopic.PACK_SELECTED,
                    payload={
                        "task_id": task.id,
                        "pack": self.manifest.name,
                        "task_kind": task.kind.value,
                    },
                ),
            ),
        )

    def _recommended_actions(
        self,
        *,
        task: TaskRecord,
        context: PackContext,
    ) -> tuple[str, ...]:
        actions = [
            "Inspect failing evidence before proposing edits.",
            "Classify whether the change is code, test, docs, or config.",
            "Keep file writes inside the reserved workspace boundary.",
            "Run deterministic verification before marking the task complete.",
        ]

        if context.brain_context is not None:
            actions.append(
                f"Route through brain role {context.brain_context.brain_role.value} "
                f"using {context.brain_context.brain_name}."
            )

        if self._config.allow_patch_generation:
            actions.append("Generate patch candidates only after policy review.")
        else:
            actions.append("Do not generate patches directly from the pack runtime.")

        if task.kind in {TaskKind.CODE, TaskKind.REFACTOR}:
            actions.append("Require tests or a documented no-test rationale.")

        return tuple(actions)

    def _blocked_actions(self, *, task: TaskRecord) -> tuple[str, ...]:
        blocked = [
            "Do not bypass governance checks.",
            "Do not write outside the reserved workspace.",
        ]

        if task.kind in {TaskKind.CODE, TaskKind.REFACTOR}:
            blocked.append("Do not claim success without verification evidence.")

        return tuple(blocked)

    def _summary(self, *, task: TaskRecord) -> str:
        return (
            f"Programming pack matched {task.kind.value} task {task.id} "
            "and produced governed implementation guidance."
        )


def build_programming_pack_manifest() -> PackManifest:
    """
    Build the built-in programming pack manifest.
    """
    return PackManifest(
        name="programming",
        version="0.1.0",
        description=(
            "Conservative programming specialist pack for code, tests, lint, "
            "debugging, and refactor work."
        ),
        capabilities=(
            PackCapability(
                capability_type=PackCapabilityType.CODE_ANALYSIS,
                name="code-analysis",
                description="Analyze code-related tasks and failing evidence.",
            ),
            PackCapability(
                capability_type=PackCapabilityType.TESTING,
                name="test-planning",
                description="Plan verification for code changes.",
            ),
            PackCapability(
                capability_type=PackCapabilityType.REFACTORING,
                name="refactor-guidance",
                description="Provide conservative refactor guidance.",
            ),
        ),
        tags=("code", "test", "debug", "lint", "refactor", "ci"),
    )
