from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from pathlib import Path
from uuid import uuid4

from ix_blackfox.forge.code_analysis import CodeAnalysisSnapshot, PythonModuleAnalysis
from ix_blackfox.forge.file_graph import FileGraphSnapshot


class PatchOperationType(StrEnum):
    """
    High-level patch operation types understood by the forge.
    """

    CREATE = auto()
    UPDATE = auto()
    DELETE = auto()


class PatchPriority(StrEnum):
    """
    Relative urgency for patch operations.
    """

    CRITICAL = auto()
    HIGH = auto()
    NORMAL = auto()
    LOW = auto()


@dataclass(frozen=True, slots=True)
class PatchOperation:
    """
    One planned patch operation.

    Attributes
    ----------
    operation_type:
        Type of patch action to perform.
    relative_path:
        Workspace-relative target path.
    priority:
        Relative urgency for the operation.
    summary:
        Short human-readable action summary.
    rationale:
        Why this operation is being proposed.
    """

    operation_type: PatchOperationType
    relative_path: str
    priority: PatchPriority
    summary: str
    rationale: str

    def __post_init__(self) -> None:
        normalized_path = _normalize_relative_path(self.relative_path)
        normalized_summary = _normalize_text(self.summary, label="summary")
        normalized_rationale = _normalize_text(self.rationale, label="rationale")

        object.__setattr__(self, "relative_path", normalized_path)
        object.__setattr__(self, "summary", normalized_summary)
        object.__setattr__(self, "rationale", normalized_rationale)


@dataclass(frozen=True, slots=True)
class PatchPlan:
    """
    Immutable forge patch plan.
    """

    plan_id: str
    summary: str
    created_at: datetime
    operations: tuple[PatchOperation, ...] = field(default_factory=tuple)

    def operation_count(self) -> int:
        """
        Return the total number of patch operations.
        """
        return len(self.operations)

    def filter_by_priority(
        self,
        priority: PatchPriority,
    ) -> tuple[PatchOperation, ...]:
        """
        Return operations matching one priority.
        """
        return tuple(
            operation for operation in self.operations if operation.priority == priority
        )

    def filter_by_path(self, relative_path: str) -> tuple[PatchOperation, ...]:
        """
        Return operations targeting one relative path.
        """
        normalized_path = _normalize_relative_path(relative_path)
        return tuple(
            operation
            for operation in self.operations
            if operation.relative_path == normalized_path
        )


class ForgePatchPlanner:
    """
    Deterministic patch-planning engine for BlackFox forge flows.

    This planner does not modify files. It produces a structured plan
    from code-analysis output and repository inventory so later forge
    layers can execute patches in a controlled way.
    """

    def build_plan(
        self,
        *,
        summary: str,
        operations: tuple[PatchOperation, ...],
    ) -> PatchPlan:
        """
        Build a normalized patch plan from explicit operations.
        """
        normalized_summary = _normalize_text(summary, label="plan summary")
        deduplicated = _deduplicate_operations(operations)

        return PatchPlan(
            plan_id=f"plan-{uuid4().hex}",
            summary=normalized_summary,
            created_at=_utc_now(),
            operations=deduplicated,
        )

    def suggest_from_analysis(
        self,
        *,
        analysis: CodeAnalysisSnapshot,
        graph: FileGraphSnapshot,
    ) -> PatchPlan:
        """
        Generate a first-pass patch plan from analysis and file inventory.

        Current rules:
        - syntax errors produce critical update operations
        - missing module docstrings produce low-priority update operations
        - valid non-test Python modules without matching tests produce
          normal-priority create-test operations
        """
        operations: list[PatchOperation] = []
        existing_paths = {node.relative_path for node in graph.files}

        for module in analysis.python_modules:
            if module.syntax_error is not None:
                operations.append(
                    PatchOperation(
                        operation_type=PatchOperationType.UPDATE,
                        relative_path=module.relative_path,
                        priority=PatchPriority.CRITICAL,
                        summary="Repair Python syntax error.",
                        rationale=module.syntax_error,
                    )
                )
                continue

            if module.docstring is None and not _is_test_module(module.relative_path):
                operations.append(
                    PatchOperation(
                        operation_type=PatchOperationType.UPDATE,
                        relative_path=module.relative_path,
                        priority=PatchPriority.LOW,
                        summary="Add module docstring.",
                        rationale=(
                            "Module parsed successfully but does not define a "
                            "top-level docstring."
                        ),
                    )
                )

            if _requires_test_stub(module):
                suggested_test_path = _suggest_test_path(module.relative_path)
                if suggested_test_path not in existing_paths:
                    operations.append(
                        PatchOperation(
                            operation_type=PatchOperationType.CREATE,
                            relative_path=suggested_test_path,
                            priority=PatchPriority.NORMAL,
                            summary="Create matching test module.",
                            rationale=(
                                "Valid Python module does not have a matching "
                                "test stub in the scanned workspace."
                            ),
                        )
                    )

        return self.build_plan(
            summary="Initial forge patch plan generated from static analysis.",
            operations=tuple(operations),
        )


def _requires_test_stub(module: PythonModuleAnalysis) -> bool:
    if _is_test_module(module.relative_path):
        return False
    filename = Path(module.relative_path).name
    if filename == "__init__.py":
        return False
    return module.is_valid_python


def _is_test_module(relative_path: str) -> bool:
    path = Path(relative_path)
    return "tests" in path.parts or path.name.startswith("test_")


def _suggest_test_path(relative_path: str) -> str:
    path = Path(relative_path)
    parts = list(path.parts)

    if parts and parts[0] == "input":
        parts = parts[1:]
    if parts and parts[0] in {"src", "lib"}:
        parts = parts[1:]

    if not parts:
        return "input/tests/test_module.py"

    filename = parts[-1]
    stem = Path(filename).stem
    parent_parts = parts[:-1]

    suggested = Path("input") / "tests"
    for part in parent_parts:
        suggested /= part
    suggested /= f"test_{stem}.py"

    return suggested.as_posix()


def _deduplicate_operations(
    operations: tuple[PatchOperation, ...],
) -> tuple[PatchOperation, ...]:
    seen: set[tuple[PatchOperationType, str, PatchPriority, str, str]] = set()
    deduplicated: list[PatchOperation] = []

    for operation in operations:
        key = (
            operation.operation_type,
            operation.relative_path,
            operation.priority,
            operation.summary,
            operation.rationale,
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(operation)

    return tuple(deduplicated)


def _normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("Forge patch relative path must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"Forge patch {label} must not be empty.")
    return cleaned


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
