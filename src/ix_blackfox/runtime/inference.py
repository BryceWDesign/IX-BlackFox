from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, auto

from ix_blackfox.kernel import TaskKind


class TaskInferenceReason(StrEnum):
    """
    Canonical reasons for a task-kind inference result.
    """

    EXPLICIT_SIGNAL = auto()
    KEYWORD_MATCH = auto()
    LABEL_MATCH = auto()
    NO_SIGNAL = auto()


@dataclass(frozen=True, slots=True)
class TaskInference:
    """
    One deterministic task-kind inference result.

    Attributes
    ----------
    kind:
        Inferred task kind.
    confidence:
        Normalized confidence score from 0.0 to 1.0.
    reason:
        Primary reason class for the inference.
    matched_terms:
        Prompt terms that contributed to the result.
    matched_labels:
        Task labels that contributed to the result.
    """

    kind: TaskKind
    confidence: float
    reason: TaskInferenceReason
    matched_terms: tuple[str, ...] = field(default_factory=tuple)
    matched_labels: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        normalized_confidence = float(self.confidence)
        if not 0.0 <= normalized_confidence <= 1.0:
            raise ValueError("Task inference confidence must be between 0.0 and 1.0.")

        object.__setattr__(self, "confidence", normalized_confidence)
        object.__setattr__(self, "matched_terms", _normalize_identifiers(self.matched_terms))
        object.__setattr__(self, "matched_labels", _normalize_identifiers(self.matched_labels))


class DeterministicTaskClassifier:
    """
    Deterministic prompt and label classifier for BlackFox task kinds.

    The goal is not to be clever. The goal is to make unknown task intake
    usable without introducing opaque routing behavior.
    """

    _TERM_MAP: dict[TaskKind, tuple[str, ...]] = {
        TaskKind.PROGRAMMING: (
            "bug",
            "build",
            "code",
            "debug",
            "fix",
            "function",
            "patch",
            "profile",
            "python",
            "refactor",
            "regression",
            "repo",
            "test",
            "tests",
        ),
        TaskKind.ARCHITECTURE: (
            "architecture",
            "boundary",
            "component",
            "design",
            "interface",
            "module",
            "orchestration",
            "runtime",
            "state model",
            "subsystem",
            "system design",
        ),
        TaskKind.ANALYSIS: (
            "analyze",
            "analysis",
            "audit",
            "explain",
            "inspect",
            "inspection",
            "review",
            "walk through",
        ),
        TaskKind.RESEARCH: (
            "compare",
            "investigate",
            "literature",
            "research",
            "survey",
            "study",
        ),
        TaskKind.EVALUATION: (
            "benchmark",
            "evaluate",
            "evaluation",
            "grade",
            "measure",
            "metric",
            "score",
            "validate",
            "verification",
            "verify",
        ),
        TaskKind.OPERATIONS: (
            "deploy",
            "incident",
            "monitor",
            "oncall",
            "operations",
            "release",
            "runbook",
            "service",
        ),
    }

    _LABEL_MAP: dict[TaskKind, tuple[str, ...]] = {
        TaskKind.PROGRAMMING: (
            "code",
            "patching",
            "profiling",
            "testing",
        ),
        TaskKind.ARCHITECTURE: (
            "architecture",
            "boundary",
            "design",
            "interfaces",
            "state",
        ),
        TaskKind.ANALYSIS: (
            "analysis",
            "audit",
            "inspection",
        ),
        TaskKind.RESEARCH: (
            "research",
            "survey",
        ),
        TaskKind.EVALUATION: (
            "benchmark",
            "evaluation",
            "verification",
        ),
        TaskKind.OPERATIONS: (
            "deploy",
            "ops",
            "operations",
            "runbook",
        ),
    }

    def infer(
        self,
        *,
        prompt: str,
        labels: tuple[str, ...] = (),
    ) -> TaskInference:
        """
        Infer a task kind from prompt text and optional labels.
        """
        normalized_prompt = prompt.strip().lower()
        normalized_labels = _normalize_identifiers(labels)

        if not normalized_prompt and not normalized_labels:
            return TaskInference(
                kind=TaskKind.UNKNOWN,
                confidence=0.0,
                reason=TaskInferenceReason.NO_SIGNAL,
            )

        best_kind = TaskKind.UNKNOWN
        best_score = 0.0
        best_terms: tuple[str, ...] = ()
        best_labels: tuple[str, ...] = ()
        best_reason = TaskInferenceReason.NO_SIGNAL

        for kind, terms in self._TERM_MAP.items():
            matched_terms = tuple(term for term in terms if term in normalized_prompt)
            label_terms = self._LABEL_MAP.get(kind, ())
            matched_labels = tuple(label for label in normalized_labels if label in label_terms)

            score = (len(matched_terms) * 0.18) + (len(matched_labels) * 0.27)
            score = min(score, 0.99)

            if score <= 0.0:
                continue

            if score > best_score:
                best_kind = kind
                best_score = score
                best_terms = matched_terms
                best_labels = matched_labels
                best_reason = (
                    TaskInferenceReason.LABEL_MATCH
                    if matched_labels and not matched_terms
                    else TaskInferenceReason.KEYWORD_MATCH
                )

        if best_kind == TaskKind.UNKNOWN:
            return TaskInference(
                kind=TaskKind.UNKNOWN,
                confidence=0.0,
                reason=TaskInferenceReason.NO_SIGNAL,
            )

        if len(best_terms) >= 2 or len(best_labels) >= 2:
            best_score = max(best_score, 0.6)

        return TaskInference(
            kind=best_kind,
            confidence=min(best_score, 1.0),
            reason=best_reason,
            matched_terms=best_terms,
            matched_labels=best_labels,
        )


def _normalize_identifiers(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = value.strip().lower()
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)
