from __future__ import annotations

from ix_blackfox.kernel import TaskKind
from ix_blackfox.runtime import DeterministicTaskClassifier


def test_classifier_infers_programming_from_prompt_and_labels() -> None:
    classifier = DeterministicTaskClassifier()

    inference = classifier.infer(
        prompt="Fix the failing tests and patch the Python repository.",
        labels=("code", "testing"),
    )

    assert inference.kind == TaskKind.PROGRAMMING
    assert inference.confidence >= 0.6
    assert "fix" in inference.matched_terms
    assert "code" in inference.matched_labels


def test_classifier_returns_unknown_without_signal() -> None:
    classifier = DeterministicTaskClassifier()

    inference = classifier.infer(prompt="   ")

    assert inference.kind == TaskKind.UNKNOWN
    assert inference.confidence == 0.0
