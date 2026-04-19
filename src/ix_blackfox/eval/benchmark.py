from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class BenchmarkCase:
    """
    One benchmark case definition.

    Attributes
    ----------
    case_id:
        Stable benchmark case identifier.
    title:
        Short human-readable case title.
    prompt:
        Primary task instruction or benchmark prompt.
    expected_artifacts:
        Optional logical artifact names expected from the run.
    minimum_score:
        Minimum acceptable evaluation score from 0.0 to 1.0.
    tags:
        Optional normalized tags for grouping or filtering.
    metadata:
        Optional structured benchmark metadata.
    """

    case_id: str
    title: str
    prompt: str
    expected_artifacts: tuple[str, ...] = field(default_factory=tuple)
    minimum_score: float = 1.0
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized_case_id = _normalize_identifier(self.case_id, label="case id")
        normalized_title = _normalize_text(self.title, label="case title")
        normalized_prompt = _normalize_text(self.prompt, label="case prompt")
        normalized_expected_artifacts = _normalize_strings(
            self.expected_artifacts,
            label="expected artifact",
        )
        normalized_tags = _normalize_identifiers(self.tags, label="tag")
        normalized_minimum_score = _normalize_score(self.minimum_score)

        object.__setattr__(self, "case_id", normalized_case_id)
        object.__setattr__(self, "title", normalized_title)
        object.__setattr__(self, "prompt", normalized_prompt)
        object.__setattr__(self, "expected_artifacts", normalized_expected_artifacts)
        object.__setattr__(self, "tags", normalized_tags)
        object.__setattr__(self, "minimum_score", normalized_minimum_score)

    @classmethod
    def create(
        cls,
        *,
        title: str,
        prompt: str,
        expected_artifacts: tuple[str, ...] = (),
        minimum_score: float = 1.0,
        tags: tuple[str, ...] = (),
        metadata: dict[str, object] | None = None,
    ) -> BenchmarkCase:
        """
        Construct a benchmark case with an auto-generated identifier.
        """
        return cls(
            case_id=f"bench-{uuid4().hex}",
            title=title,
            prompt=prompt,
            expected_artifacts=expected_artifacts,
            minimum_score=minimum_score,
            tags=tags,
            metadata=dict(metadata or {}),
        )


@dataclass(frozen=True, slots=True)
class BenchmarkSuite:
    """
    One named collection of benchmark cases.
    """

    suite_name: str
    version: str
    cases: tuple[BenchmarkCase, ...] = field(default_factory=tuple)
    description: str = ""

    def __post_init__(self) -> None:
        normalized_name = _normalize_identifier(self.suite_name, label="suite name")
        normalized_version = _normalize_text(self.version, label="suite version")
        normalized_description = self.description.strip()

        case_ids = tuple(case.case_id for case in self.cases)
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("Benchmark suite case ids must be unique.")

        object.__setattr__(self, "suite_name", normalized_name)
        object.__setattr__(self, "version", normalized_version)
        object.__setattr__(self, "description", normalized_description)

    def case_count(self) -> int:
        """
        Return the total number of cases in the suite.
        """
        return len(self.cases)

    def get_case(self, case_id: str) -> BenchmarkCase | None:
        """
        Retrieve one case by identifier.
        """
        normalized_case_id = _normalize_identifier(case_id, label="case id")
        for case in self.cases:
            if case.case_id == normalized_case_id:
                return case
        return None

    def filter_by_tag(self, tag: str) -> tuple[BenchmarkCase, ...]:
        """
        Return all cases containing one tag.
        """
        normalized_tag = _normalize_identifier(tag, label="tag")
        return tuple(case for case in self.cases if normalized_tag in case.tags)


@dataclass(frozen=True, slots=True)
class BenchmarkSuiteSnapshot:
    """
    Immutable view of registered benchmark suites.
    """

    suites: tuple[BenchmarkSuite, ...]

    def names(self) -> tuple[str, ...]:
        """
        Return registered suite names in insertion order.
        """
        return tuple(suite.suite_name for suite in self.suites)

    def get(self, suite_name: str) -> BenchmarkSuite | None:
        """
        Retrieve a suite by name.
        """
        normalized_name = _normalize_identifier(suite_name, label="suite name")
        for suite in self.suites:
            if suite.suite_name == normalized_name:
                return suite
        return None


class BenchmarkSuiteRegistry:
    """
    Thread-safe registry for benchmark suites.
    """

    def __init__(self) -> None:
        self._suites: list[BenchmarkSuite] = []
        self._lock = RLock()

    def register(self, suite: BenchmarkSuite) -> None:
        """
        Register or replace a benchmark suite by name.
        """
        with self._lock:
            for index, existing in enumerate(self._suites):
                if existing.suite_name == suite.suite_name:
                    self._suites[index] = suite
                    return
            self._suites.append(suite)

    def unregister(self, suite_name: str) -> bool:
        """
        Remove a benchmark suite by name.
        """
        normalized_name = _normalize_identifier(suite_name, label="suite name")

        with self._lock:
            for index, suite in enumerate(self._suites):
                if suite.suite_name == normalized_name:
                    del self._suites[index]
                    return True
            return False

    def get(self, suite_name: str) -> BenchmarkSuite | None:
        """
        Retrieve a benchmark suite by name.
        """
        normalized_name = _normalize_identifier(suite_name, label="suite name")

        with self._lock:
            for suite in self._suites:
                if suite.suite_name == normalized_name:
                    return suite
            return None

    def snapshot(self) -> BenchmarkSuiteSnapshot:
        """
        Return an immutable registry snapshot.
        """
        with self._lock:
            return BenchmarkSuiteSnapshot(suites=tuple(self._suites))

    def clear(self) -> None:
        """
        Remove all registered benchmark suites.
        """
        with self._lock:
            self._suites.clear()


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError(f"Benchmark {label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"Benchmark {label} must not be empty.")
    return cleaned


def _normalize_strings(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = _normalize_text(value, label=label)
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _normalize_identifiers(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = _normalize_identifier(value, label=label)
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _normalize_score(value: float) -> float:
    normalized = float(value)
    if not 0.0 <= normalized <= 1.0:
        raise ValueError("Benchmark minimum score must be between 0.0 and 1.0.")
    return normalized
