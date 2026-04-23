from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ix_blackfox.sentinel.core import (
    SentinelCheck,
    SentinelContext,
    SentinelIssue,
    SentinelSeverity,
)


@dataclass(frozen=True, slots=True)
class ContradictionAssertion:
    """
    One normalized assertion used for contradiction analysis.

    Attributes
    ----------
    subject:
        Logical subject of the assertion.
    predicate:
        Logical predicate applied to the subject.
    value:
        Asserted value for the subject and predicate.
    source:
        Optional source label for diagnostics.
    """

    subject: str
    predicate: str
    value: Any
    source: str | None = None

    def __post_init__(self) -> None:
        normalized_subject = _normalize_identifier(self.subject, label="subject")
        normalized_predicate = _normalize_identifier(self.predicate, label="predicate")
        normalized_source = _normalize_optional_text(self.source)

        object.__setattr__(self, "subject", normalized_subject)
        object.__setattr__(self, "predicate", normalized_predicate)
        object.__setattr__(self, "source", normalized_source)

    @classmethod
    def from_mapping(
        cls,
        raw: Mapping[str, Any],
    ) -> ContradictionAssertion:
        """
        Build an assertion from a mapping with subject, predicate, and value.
        """
        try:
            subject = str(raw["subject"])
            predicate = str(raw["predicate"])
            value = raw["value"]
        except KeyError as exc:
            raise ValueError(
                f"Contradiction assertion is missing required field {exc!s}."
            ) from exc

        source_raw = raw.get("source")
        source = None if source_raw is None else str(source_raw)

        return cls(
            subject=subject,
            predicate=predicate,
            value=value,
            source=source,
        )

    def normalized_value(self) -> str:
        """
        Return a canonical representation of the asserted value.
        """
        return _normalize_value(self.value)


class ContradictionCheck(SentinelCheck):
    """
    Built-in check that detects incompatible assertions.

    Expected context metadata format:
    {
        "assertions": [
            {"subject": "...", "predicate": "...", "value": "...", "source": "..."},
            ...
        ]
    }

    Assertions sharing the same (subject, predicate) pair but holding
    different normalized values are treated as contradictions.
    """

    def __init__(
        self,
        *,
        critical_predicates: tuple[str, ...] = (),
    ) -> None:
        self._critical_predicates = tuple(
            _normalize_identifier(predicate, label="critical predicate")
            for predicate in critical_predicates
        )

    @property
    def check_name(self) -> str:
        return "contradiction"

    def evaluate(self, context: SentinelContext) -> tuple[SentinelIssue, ...]:
        """
        Evaluate context assertions and emit contradiction issues.
        """
        raw_assertions = context.metadata.get("assertions", ())
        issues: list[SentinelIssue] = []

        try:
            assertions = self._coerce_assertions(raw_assertions)
        except ValueError as exc:
            return (
                SentinelIssue(
                    code="reasoning.invalid_assertion",
                    severity=SentinelSeverity.ERROR,
                    summary="Invalid contradiction-check assertion payload.",
                    source=self.check_name,
                    details=str(exc),
                ),
            )

        grouped: dict[tuple[str, str], list[ContradictionAssertion]] = defaultdict(list)
        for assertion in assertions:
            grouped[(assertion.subject, assertion.predicate)].append(assertion)

        for (subject, predicate), group in grouped.items():
            by_value: dict[str, list[ContradictionAssertion]] = defaultdict(list)
            for assertion in group:
                by_value[assertion.normalized_value()].append(assertion)

            if len(by_value) <= 1:
                continue

            severity = (
                SentinelSeverity.ERROR
                if predicate in self._critical_predicates
                else SentinelSeverity.WARNING
            )

            normalized_values = tuple(sorted(by_value))
            sources = tuple(
                sorted(
                    {
                        assertion.source
                        for assertion_group in by_value.values()
                        for assertion in assertion_group
                        if assertion.source is not None
                    }
                )
            )

            issues.append(
                SentinelIssue(
                    code="reasoning.contradiction_detected",
                    severity=severity,
                    summary=(
                        f"Contradictory assertions detected for "
                        f"{subject}.{predicate}."
                    ),
                    source=self.check_name,
                    details=_build_details(
                        subject=subject,
                        predicate=predicate,
                        values=normalized_values,
                        sources=sources,
                    ),
                    data={
                        "subject": subject,
                        "predicate": predicate,
                        "values": normalized_values,
                        "sources": sources,
                        "assertion_count": len(group),
                    },
                )
            )

        return tuple(issues)

    def _coerce_assertions(
        self,
        raw_assertions: Any,
    ) -> tuple[ContradictionAssertion, ...]:
        if not isinstance(raw_assertions, Sequence) or isinstance(
            raw_assertions,
            str | bytes | bytearray,
        ):
            raise ValueError("Assertions must be a sequence of mappings or assertions.")

        normalized: list[ContradictionAssertion] = []
        for raw in raw_assertions:
            if isinstance(raw, ContradictionAssertion):
                normalized.append(raw)
            elif isinstance(raw, Mapping):
                normalized.append(ContradictionAssertion.from_mapping(raw))
            else:
                raise ValueError(
                    "Each assertion must be a mapping or ContradictionAssertion."
                )

        return tuple(normalized)


def _build_details(
    *,
    subject: str,
    predicate: str,
    values: tuple[str, ...],
    sources: tuple[str, ...],
) -> str:
    values_text = ", ".join(values)
    if not sources:
        return f"Conflicting values for {subject}.{predicate}: {values_text}."

    sources_text = ", ".join(sources)
    return (
        f"Conflicting values for {subject}.{predicate}: {values_text}. "
        f"Sources: {sources_text}."
    )


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError(f"Contradiction assertion {label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _normalize_value(value: Any) -> str:
    if isinstance(value, str):
        cleaned = value.strip().lower()
        if not cleaned:
            return '""'
        return cleaned

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
