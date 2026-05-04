from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any, Self
from uuid import uuid4

from ix_blackfox.authoring.errors import AuthoringParseError
from ix_blackfox.authoring.models import (
    AuthoringFinding,
    AuthoringFindingSeverity,
)


class PatchMutationType(StrEnum):
    """
    Supported Wave 3 proposal mutation types.

    Wave 3 proposals are intentionally constrained. The model may propose
    creating a new file or replacing existing text, but it does not get to
    execute commands, apply arbitrary diffs, delete files, or mutate policy
    outside the compiler and Wave 2 control plane.
    """

    REPLACE_TEXT = auto()
    CREATE_FILE = auto()


class ProposalParseStatus(StrEnum):
    """
    Result status for parsing untrusted model/manual proposal text.
    """

    PARSED = auto()
    REJECTED = auto()


@dataclass(frozen=True, slots=True)
class PatchAuthoringMutation:
    """
    One parsed file mutation from a Wave 3 authored proposal.

    The mutation is still untrusted. The patch compiler must verify paths,
    current file text, and policy before it can become a PatchDiff.
    """

    mutation_id: str
    mutation_type: PatchMutationType
    path: str
    before_text: str
    after_text: str
    rationale: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "mutation_id",
            _normalize_identifier(self.mutation_id, label="mutation_id"),
        )
        object.__setattr__(self, "path", _normalize_relative_path(self.path))
        object.__setattr__(
            self,
            "rationale",
            _normalize_text(self.rationale, label="rationale"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.mutation_type is PatchMutationType.REPLACE_TEXT:
            if not self.before_text:
                raise ValueError("replace_text mutations require non-empty before_text.")
            if self.before_text == self.after_text:
                raise ValueError("replace_text mutations must change text.")

        if self.mutation_type is PatchMutationType.CREATE_FILE and self.before_text:
            raise ValueError("create_file mutations must use empty before_text.")

    @classmethod
    def create_replace_text(
        cls,
        *,
        path: str,
        before_text: str,
        after_text: str,
        rationale: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            mutation_id=f"patch-mutation-{uuid4().hex}",
            mutation_type=PatchMutationType.REPLACE_TEXT,
            path=path,
            before_text=before_text,
            after_text=after_text,
            rationale=rationale,
            metadata=dict(metadata or {}),
        )

    @classmethod
    def create_file(
        cls,
        *,
        path: str,
        after_text: str,
        rationale: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            mutation_id=f"patch-mutation-{uuid4().hex}",
            mutation_type=PatchMutationType.CREATE_FILE,
            path=path,
            before_text="",
            after_text=after_text,
            rationale=rationale,
            metadata=dict(metadata or {}),
        )

    @property
    def size_delta(self) -> int:
        return len(self.after_text.encode("utf-8")) - len(
            self.before_text.encode("utf-8")
        )

    @property
    def digest(self) -> str:
        return _digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload = {
            "mutation_id": self.mutation_id,
            "mutation_type": self.mutation_type.value,
            "path": self.path,
            "before_text": self.before_text,
            "after_text": self.after_text,
            "before_sha256": _sha256_text(self.before_text),
            "after_sha256": _sha256_text(self.after_text),
            "size_delta": self.size_delta,
            "rationale": self.rationale,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        mutation_type = PatchMutationType(_require_text(payload, "mutation_type"))
        mutation_id = str(payload.get("mutation_id") or f"patch-mutation-{uuid4().hex}")

        return cls(
            mutation_id=mutation_id,
            mutation_type=mutation_type,
            path=_require_text(payload, "path"),
            before_text=str(payload.get("before_text", "")),
            after_text=_require_text(payload, "after_text"),
            rationale=str(payload.get("rationale", "Wave 3 authored mutation.")),
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )


@dataclass(frozen=True, slots=True)
class PatchAuthoringProposal:
    """
    Parsed Wave 3 patch-authoring proposal.

    This is a data contract, not authority. The proposal must pass policy,
    compile into PatchDiff, be ranked, then flow through Wave 2 execution and
    Wave 3 acceptance before anything can be treated as successful.
    """

    proposal_id: str
    objective_summary: str
    reasoning_summary: str
    mutations: tuple[PatchAuthoringMutation, ...]
    expected_tests: tuple[str, ...] = field(default_factory=tuple)
    confidence: float = 0.0
    assumptions: tuple[str, ...] = field(default_factory=tuple)
    risk_notes: tuple[str, ...] = field(default_factory=tuple)
    raw_response: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "proposal_id",
            _normalize_identifier(self.proposal_id, label="proposal_id"),
        )
        object.__setattr__(
            self,
            "objective_summary",
            _normalize_text(self.objective_summary, label="objective_summary"),
        )
        object.__setattr__(
            self,
            "reasoning_summary",
            _normalize_text(self.reasoning_summary, label="reasoning_summary"),
        )
        mutations = tuple(self.mutations)
        if not mutations:
            raise ValueError("PatchAuthoringProposal requires at least one mutation.")
        object.__setattr__(self, "mutations", mutations)

        object.__setattr__(
            self,
            "expected_tests",
            tuple(
                _normalize_text(value, label="expected_test")
                for value in self.expected_tests
            ),
        )
        if self.confidence < 0.0 or self.confidence > 1.0:
            raise ValueError("proposal confidence must be between 0.0 and 1.0.")
        object.__setattr__(
            self,
            "assumptions",
            tuple(
                _normalize_text(value, label="assumption") for value in self.assumptions
            ),
        )
        object.__setattr__(
            self,
            "risk_notes",
            tuple(_normalize_text(value, label="risk_note") for value in self.risk_notes),
        )
        object.__setattr__(
            self,
            "raw_response",
            None if self.raw_response is None else str(self.raw_response),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @classmethod
    def create(
        cls,
        *,
        objective_summary: str,
        reasoning_summary: str,
        mutations: Iterable[PatchAuthoringMutation],
        expected_tests: Iterable[str] = (),
        confidence: float = 0.0,
        assumptions: Iterable[str] = (),
        risk_notes: Iterable[str] = (),
        raw_response: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            proposal_id=f"patch-proposal-{uuid4().hex}",
            objective_summary=objective_summary,
            reasoning_summary=reasoning_summary,
            mutations=tuple(mutations),
            expected_tests=tuple(expected_tests),
            confidence=confidence,
            assumptions=tuple(assumptions),
            risk_notes=tuple(risk_notes),
            raw_response=raw_response,
            metadata=dict(metadata or {}),
        )

    @property
    def affected_paths(self) -> tuple[str, ...]:
        paths: list[str] = []
        seen: set[str] = set()
        for mutation in self.mutations:
            if mutation.path in seen:
                continue
            seen.add(mutation.path)
            paths.append(mutation.path)
        return tuple(paths)

    @property
    def total_size_delta(self) -> int:
        return sum(mutation.size_delta for mutation in self.mutations)

    @property
    def raw_digest(self) -> str | None:
        if self.raw_response is None:
            return None
        return _sha256_text(self.raw_response)

    @property
    def digest(self) -> str:
        return _digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload = {
            "proposal_id": self.proposal_id,
            "objective_summary": self.objective_summary,
            "reasoning_summary": self.reasoning_summary,
            "affected_paths": list(self.affected_paths),
            "mutation_count": len(self.mutations),
            "total_size_delta": self.total_size_delta,
            "mutations": [
                mutation.to_dict(include_digest=include_digest)
                for mutation in self.mutations
            ],
            "expected_tests": list(self.expected_tests),
            "confidence": self.confidence,
            "assumptions": list(self.assumptions),
            "risk_notes": list(self.risk_notes),
            "raw_digest": self.raw_digest,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload

    @classmethod
    def from_dict(
        cls,
        payload: Mapping[str, Any],
        *,
        raw_response: str | None = None,
    ) -> Self:
        raw_mutations = payload.get("mutations", ())
        if isinstance(raw_mutations, str) or not isinstance(raw_mutations, Iterable):
            raise TypeError("mutations must be an iterable of mappings.")

        mutations: list[PatchAuthoringMutation] = []
        for raw_mutation in raw_mutations:
            if not isinstance(raw_mutation, Mapping):
                raise TypeError("mutations must contain only mappings.")
            mutations.append(PatchAuthoringMutation.from_dict(raw_mutation))

        proposal_id = str(payload.get("proposal_id") or f"patch-proposal-{uuid4().hex}")

        return cls(
            proposal_id=proposal_id,
            objective_summary=_require_text(payload, "objective_summary"),
            reasoning_summary=str(
                payload.get("reasoning_summary", "No reasoning summary supplied.")
            ),
            mutations=tuple(mutations),
            expected_tests=_coerce_text_tuple(
                payload.get("expected_tests", ()), field_name="expected_tests"
            ),
            confidence=_coerce_confidence(payload.get("confidence", 0.0)),
            assumptions=_coerce_text_tuple(
                payload.get("assumptions", ()), field_name="assumptions"
            ),
            risk_notes=_coerce_text_tuple(
                payload.get("risk_notes", ()), field_name="risk_notes"
            ),
            raw_response=raw_response,
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )


@dataclass(frozen=True, slots=True)
class ProposalParseReport:
    """
    Result of parsing untrusted Wave 3 proposal text.
    """

    report_id: str
    status: ProposalParseStatus
    proposal: PatchAuthoringProposal | None = None
    findings: tuple[AuthoringFinding, ...] = field(default_factory=tuple)
    raw_digest: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "report_id",
            _normalize_identifier(self.report_id, label="report_id"),
        )
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "raw_digest", _normalize_optional_sha256(self.raw_digest))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.status is ProposalParseStatus.PARSED and self.proposal is None:
            raise ValueError("parsed proposal reports require a proposal.")
        if self.status is ProposalParseStatus.REJECTED and self.proposal is not None:
            raise ValueError("rejected proposal reports must not include a proposal.")

    @property
    def parsed(self) -> bool:
        return self.status is ProposalParseStatus.PARSED

    @property
    def rejected(self) -> bool:
        return self.status is ProposalParseStatus.REJECTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "status": self.status.value,
            "parsed": self.parsed,
            "rejected": self.rejected,
            "proposal": None if self.proposal is None else self.proposal.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "raw_digest": self.raw_digest,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class PatchAuthoringResponseParserConfig:
    """
    Limits and extraction settings for proposal parsing.
    """

    max_response_chars: int = 200_000
    require_json_object: bool = True
    allow_markdown_fenced_json: bool = True

    def __post_init__(self) -> None:
        if self.max_response_chars <= 0:
            raise ValueError("max_response_chars must be positive.")


@dataclass(frozen=True, slots=True)
class PatchAuthoringResponseParser:
    """
    Parse untrusted Wave 3 patch proposal output into a strict data contract.

    The accepted JSON shape is:

    {
      "objective_summary": "...",
      "reasoning_summary": "...",
      "confidence": 0.75,
      "expected_tests": ["python -m pytest -q"],
      "assumptions": ["..."],
      "risk_notes": ["..."],
      "mutations": [
        {
          "mutation_type": "replace_text",
          "path": "src/example.py",
          "before_text": "...",
          "after_text": "...",
          "rationale": "..."
        }
      ]
    }
    """

    config: PatchAuthoringResponseParserConfig = field(
        default_factory=PatchAuthoringResponseParserConfig
    )

    def parse(self, raw_response: str) -> ProposalParseReport:
        raw_text = _normalize_text(raw_response, label="raw_response")
        raw_digest = _sha256_text(raw_text)

        if len(raw_text) > self.config.max_response_chars:
            finding = AuthoringFinding(
                code="authoring.response_parser.response_too_large",
                severity=AuthoringFindingSeverity.ERROR,
                summary="Patch authoring response exceeded parser size limit.",
                metadata={
                    "response_chars": len(raw_text),
                    "max_response_chars": self.config.max_response_chars,
                },
            )
            return ProposalParseReport(
                report_id=f"proposal-parse-report-{uuid4().hex}",
                status=ProposalParseStatus.REJECTED,
                findings=(finding,),
                raw_digest=raw_digest,
            )

        try:
            payload = self._load_payload(raw_text)
            proposal = PatchAuthoringProposal.from_dict(
                payload,
                raw_response=raw_text,
            )
        except Exception as exc:
            finding = AuthoringFinding(
                code="authoring.response_parser.parse_failed",
                severity=AuthoringFindingSeverity.ERROR,
                summary=f"Patch authoring response could not be parsed: {exc}",
                metadata={
                    "error_type": type(exc).__name__,
                    "raw_digest": raw_digest,
                },
            )
            return ProposalParseReport(
                report_id=f"proposal-parse-report-{uuid4().hex}",
                status=ProposalParseStatus.REJECTED,
                findings=(finding,),
                raw_digest=raw_digest,
            )

        findings = self._validate_proposal_shape(proposal)

        if any(
            finding.severity is AuthoringFindingSeverity.ERROR
            for finding in findings
        ):
            return ProposalParseReport(
                report_id=f"proposal-parse-report-{uuid4().hex}",
                status=ProposalParseStatus.REJECTED,
                findings=findings,
                raw_digest=raw_digest,
                metadata={"proposal_id": proposal.proposal_id},
            )

        return ProposalParseReport(
            report_id=f"proposal-parse-report-{uuid4().hex}",
            status=ProposalParseStatus.PARSED,
            proposal=proposal,
            findings=findings,
            raw_digest=raw_digest,
            metadata={
                "proposal_id": proposal.proposal_id,
                "mutation_count": len(proposal.mutations),
                "affected_paths": list(proposal.affected_paths),
            },
        )

    def parse_or_raise(self, raw_response: str) -> PatchAuthoringProposal:
        report = self.parse(raw_response)
        if report.proposal is None:
            joined = "; ".join(finding.summary for finding in report.findings)
            raise AuthoringParseError(joined or "Patch authoring response rejected.")
        return report.proposal

    def _load_payload(self, raw_text: str) -> Mapping[str, Any]:
        candidate_text = raw_text
        if self.config.allow_markdown_fenced_json:
            candidate_text = _extract_json_candidate(raw_text)

        loaded = json.loads(candidate_text)
        if not isinstance(loaded, Mapping):
            raise TypeError("proposal response must decode to a JSON object.")

        return loaded

    def _validate_proposal_shape(
        self,
        proposal: PatchAuthoringProposal,
    ) -> tuple[AuthoringFinding, ...]:
        findings: list[AuthoringFinding] = []

        if not proposal.expected_tests:
            findings.append(
                AuthoringFinding(
                    code="authoring.response_parser.expected_tests_missing",
                    severity=AuthoringFindingSeverity.WARNING,
                    summary="Proposal does not include expected tests.",
                    metadata={"proposal_id": proposal.proposal_id},
                )
            )

        if proposal.confidence <= 0.0:
            findings.append(
                AuthoringFinding(
                    code="authoring.response_parser.confidence_zero",
                    severity=AuthoringFindingSeverity.WARNING,
                    summary="Proposal confidence is zero.",
                    metadata={"proposal_id": proposal.proposal_id},
                )
            )

        duplicate_paths = _duplicates(proposal.affected_paths)
        if duplicate_paths:
            findings.append(
                AuthoringFinding(
                    code="authoring.response_parser.duplicate_paths",
                    severity=AuthoringFindingSeverity.ERROR,
                    summary="Proposal contains duplicate affected paths.",
                    metadata={
                        "proposal_id": proposal.proposal_id,
                        "duplicate_paths": list(duplicate_paths),
                    },
                )
            )

        for mutation in proposal.mutations:
            if _looks_like_absolute_or_drive_path(mutation.path):
                findings.append(
                    AuthoringFinding(
                        code="authoring.response_parser.absolute_path",
                        severity=AuthoringFindingSeverity.ERROR,
                        summary="Proposal mutation path is absolute or drive-qualified.",
                        path=mutation.path,
                        metadata={
                            "proposal_id": proposal.proposal_id,
                            "mutation_id": mutation.mutation_id,
                        },
                    )
                )

            if ".." in mutation.path.split("/"):
                findings.append(
                    AuthoringFinding(
                        code="authoring.response_parser.path_traversal",
                        severity=AuthoringFindingSeverity.ERROR,
                        summary="Proposal mutation path contains traversal.",
                        path=mutation.path,
                        metadata={
                            "proposal_id": proposal.proposal_id,
                            "mutation_id": mutation.mutation_id,
                        },
                    )
                )

        if not findings:
            findings.append(
                AuthoringFinding(
                    code="authoring.response_parser.parsed",
                    severity=AuthoringFindingSeverity.INFO,
                    summary="Patch authoring proposal parsed into a strict Wave 3 contract.",
                    metadata={"proposal_id": proposal.proposal_id},
                )
            )

        return tuple(findings)


def _extract_json_candidate(raw_text: str) -> str:
    fenced_match = re.search(
        r"```(?:json)?\s*(?P<body>\{.*?\})\s*```",
        raw_text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if fenced_match:
        return fenced_match.group("body").strip()

    stripped = raw_text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped

    first_brace = stripped.find("{")
    last_brace = stripped.rfind("}")
    if first_brace >= 0 and last_brace > first_brace:
        return stripped[first_brace : last_brace + 1]

    return stripped


def _duplicates(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    duplicates: list[str] = []

    for value in values:
        if value in seen and value not in duplicates:
            duplicates.append(value)
        seen.add(value)

    return tuple(duplicates)


def _looks_like_absolute_or_drive_path(path: str) -> bool:
    cleaned = path.strip().replace("\\", "/")
    return cleaned.startswith(("/", "~")) or bool(re.match(r"^[a-zA-Z]:", cleaned))


def _digest_payload(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("relative path must not be empty.")
    if cleaned.startswith(("/", "~")) or ":" in cleaned.split("/")[0]:
        raise ValueError(f"path must be relative: {value!r}")

    parts: list[str] = []
    for raw_part in cleaned.split("/"):
        part = raw_part.strip()
        if part in {"", "."}:
            continue
        if part == "..":
            raise ValueError(f"path traversal is not allowed: {value!r}")
        parts.append(part)

    if not parts:
        raise ValueError("relative path must not resolve to workspace root.")

    return "/".join(parts)


def _normalize_sha256(value: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) != 64 or any(char not in "0123456789abcdef" for char in cleaned):
        raise ValueError("sha256 must be a 64-character lowercase hexadecimal digest.")
    return cleaned


def _normalize_optional_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_sha256(value)


def _coerce_confidence(value: Any) -> float:
    if isinstance(value, bool):
        raise TypeError("confidence must be numeric, not boolean.")
    if not isinstance(value, int | float):
        raise TypeError("confidence must be numeric.")
    confidence = float(value)
    if confidence < 0.0 or confidence > 1.0:
        raise ValueError("confidence must be between 0.0 and 1.0.")
    return confidence


def _coerce_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")
    return dict(value)


def _coerce_text_tuple(value: Any, *, field_name: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError(f"{field_name} must be an iterable of strings.")

    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"{field_name} must contain only strings.")
        result.append(item)

    return tuple(result)


def _require_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string.")
    return value
