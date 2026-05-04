from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any, Self
from uuid import uuid4


class AuthoringMode(StrEnum):
    """
    Source mode used to create Wave 3 patch-authoring output.
    """

    DETERMINISTIC = auto()
    MODEL_ASSISTED = auto()
    IMPORTED_PROPOSAL = auto()
    REPLAYED = auto()


class AuthoringStatus(StrEnum):
    """
    Lifecycle status for a Wave 3 authoring request or run.
    """

    REQUESTED = auto()
    CONTEXT_READY = auto()
    EVIDENCE_READY = auto()
    DECOMPOSED = auto()
    AUTHORED = auto()
    REJECTED = auto()
    BLOCKED = auto()
    REQUIRES_REVIEW = auto()
    COMPILED = auto()
    SUBMITTED_TO_WAVE2 = auto()
    WAVE2_FAILED = auto()
    WAVE2_PASSED = auto()
    ACCEPTED = auto()
    FAILED_ACCEPTANCE = auto()


class AuthoringEvidenceStrength(StrEnum):
    """
    How directly evidence supports a repair objective.
    """

    MISSING = auto()
    WEAK = auto()
    DIRECT = auto()


class AuthoringFindingSeverity(StrEnum):
    """
    Severity for authoring findings emitted before Wave 2 execution.
    """

    INFO = auto()
    WARNING = auto()
    ERROR = auto()


class AuthoringRiskLevel(StrEnum):
    """
    Coarse Wave 3 risk level used before governance policy expansion.
    """

    LOW = auto()
    MODERATE = auto()
    HIGH = auto()
    CRITICAL = auto()


class AuthoringSubtaskKind(StrEnum):
    """
    Task-decomposition step category.
    """

    INSPECT = auto()
    MODIFY = auto()
    TEST = auto()
    REVIEW = auto()


@dataclass(frozen=True, slots=True)
class AuthoringFinding:
    """
    One structured finding produced by the Wave 3 authoring layer.
    """

    code: str
    severity: AuthoringFindingSeverity
    summary: str
    path: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _normalize_token(self.code, label="code"))
        object.__setattr__(
            self, "summary", _normalize_text(self.summary, label="summary")
        )
        object.__setattr__(self, "path", _normalize_optional_path(self.path))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "summary": self.summary,
            "path": self.path,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            code=_require_text(payload, "code"),
            severity=AuthoringFindingSeverity(_require_text(payload, "severity")),
            summary=_require_text(payload, "summary"),
            path=_optional_text_from_payload(payload, "path"),
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )


@dataclass(frozen=True, slots=True)
class AuthoringObjective:
    """
    Normalized repair objective supplied to the Wave 3 authoring layer.
    """

    objective_id: str
    task_id: str
    summary: str
    requested_by: str = "operator"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "objective_id",
            _normalize_identifier(self.objective_id, label="objective_id"),
        )
        object.__setattr__(
            self, "task_id", _normalize_identifier(self.task_id, label="task_id")
        )
        object.__setattr__(
            self, "summary", _normalize_text(self.summary, label="summary")
        )
        object.__setattr__(
            self,
            "requested_by",
            _normalize_token(self.requested_by, label="requested_by"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @classmethod
    def create(
        cls,
        *,
        task_id: str,
        summary: str,
        requested_by: str = "operator",
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            objective_id=f"objective-{uuid4().hex}",
            task_id=task_id,
            summary=summary,
            requested_by=requested_by,
            metadata=dict(metadata or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective_id": self.objective_id,
            "task_id": self.task_id,
            "summary": self.summary,
            "requested_by": self.requested_by,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            objective_id=_require_text(payload, "objective_id"),
            task_id=_require_text(payload, "task_id"),
            summary=_require_text(payload, "summary"),
            requested_by=str(payload.get("requested_by", "operator")),
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )


@dataclass(frozen=True, slots=True)
class AuthoringContextFile:
    """
    One file admitted into a bounded Wave 3 repository context snapshot.
    """

    path: str
    sha256: str
    size_bytes: int
    purpose: str = "repair_context"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _normalize_relative_path(self.path))
        object.__setattr__(self, "sha256", _normalize_sha256(self.sha256))
        if self.size_bytes < 0:
            raise ValueError("size_bytes must be zero or greater.")
        object.__setattr__(
            self, "purpose", _normalize_token(self.purpose, label="purpose")
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "purpose": self.purpose,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            path=_require_text(payload, "path"),
            sha256=_require_text(payload, "sha256"),
            size_bytes=_require_int(payload, "size_bytes"),
            purpose=str(payload.get("purpose", "repair_context")),
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )


@dataclass(frozen=True, slots=True)
class AuthoringContext:
    """
    Bounded repository context manifest for one Wave 3 authoring request.

    This skeleton stores file metadata and a manifest digest. Later commits add
    the context builder that decides which files are admitted.
    """

    context_id: str
    files: tuple[AuthoringContextFile, ...] = field(default_factory=tuple)
    total_bytes: int = 0
    digest: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "context_id",
            _normalize_identifier(self.context_id, label="context_id"),
        )
        files = tuple(self.files)
        object.__setattr__(self, "files", files)
        if self.total_bytes < 0:
            raise ValueError("total_bytes must be zero or greater.")
        computed_total = sum(context_file.size_bytes for context_file in files)
        if files and self.total_bytes != computed_total:
            raise ValueError("total_bytes must equal the sum of context file sizes.")
        digest = self.digest or _digest_payload(
            [context_file.to_dict() for context_file in files]
        )
        object.__setattr__(self, "digest", _normalize_sha256(digest))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @classmethod
    def create(
        cls,
        *,
        files: Iterable[AuthoringContextFile] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        file_tuple = tuple(files)
        return cls(
            context_id=f"context-{uuid4().hex}",
            files=file_tuple,
            total_bytes=sum(context_file.size_bytes for context_file in file_tuple),
            metadata=dict(metadata or {}),
        )

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(context_file.path for context_file in self.files)

    def to_dict(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "file_count": len(self.files),
            "total_bytes": self.total_bytes,
            "digest": self.digest,
            "paths": list(self.paths),
            "files": [context_file.to_dict() for context_file in self.files],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_files = payload.get("files", ())
        if not isinstance(raw_files, Iterable) or isinstance(raw_files, str):
            raise TypeError("files must be an iterable of mappings.")
        files: list[AuthoringContextFile] = []
        for raw_file in raw_files:
            if not isinstance(raw_file, Mapping):
                raise TypeError("files must contain only mappings.")
            files.append(AuthoringContextFile.from_dict(raw_file))
        return cls(
            context_id=_require_text(payload, "context_id"),
            files=tuple(files),
            total_bytes=_require_int(payload, "total_bytes"),
            digest=_optional_text_from_payload(payload, "digest"),
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )


@dataclass(frozen=True, slots=True)
class AuthoringEvidence:
    """
    Evidence supplied to the Wave 3 authoring layer before patch generation.
    """

    evidence_id: str
    summary: str
    strength: AuthoringEvidenceStrength = AuthoringEvidenceStrength.WEAK
    source: str = "operator"
    path: str | None = None
    line: int | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "evidence_id",
            _normalize_identifier(self.evidence_id, label="evidence_id"),
        )
        object.__setattr__(
            self, "summary", _normalize_text(self.summary, label="summary")
        )
        object.__setattr__(self, "source", _normalize_token(self.source, label="source"))
        object.__setattr__(self, "path", _normalize_optional_path(self.path))
        if self.line is not None and self.line <= 0:
            raise ValueError("line must be positive when provided.")
        object.__setattr__(
            self,
            "tags",
            tuple(_normalize_token(tag, label="tag") for tag in self.tags),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @classmethod
    def create(
        cls,
        *,
        summary: str,
        strength: AuthoringEvidenceStrength = AuthoringEvidenceStrength.WEAK,
        source: str = "operator",
        path: str | None = None,
        line: int | None = None,
        tags: Iterable[str] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            evidence_id=f"evidence-{uuid4().hex}",
            summary=summary,
            strength=strength,
            source=source,
            path=path,
            line=line,
            tags=tuple(tags),
            metadata=dict(metadata or {}),
        )

    @property
    def has_direct_evidence(self) -> bool:
        return self.strength is AuthoringEvidenceStrength.DIRECT

    @property
    def location(self) -> str | None:
        if self.path is None:
            return None
        if self.line is None:
            return self.path
        return f"{self.path}:{self.line}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "summary": self.summary,
            "strength": self.strength.value,
            "source": self.source,
            "path": self.path,
            "line": self.line,
            "location": self.location,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            evidence_id=_require_text(payload, "evidence_id"),
            summary=_require_text(payload, "summary"),
            strength=AuthoringEvidenceStrength(
                str(payload.get("strength", AuthoringEvidenceStrength.WEAK.value))
            ),
            source=str(payload.get("source", "operator")),
            path=_optional_text_from_payload(payload, "path"),
            line=_optional_int_from_payload(payload, "line"),
            tags=_coerce_text_tuple(payload.get("tags", ()), field_name="tags"),
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )


@dataclass(frozen=True, slots=True)
class PatchAuthoringMutation:
    """
    One file-level mutation proposed by Wave 3.

    The mutation is structured so a compiler can convert it to a PatchDiff
    without executing model-provided code.
    """

    path: str
    before: str
    after: str
    mutation_type: str = "replace"
    rationale: str = "model proposed patch mutation"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _normalize_relative_path(self.path))
        object.__setattr__(
            self,
            "mutation_type",
            _normalize_token(self.mutation_type, label="mutation_type"),
        )
        object.__setattr__(
            self,
            "rationale",
            _normalize_text(self.rationale, label="rationale"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def digest(self) -> str:
        return _digest_payload(self.to_dict(include_digest=False))

    @property
    def size_delta(self) -> int:
        return len(self.after.encode("utf-8")) - len(self.before.encode("utf-8"))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload = {
            "path": self.path,
            "before_sha256": _sha256_text(self.before),
            "after_sha256": _sha256_text(self.after),
            "size_delta": self.size_delta,
            "mutation_type": self.mutation_type,
            "rationale": self.rationale,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            path=_require_text(payload, "path"),
            before=_require_text(payload, "before"),
            after=_require_text(payload, "after"),
            mutation_type=str(payload.get("mutation_type", "replace")),
            rationale=str(payload.get("rationale", "model proposed patch mutation")),
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )


@dataclass(frozen=True, slots=True)
class PatchAuthoringProposal:
    """
    Parsed Wave 3 patch proposal before policy review and compilation.

    This is still untrusted input. The compiler and policy gate must reject
    anything that violates the bounded authoring contract.
    """

    proposal_id: str
    objective: str
    mutations: tuple[PatchAuthoringMutation, ...]
    tests_to_run: tuple[str, ...] = field(default_factory=tuple)
    rationale: str = "model proposed patch"
    confidence: float = 0.0
    risks: tuple[str, ...] = field(default_factory=tuple)
    assumptions: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "proposal_id",
            _normalize_identifier(self.proposal_id, label="proposal_id"),
        )
        object.__setattr__(
            self,
            "objective",
            _normalize_text(self.objective, label="objective"),
        )
        mutation_tuple = tuple(self.mutations)
        if not mutation_tuple:
            raise ValueError("PatchAuthoringProposal requires at least one mutation.")
        object.__setattr__(self, "mutations", mutation_tuple)
        object.__setattr__(
            self,
            "tests_to_run",
            tuple(_normalize_text(test, label="test") for test in self.tests_to_run),
        )
        object.__setattr__(
            self, "rationale", _normalize_text(self.rationale, label="rationale")
        )
        if self.confidence < 0.0 or self.confidence > 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0.")
        object.__setattr__(
            self,
            "risks",
            tuple(_normalize_text(risk, label="risk") for risk in self.risks),
        )
        object.__setattr__(
            self,
            "assumptions",
            tuple(
                _normalize_text(assumption, label="assumption")
                for assumption in self.assumptions
            ),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @classmethod
    def create(
        cls,
        *,
        objective: str,
        mutations: Iterable[PatchAuthoringMutation],
        tests_to_run: Iterable[str] = (),
        rationale: str = "model proposed patch",
        confidence: float = 0.0,
        risks: Iterable[str] = (),
        assumptions: Iterable[str] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            proposal_id=f"patch-proposal-{uuid4().hex}",
            objective=objective,
            mutations=tuple(mutations),
            tests_to_run=tuple(tests_to_run),
            rationale=rationale,
            confidence=confidence,
            risks=tuple(risks),
            assumptions=tuple(assumptions),
            metadata=dict(metadata or {}),
        )

    @property
    def affected_paths(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(mutation.path for mutation in self.mutations))

    @property
    def total_size_delta(self) -> int:
        return sum(mutation.size_delta for mutation in self.mutations)

    @property
    def digest(self) -> str:
        return _digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload = {
            "proposal_id": self.proposal_id,
            "objective": self.objective,
            "affected_paths": list(self.affected_paths),
            "mutation_count": len(self.mutations),
            "total_size_delta": self.total_size_delta,
            "mutations": [mutation.to_dict() for mutation in self.mutations],
            "tests_to_run": list(self.tests_to_run),
            "rationale": self.rationale,
            "confidence": self.confidence,
            "risks": list(self.risks),
            "assumptions": list(self.assumptions),
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_mutations = payload.get("mutations", ())
        if not isinstance(raw_mutations, Iterable) or isinstance(raw_mutations, str):
            raise TypeError("mutations must be an iterable of mappings.")
        mutations: list[PatchAuthoringMutation] = []
        for raw_mutation in raw_mutations:
            if not isinstance(raw_mutation, Mapping):
                raise TypeError("mutations must contain only mappings.")
            mutations.append(PatchAuthoringMutation.from_dict(raw_mutation))

        return cls(
            proposal_id=_require_text(payload, "proposal_id"),
            objective=_require_text(payload, "objective"),
            mutations=tuple(mutations),
            tests_to_run=_coerce_text_tuple(
                payload.get("tests_to_run", ()), field_name="tests_to_run"
            ),
            rationale=str(payload.get("rationale", "model proposed patch")),
            confidence=float(payload.get("confidence", 0.0)),
            risks=_coerce_text_tuple(payload.get("risks", ()), field_name="risks"),
            assumptions=_coerce_text_tuple(
                payload.get("assumptions", ()), field_name="assumptions"
            ),
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )


@dataclass(frozen=True, slots=True)
class AuthoringSubtask:
    """
    One bounded task inside a Wave 3 repair decomposition plan.
    """

    subtask_id: str
    summary: str
    kind: AuthoringSubtaskKind
    risk_level: AuthoringRiskLevel = AuthoringRiskLevel.MODERATE
    depends_on: tuple[str, ...] = field(default_factory=tuple)
    target_paths: tuple[str, ...] = field(default_factory=tuple)
    required_evidence: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "subtask_id",
            _normalize_identifier(self.subtask_id, label="subtask_id"),
        )
        object.__setattr__(
            self, "summary", _normalize_text(self.summary, label="summary")
        )
        object.__setattr__(
            self,
            "depends_on",
            tuple(_normalize_identifier(item, label="depends_on") for item in self.depends_on),
        )
        object.__setattr__(
            self,
            "target_paths",
            tuple(_normalize_relative_path(path) for path in self.target_paths),
        )
        object.__setattr__(
            self,
            "required_evidence",
            tuple(_normalize_text(item, label="required_evidence") for item in self.required_evidence),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @classmethod
    def create(
        cls,
        *,
        summary: str,
        kind: AuthoringSubtaskKind,
        risk_level: AuthoringRiskLevel = AuthoringRiskLevel.MODERATE,
        depends_on: Iterable[str] = (),
        target_paths: Iterable[str] = (),
        required_evidence: Iterable[str] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            subtask_id=f"authoring-subtask-{uuid4().hex}",
            summary=summary,
            kind=kind,
            risk_level=risk_level,
            depends_on=tuple(depends_on),
            target_paths=tuple(target_paths),
            required_evidence=tuple(required_evidence),
            metadata=dict(metadata or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "subtask_id": self.subtask_id,
            "summary": self.summary,
            "kind": self.kind.value,
            "risk_level": self.risk_level.value,
            "depends_on": list(self.depends_on),
            "target_paths": list(self.target_paths),
            "required_evidence": list(self.required_evidence),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            subtask_id=_require_text(payload, "subtask_id"),
            summary=_require_text(payload, "summary"),
            kind=AuthoringSubtaskKind(_require_text(payload, "kind")),
            risk_level=AuthoringRiskLevel(
                str(payload.get("risk_level", AuthoringRiskLevel.MODERATE.value))
            ),
            depends_on=_coerce_text_tuple(
                payload.get("depends_on", ()), field_name="depends_on"
            ),
            target_paths=_coerce_text_tuple(
                payload.get("target_paths", ()), field_name="target_paths"
            ),
            required_evidence=_coerce_text_tuple(
                payload.get("required_evidence", ()), field_name="required_evidence"
            ),
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )


@dataclass(frozen=True, slots=True)
class AuthoringRequest:
    """
    Top-level request entering the Wave 3 authoring layer.
    """

    request_id: str
    objective: AuthoringObjective
    mode: AuthoringMode = AuthoringMode.DETERMINISTIC
    status: AuthoringStatus = AuthoringStatus.REQUESTED
    context: AuthoringContext | None = None
    evidence: tuple[AuthoringEvidence, ...] = field(default_factory=tuple)
    subtasks: tuple[AuthoringSubtask, ...] = field(default_factory=tuple)
    findings: tuple[AuthoringFinding, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "request_id",
            _normalize_identifier(self.request_id, label="request_id"),
        )
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "subtasks", tuple(self.subtasks))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @classmethod
    def create(
        cls,
        *,
        task_id: str,
        objective: str,
        mode: AuthoringMode = AuthoringMode.DETERMINISTIC,
        requested_by: str = "operator",
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            request_id=f"authoring-request-{uuid4().hex}",
            objective=AuthoringObjective.create(
                task_id=task_id,
                summary=objective,
                requested_by=requested_by,
            ),
            mode=mode,
            metadata=dict(metadata or {}),
        )

    @property
    def task_id(self) -> str:
        return self.objective.task_id

    @property
    def has_context(self) -> bool:
        return self.context is not None

    @property
    def has_direct_evidence(self) -> bool:
        return any(item.has_direct_evidence for item in self.evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "task_id": self.task_id,
            "mode": self.mode.value,
            "status": self.status.value,
            "objective": self.objective.to_dict(),
            "context": None if self.context is None else self.context.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
            "subtasks": [subtask.to_dict() for subtask in self.subtasks],
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_objective = payload.get("objective")
        if not isinstance(raw_objective, Mapping):
            raise TypeError("objective must be a mapping.")

        raw_context = payload.get("context")
        if raw_context is not None and not isinstance(raw_context, Mapping):
            raise TypeError("context must be a mapping or None.")

        return cls(
            request_id=_require_text(payload, "request_id"),
            objective=AuthoringObjective.from_dict(raw_objective),
            mode=AuthoringMode(_require_text(payload, "mode")),
            status=AuthoringStatus(_require_text(payload, "status")),
            context=None
            if raw_context is None
            else AuthoringContext.from_dict(raw_context),
            evidence=_load_evidence(payload.get("evidence", ())),
            subtasks=_load_subtasks(payload.get("subtasks", ())),
            findings=_load_findings(payload.get("findings", ())),
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )


def _load_findings(value: Any) -> tuple[AuthoringFinding, ...]:
    if not isinstance(value, Iterable) or isinstance(value, str):
        raise TypeError("findings must be an iterable of mappings.")
    findings: list[AuthoringFinding] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise TypeError("findings must contain only mappings.")
        findings.append(AuthoringFinding.from_dict(item))
    return tuple(findings)


def _load_evidence(value: Any) -> tuple[AuthoringEvidence, ...]:
    if not isinstance(value, Iterable) or isinstance(value, str):
        raise TypeError("evidence must be an iterable of mappings.")
    evidence: list[AuthoringEvidence] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise TypeError("evidence must contain only mappings.")
        evidence.append(AuthoringEvidence.from_dict(item))
    return tuple(evidence)


def _load_subtasks(value: Any) -> tuple[AuthoringSubtask, ...]:
    if not isinstance(value, Iterable) or isinstance(value, str):
        raise TypeError("subtasks must be an iterable of mappings.")
    subtasks: list[AuthoringSubtask] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise TypeError("subtasks must contain only mappings.")
        subtasks.append(AuthoringSubtask.from_dict(item))
    return tuple(subtasks)


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_token(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_path(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_relative_path(value)


def _normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("path must not be empty.")
    if cleaned.startswith(("/", "~")) or ":" in cleaned.split("/")[0]:
        raise ValueError(f"path must be relative: {value!r}.")

    parts: list[str] = []
    for raw_part in cleaned.split("/"):
        part = raw_part.strip()
        if part in {"", "."}:
            continue
        if part == "..":
            raise ValueError(f"path must not contain traversal: {value!r}.")
        parts.append(part)

    if not parts:
        raise ValueError("path must not resolve to the workspace root.")
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


def _sha256_text(value: str | None) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest_payload(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _coerce_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")
    return dict(value)


def _coerce_text_tuple(value: Any, *, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, Iterable) or isinstance(value, str):
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


def _require_int(payload: Mapping[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int):
        raise TypeError(f"Field {key!r} must be an integer.")
    return value


def _optional_text_from_payload(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string or None.")
    return value


def _optional_int_from_payload(payload: Mapping[str, Any], key: str) -> int | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, int):
        raise TypeError(f"Field {key!r} must be an integer or None.")
    return value
