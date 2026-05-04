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
    Normalized evidence available to the Wave 3 authoring layer.
    """

    evidence_id: str
    source: str
    strength: AuthoringEvidenceStrength
    summary: str
    raw_digest: str | None = None
    related_paths: tuple[str, ...] = field(default_factory=tuple)
    findings: tuple[AuthoringFinding, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "evidence_id",
            _normalize_identifier(self.evidence_id, label="evidence_id"),
        )
        object.__setattr__(
            self, "source", _normalize_token(self.source, label="source")
        )
        object.__setattr__(
            self, "summary", _normalize_text(self.summary, label="summary")
        )
        object.__setattr__(
            self,
            "raw_digest",
            _normalize_optional_sha256(self.raw_digest),
        )
        object.__setattr__(
            self,
            "related_paths",
            tuple(_normalize_relative_path(path) for path in self.related_paths),
        )
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @classmethod
    def create(
        cls,
        *,
        source: str,
        strength: AuthoringEvidenceStrength,
        summary: str,
        raw_text: str | None = None,
        related_paths: Iterable[str] = (),
        findings: Iterable[AuthoringFinding] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            evidence_id=f"evidence-{uuid4().hex}",
            source=source,
            strength=strength,
            summary=summary,
            raw_digest=_sha256_text(raw_text),
            related_paths=tuple(related_paths),
            findings=tuple(findings),
            metadata=dict(metadata or {}),
        )

    @property
    def has_direct_evidence(self) -> bool:
        return self.strength is AuthoringEvidenceStrength.DIRECT

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source": self.source,
            "strength": self.strength.value,
            "summary": self.summary,
            "raw_digest": self.raw_digest,
            "related_paths": list(self.related_paths),
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_findings = payload.get("findings", ())
        if not isinstance(raw_findings, Iterable) or isinstance(raw_findings, str):
            raise TypeError("findings must be an iterable of mappings.")
        findings: list[AuthoringFinding] = []
        for raw_finding in raw_findings:
            if not isinstance(raw_finding, Mapping):
                raise TypeError("findings must contain only mappings.")
            findings.append(AuthoringFinding.from_dict(raw_finding))
        return cls(
            evidence_id=_require_text(payload, "evidence_id"),
            source=_require_text(payload, "source"),
            strength=AuthoringEvidenceStrength(_require_text(payload, "strength")),
            summary=_require_text(payload, "summary"),
            raw_digest=_optional_text_from_payload(payload, "raw_digest"),
            related_paths=_coerce_text_tuple(
                payload.get("related_paths", ()), field_name="related_paths"
            ),
            findings=tuple(findings),
            metadata=_coerce_mapping(
                payload.get("metadata", {}), field_name="metadata"
            ),
        )


@dataclass(frozen=True, slots=True)
class AuthoringSubtask:
    """
    One explicit task-decomposition step for Wave 3 repair authoring.
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
            tuple(
                _normalize_identifier(value, label="depends_on")
                for value in self.depends_on
            ),
        )
        object.__setattr__(
            self,
            "target_paths",
            tuple(_normalize_relative_path(path) for path in self.target_paths),
        )
        object.__setattr__(
            self,
            "required_evidence",
            tuple(
                _normalize_identifier(value, label="required_evidence")
                for value in self.required_evidence
            ),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

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
