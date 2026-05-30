from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum, auto
from pathlib import PurePosixPath
from typing import Any, TypeVar

WAVE10_OPERATING_SCHEMA_VERSION = "wave10.ai_engineering_operating_system.v1"
_SHA256_LENGTH = 64
_StrEnumT = TypeVar("_StrEnumT", bound=StrEnum)


class OperatingDisposition(StrEnum):
    """Top-level Wave 10 operating gate disposition."""

    READY = auto()
    WARNING = auto()
    BLOCKED = auto()


class OperatingSeverity(StrEnum):
    """Normalized severity scale for Wave 10 findings and blockers."""

    INFO = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


class OperatingDomain(StrEnum):
    """Wave 10 operating domains required by the locked roadmap."""

    MULTI_REPO = auto()
    MULTI_TEAM = auto()
    POLICY_GOVERNED = auto()
    MEASURABLE = auto()
    REPLAYABLE = auto()
    REVIEWABLE = auto()


class OperatingArtifactKind(StrEnum):
    """Evidence artifact families consumed or emitted by Wave 10."""

    REPOSITORY_REGISTRY = auto()
    TEAM_AUTHORITY = auto()
    WORK_PACKAGE = auto()
    CAMPAIGN_GRAPH = auto()
    EVIDENCE_MANIFEST = auto()
    REPLAY_MANIFEST = auto()
    REVIEW_BUNDLE = auto()
    OPERATING_REPORT = auto()
    POLICY_EVALUATION = auto()
    STANDARDS_CROSSWALK = auto()
    CLOUD_FINDING_EXPORT = auto()


class OperatingSourceWave(StrEnum):
    """Origin layer for evidence normalized into the Wave 10 operating layer."""

    WAVE5 = auto()
    WAVE6 = auto()
    WAVE7 = auto()
    WAVE8 = auto()
    WAVE9 = auto()
    WAVE10 = auto()
    DONOR_COGNITION = auto()
    DONOR_WORLDTWIN = auto()
    DONOR_ASSURANCE_CASE_RUNTIME = auto()
    DONOR_SUSTAINMENT_OS = auto()
    DONOR_STYLE = auto()
    DONOR_SUPERHEAVY_SURVIVAL_AUDIT = auto()
    DONOR_DECRIEL = auto()
    EXTERNAL = auto()


@dataclass(frozen=True, slots=True)
class OperatingFinding:
    """A deterministic Wave 10 finding attached to a gate, report, or bundle."""

    code: str
    severity: OperatingSeverity
    summary: str
    domains: tuple[OperatingDomain, ...] = ()
    paths: tuple[str, ...] = ()
    blocking: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", normalize_dotted_name(self.code, label="code"))
        object.__setattr__(self, "summary", normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "domains", unique_sorted_enum_tuple(self.domains))
        object.__setattr__(self, "paths", normalize_path_tuple(self.paths, label="paths"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "summary": self.summary,
            "domains": [domain.value for domain in self.domains],
            "paths": list(self.paths),
            "blocking": self.blocking,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OperatingArtifactRef:
    """Stable reference to an evidence artifact used by the operating layer."""

    artifact_id: str
    kind: OperatingArtifactKind
    source_wave: OperatingSourceWave
    path: str
    sha256: str
    producer: str
    schema_version: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "artifact_id",
            normalize_identifier(self.artifact_id, label="artifact_id"),
        )
        object.__setattr__(self, "path", normalize_relative_path(self.path))
        object.__setattr__(self, "sha256", normalize_sha256(self.sha256))
        object.__setattr__(self, "producer", normalize_text(self.producer, label="producer"))
        object.__setattr__(
            self,
            "schema_version",
            normalize_optional_text(self.schema_version, label="schema_version"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind.value,
            "source_wave": self.source_wave.value,
            "path": self.path,
            "sha256": self.sha256,
            "producer": self.producer,
            "schema_version": self.schema_version,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class OperatingEnvelope:
    """Common signed-by-digest envelope for Wave 10 operating artifacts."""

    envelope_id: str
    artifact_kind: OperatingArtifactKind
    subject: str
    schema_version: str = WAVE10_OPERATING_SCHEMA_VERSION
    domains: tuple[OperatingDomain, ...] = ()
    evidence: tuple[OperatingArtifactRef, ...] = ()
    findings: tuple[OperatingFinding, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "envelope_id",
            normalize_identifier(self.envelope_id, label="envelope_id"),
        )
        object.__setattr__(self, "subject", normalize_text(self.subject, label="subject"))
        object.__setattr__(
            self,
            "schema_version",
            normalize_text(self.schema_version, label="schema_version"),
        )
        object.__setattr__(self, "domains", unique_sorted_enum_tuple(self.domains))
        evidence = tuple(sorted(self.evidence, key=lambda item: item.artifact_id))
        artifact_ids = [artifact.artifact_id for artifact in evidence]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError("OperatingEnvelope evidence artifact_id values must be unique.")
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(
            self,
            "findings",
            tuple(sorted(self.findings, key=lambda item: (item.severity.value, item.code))),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def blocking_findings(self) -> tuple[OperatingFinding, ...]:
        return tuple(finding for finding in self.findings if finding.blocking)

    @property
    def warning_findings(self) -> tuple[OperatingFinding, ...]:
        return tuple(finding for finding in self.findings if not finding.blocking)

    @property
    def disposition(self) -> OperatingDisposition:
        if self.blocking_findings:
            return OperatingDisposition.BLOCKED
        if self.findings:
            return OperatingDisposition.WARNING
        return OperatingDisposition.READY

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "envelope_id": self.envelope_id,
            "artifact_kind": self.artifact_kind.value,
            "subject": self.subject,
            "schema_version": self.schema_version,
            "domains": [domain.value for domain in self.domains],
            "evidence": [artifact.to_dict() for artifact in self.evidence],
            "findings": [finding.to_dict() for finding in self.findings],
            "blocking_finding_count": len(self.blocking_findings),
            "disposition": self.disposition.value,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


def digest_payload(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace("_", "-").replace(" ", "-")
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    cleaned = cleaned.strip("-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def normalize_dotted_name(value: str, *, label: str) -> str:
    cleaned = value.strip().replace("/", ".")
    cleaned = ".".join(part.strip() for part in cleaned.split(".") if part.strip())
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def normalize_optional_text(value: str, *, label: str) -> str:
    if not value.strip():
        return ""
    return normalize_text(value, label=label)


def normalize_text(value: str, *, label: str) -> str:
    cleaned = " ".join(value.strip().split())
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def normalize_sha256(value: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) != _SHA256_LENGTH or any(char not in "0123456789abcdef" for char in cleaned):
        raise ValueError("sha256 must be a 64-character lowercase hexadecimal digest.")
    return cleaned


def normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("path must not be empty.")
    path = PurePosixPath(cleaned)
    if path.is_absolute():
        raise ValueError("path must be repository-relative.")
    if any(part == ".." for part in path.parts):
        raise ValueError("path traversal is not allowed.")
    return path.as_posix()


def normalize_path_tuple(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = normalize_relative_path(value)
        if item not in seen:
            normalized.append(item)
            seen.add(item)
    return tuple(sorted(normalized))


def unique_sorted_enum_tuple(values: Sequence[_StrEnumT]) -> tuple[_StrEnumT, ...]:
    by_value: dict[str, _StrEnumT] = {}
    for value in values:
        by_value[value.value] = value
    return tuple(by_value[key] for key in sorted(by_value))
