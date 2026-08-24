from __future__ import annotations

import hashlib
import json
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from ix_blackfox.assurance.models import (
    AssuranceEvidenceArtifact,
    AssuranceEvidenceKind,
    AssuranceEvidenceSource,
    EvidenceVerificationState,
    normalize_media_type,
    normalize_optional_text,
)
from ix_blackfox.operating.models import (
    normalize_identifier,
    normalize_relative_path,
    normalize_text,
)

DEFAULT_MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_TOTAL_EVIDENCE_BYTES = 64 * 1024 * 1024

_DENIED_PATH_PARTS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "__pycache__",
        "node_modules",
    }
)
_DENIED_FILENAMES = frozenset(
    {
        ".env",
        "id_rsa",
        "id_ed25519",
        "credentials",
        "credentials.json",
    }
)
_DENIED_SUFFIXES = frozenset({".key", ".pem", ".p12", ".pfx"})
_PRIVATE_KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)


@dataclass(frozen=True, slots=True)
class EvidenceInputSpec:
    """Local file input that Wave 12 will collect into its evidence namespace."""

    artifact_id: str
    source_wave: AssuranceEvidenceSource
    evidence_kind: AssuranceEvidenceKind
    source_path: str
    package_path: str
    media_type: str
    producer: str
    schema_version: str = ""
    required: bool = True
    revision_json_pointer: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "artifact_id",
            normalize_identifier(self.artifact_id, label="artifact_id"),
        )
        object.__setattr__(self, "source_path", normalize_relative_path(self.source_path))
        package_path = normalize_relative_path(self.package_path)
        if not package_path.startswith("evidence/"):
            raise ValueError("EvidenceInputSpec package_path must be beneath evidence/.")
        object.__setattr__(self, "package_path", package_path)
        object.__setattr__(self, "media_type", normalize_media_type(self.media_type))
        object.__setattr__(
            self,
            "producer",
            normalize_text(self.producer, label="producer"),
        )
        object.__setattr__(
            self,
            "schema_version",
            normalize_optional_text(self.schema_version, label="schema_version"),
        )
        object.__setattr__(
            self,
            "revision_json_pointer",
            normalize_json_pointer(self.revision_json_pointer),
        )
        if self.revision_json_pointer and self.media_type != "application/json":
            raise ValueError(
                "revision_json_pointer requires media_type application/json."
            )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> EvidenceInputSpec:
        return cls(
            artifact_id=_string_field(payload, "artifact_id"),
            source_wave=AssuranceEvidenceSource(_string_field(payload, "source_wave")),
            evidence_kind=AssuranceEvidenceKind(
                _string_field(payload, "evidence_kind")
            ),
            source_path=_string_field(payload, "source_path"),
            package_path=_string_field(payload, "package_path"),
            media_type=_string_field(payload, "media_type"),
            producer=_string_field(payload, "producer"),
            schema_version=_optional_string_field(payload, "schema_version"),
            required=_bool_field(payload, "required", default=True),
            revision_json_pointer=_optional_string_field(
                payload,
                "revision_json_pointer",
            ),
            metadata=_mapping_field(payload.get("metadata", {}), "metadata"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "source_wave": self.source_wave.value,
            "evidence_kind": self.evidence_kind.value,
            "source_path": self.source_path,
            "package_path": self.package_path,
            "media_type": self.media_type,
            "producer": self.producer,
            "schema_version": self.schema_version,
            "required": self.required,
            "revision_json_pointer": self.revision_json_pointer,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class CollectedEvidence:
    """Validated evidence bytes and their immutable descriptor."""

    artifact: AssuranceEvidenceArtifact
    body: bytes = field(repr=False)

    def __post_init__(self) -> None:
        actual_digest = hashlib.sha256(self.body).hexdigest()
        if actual_digest != self.artifact.sha256:
            raise ValueError("Collected evidence body does not match descriptor sha256.")
        if len(self.body) != self.artifact.size_bytes:
            raise ValueError("Collected evidence body does not match descriptor size_bytes.")


def load_evidence_specs(path: Path) -> tuple[EvidenceInputSpec, ...]:
    """Load a deterministic evidence-spec list from JSON."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        raw_specs = payload.get("evidence")
    else:
        raw_specs = payload
    if not isinstance(raw_specs, list):
        raise ValueError("Evidence spec JSON must be a list or contain an evidence list.")

    specs: list[EvidenceInputSpec] = []
    for index, item in enumerate(raw_specs):
        if not isinstance(item, dict):
            raise ValueError(f"Evidence spec at index {index} must be an object.")
        specs.append(EvidenceInputSpec.from_mapping(item))
    return normalize_evidence_specs(specs)


def normalize_evidence_specs(
    specs: Sequence[EvidenceInputSpec],
) -> tuple[EvidenceInputSpec, ...]:
    normalized = tuple(sorted(specs, key=lambda item: item.artifact_id))
    if not normalized:
        raise ValueError("At least one evidence input spec is required.")
    artifact_ids = [spec.artifact_id for spec in normalized]
    package_paths = [spec.package_path for spec in normalized]
    if len(artifact_ids) != len(set(artifact_ids)):
        raise ValueError("Evidence input artifact_id values must be unique.")
    if len(package_paths) != len(set(package_paths)):
        raise ValueError("Evidence input package_path values must be unique.")
    return normalized


def collect_evidence(
    root: Path,
    specs: Sequence[EvidenceInputSpec],
    *,
    expected_revision: str,
    max_evidence_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES,
    max_total_evidence_bytes: int = DEFAULT_MAX_TOTAL_EVIDENCE_BYTES,
) -> tuple[CollectedEvidence, ...]:
    """Collect local evidence with path, size, secret, JSON, and revision checks."""

    if max_evidence_bytes <= 0 or max_total_evidence_bytes <= 0:
        raise ValueError("Evidence size limits must be positive.")
    resolved_root = root.resolve(strict=True)
    normalized_specs = normalize_evidence_specs(specs)
    collected: list[CollectedEvidence] = []
    total_bytes = 0

    for spec in normalized_specs:
        source = _resolve_evidence_source(resolved_root, spec.source_path)
        body = _read_bounded_evidence(
            source,
            artifact_id=spec.artifact_id,
            max_bytes=max_evidence_bytes,
        )
        size = len(body)
        total_bytes += size
        if total_bytes > max_total_evidence_bytes:
            raise ValueError("Collected evidence exceeds the total size limit.")

        _reject_private_key_material(spec, body)
        revision_binding_verified = _validate_structured_evidence(
            spec,
            body,
            expected_revision=expected_revision,
        )
        metadata = {
            **dict(spec.metadata),
            "source_path": spec.source_path,
            "revision_binding_required": bool(spec.revision_json_pointer),
            "revision_binding_verified": revision_binding_verified,
            "revision_json_pointer": spec.revision_json_pointer,
        }
        artifact = AssuranceEvidenceArtifact(
            artifact_id=spec.artifact_id,
            source_wave=spec.source_wave,
            evidence_kind=spec.evidence_kind,
            path=spec.package_path,
            sha256=hashlib.sha256(body).hexdigest(),
            size_bytes=len(body),
            media_type=spec.media_type,
            producer=spec.producer,
            verification_state=EvidenceVerificationState.INTEGRITY_VERIFIED,
            schema_version=spec.schema_version,
            required=spec.required,
            metadata=metadata,
        )
        collected.append(CollectedEvidence(artifact=artifact, body=body))

    return tuple(collected)


def _resolve_evidence_source(root: Path, relative_path: str) -> Path:
    pure_path = PurePosixPath(relative_path)
    _reject_sensitive_path(pure_path)
    candidate = root.joinpath(*pure_path.parts)
    _reject_symlink_components(root, candidate)
    try:
        mode = candidate.stat().st_mode
    except FileNotFoundError as exc:
        raise ValueError(f"Evidence source does not exist: {relative_path}") from exc
    if not stat.S_ISREG(mode):
        raise ValueError(f"Evidence source is not a regular file: {relative_path}")
    resolved_candidate = candidate.resolve(strict=True)
    if not resolved_candidate.is_relative_to(root):
        raise ValueError("Evidence source escapes the repository root.")
    return resolved_candidate


def _reject_symlink_components(root: Path, candidate: Path) -> None:
    current = root
    relative = candidate.relative_to(root)
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"Evidence source contains a symlink component: {part}")


def _reject_sensitive_path(path: PurePosixPath) -> None:
    lowered_parts = tuple(part.lower() for part in path.parts)
    if any(part in _DENIED_PATH_PARTS for part in lowered_parts):
        raise ValueError("Evidence source path is inside a denied generated or VCS area.")
    filename = lowered_parts[-1]
    if filename in _DENIED_FILENAMES or path.suffix.lower() in _DENIED_SUFFIXES:
        raise ValueError("Evidence source path resembles credential or key material.")


def _reject_private_key_material(spec: EvidenceInputSpec, body: bytes) -> None:
    if any(marker in body for marker in _PRIVATE_KEY_MARKERS):
        raise ValueError(
            f"Evidence artifact {spec.artifact_id} contains private-key material."
        )


def _read_bounded_evidence(
    source: Path,
    *,
    artifact_id: str,
    max_bytes: int,
) -> bytes:
    with source.open("rb") as stream:
        body = stream.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ValueError(
            f"Evidence artifact {artifact_id} exceeds the per-file size limit."
        )
    return body


def _validate_structured_evidence(
    spec: EvidenceInputSpec,
    body: bytes,
    *,
    expected_revision: str,
) -> bool:
    if spec.media_type != "application/json":
        return False
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"Evidence artifact {spec.artifact_id} is not valid UTF-8 JSON."
        ) from exc
    if not spec.revision_json_pointer:
        return False
    actual_revision = resolve_json_pointer(payload, spec.revision_json_pointer)
    if actual_revision != expected_revision:
        raise ValueError(
            f"Evidence artifact {spec.artifact_id} is bound to revision "
            f"{actual_revision!r}, not {expected_revision!r}."
        )
    return True


def resolve_json_pointer(payload: Any, pointer: str) -> Any:
    """Resolve an RFC 6901-style JSON pointer without accepting invalid escapes."""

    normalized = normalize_json_pointer(pointer)
    if not normalized:
        return payload
    current = payload
    for raw_part in normalized[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if part not in current:
                raise ValueError(f"JSON pointer component is missing: {part}")
            current = current[part]
        elif isinstance(current, list):
            try:
                index = int(part)
                current = current[index]
            except (ValueError, IndexError) as exc:
                raise ValueError(f"JSON pointer list index is invalid: {part}") from exc
        else:
            raise ValueError(f"JSON pointer cannot descend through component: {part}")
    return current


def normalize_json_pointer(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        return ""
    if not cleaned.startswith("/"):
        raise ValueError("revision_json_pointer must be empty or start with /.")
    index = 0
    while index < len(cleaned):
        if cleaned[index] == "~":
            if index + 1 >= len(cleaned) or cleaned[index + 1] not in {"0", "1"}:
                raise ValueError("JSON pointer contains an invalid escape.")
            index += 2
            continue
        index += 1
    return cleaned


def _string_field(payload: Mapping[str, Any], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string.")
    return value


def _optional_string_field(payload: Mapping[str, Any], name: str) -> str:
    value = payload.get(name, "")
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string.")
    return value


def _bool_field(payload: Mapping[str, Any], name: str, *, default: bool) -> bool:
    value = payload.get(name, default)
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean.")
    return value


def _mapping_field(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object.")
    return value
