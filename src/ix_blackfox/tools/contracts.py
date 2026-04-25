from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any, Self
from uuid import uuid4

from ix_blackfox.tools.manifest import ToolCapability


class ToolInvocationStatus(StrEnum):
    """
    Terminal status for one governed tool invocation.
    """

    SUCCEEDED = auto()
    FAILED = auto()
    BLOCKED = auto()
    REVIEW_REQUIRED = auto()
    TIMED_OUT = auto()


class ToolFailureKind(StrEnum):
    """
    Provider-agnostic failure categories for governed tool calls.
    """

    INVALID_REQUEST = auto()
    TOOL_NOT_FOUND = auto()
    UNSUPPORTED_CAPABILITY = auto()
    POLICY_BLOCKED = auto()
    APPROVAL_REQUIRED = auto()
    PATH_VIOLATION = auto()
    TIMEOUT = auto()
    EXECUTION_ERROR = auto()
    PROTOCOL_ERROR = auto()


@dataclass(frozen=True, slots=True)
class ToolFailure:
    """
    Normalized failure detail for one tool invocation.

    Attributes
    ----------
    kind:
        Stable failure category.
    message:
        Human-readable failure explanation.
    retryable:
        Whether the runtime may retry safely.
    metadata:
        Optional structured failure metadata.
    """

    kind: ToolFailureKind
    message: str
    retryable: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "message", _normalize_text(self.message, label="message"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "message": self.message,
            "retryable": self.retryable,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            kind=ToolFailureKind(_require_text(payload, "kind")),
            message=_require_text(payload, "message"),
            retryable=bool(payload.get("retryable", False)),
            metadata=_coerce_mapping(
                payload.get("metadata", {}),
                field_name="metadata",
            ),
        )


@dataclass(frozen=True, slots=True)
class ToolOutputArtifact:
    """
    Logical artifact emitted by a governed tool invocation.

    The artifact may point to a file path, run-bundle URI, or in-memory logical
    reference. The contract records identity and provenance metadata without
    assuming storage implementation.
    """

    artifact_id: str
    name: str
    uri: str
    media_type: str = "application/octet-stream"
    sha256: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "artifact_id",
            _normalize_identifier(self.artifact_id, label="artifact_id"),
        )
        object.__setattr__(self, "name", _normalize_text(self.name, label="name"))
        object.__setattr__(self, "uri", _normalize_text(self.uri, label="uri"))
        object.__setattr__(
            self,
            "media_type",
            _normalize_text(self.media_type, label="media_type"),
        )
        object.__setattr__(self, "sha256", _normalize_optional_text(self.sha256))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.sha256 is not None and len(self.sha256) != 64:
            raise ValueError("ToolOutputArtifact sha256 must be a 64-character digest.")

    @classmethod
    def create(
        cls,
        *,
        name: str,
        uri: str,
        media_type: str = "application/octet-stream",
        sha256: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            artifact_id=f"tool-artifact-{uuid4().hex}",
            name=name,
            uri=uri,
            media_type=media_type,
            sha256=sha256,
            metadata=dict(metadata or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "name": self.name,
            "uri": self.uri,
            "media_type": self.media_type,
            "sha256": self.sha256,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            artifact_id=_require_text(payload, "artifact_id"),
            name=_require_text(payload, "name"),
            uri=_require_text(payload, "uri"),
            media_type=str(payload.get("media_type", "application/octet-stream")),
            sha256=_optional_text_from_payload(payload, "sha256"),
            metadata=_coerce_mapping(
                payload.get("metadata", {}),
                field_name="metadata",
            ),
        )


@dataclass(frozen=True, slots=True)
class ToolInvocationRequest:
    """
    Provider-agnostic request to invoke one governed tool.

    This contract is intentionally separate from tool execution. Runtime layers
    must still resolve the manifest, apply policy, enforce approval, execute the
    tool, and record receipts.
    """

    invocation_id: str
    tool_id: str
    capability: ToolCapability
    arguments: Mapping[str, Any] = field(default_factory=dict)
    task_id: str | None = None
    run_id: str | None = None
    requested_by: str | None = None
    timeout_seconds: float | None = None
    labels: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "invocation_id",
            _normalize_identifier(self.invocation_id, label="invocation_id"),
        )
        object.__setattr__(
            self,
            "tool_id",
            _normalize_identifier(self.tool_id, label="tool_id"),
        )
        object.__setattr__(
            self,
            "arguments",
            _coerce_mapping(self.arguments, field_name="arguments"),
        )
        object.__setattr__(self, "task_id", _normalize_optional_identifier(self.task_id))
        object.__setattr__(self, "run_id", _normalize_optional_identifier(self.run_id))
        object.__setattr__(
            self,
            "requested_by",
            _normalize_optional_identifier(self.requested_by),
        )
        object.__setattr__(self, "labels", _normalize_labels(self.labels))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.timeout_seconds is not None and self.timeout_seconds <= 0:
            raise ValueError("ToolInvocationRequest timeout_seconds must be positive.")

        if self.created_at.tzinfo is None:
            raise ValueError("ToolInvocationRequest created_at must be timezone-aware.")

    @classmethod
    def create(
        cls,
        *,
        tool_id: str,
        capability: ToolCapability,
        arguments: Mapping[str, Any] | None = None,
        task_id: str | None = None,
        run_id: str | None = None,
        requested_by: str | None = None,
        timeout_seconds: float | None = None,
        labels: tuple[str, ...] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            invocation_id=f"tool-call-{uuid4().hex}",
            tool_id=tool_id,
            capability=capability,
            arguments=dict(arguments or {}),
            task_id=task_id,
            run_id=run_id,
            requested_by=requested_by,
            timeout_seconds=timeout_seconds,
            labels=tuple(labels or ()),
            metadata=dict(metadata or {}),
            created_at=datetime.now(tz=UTC),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "invocation_id": self.invocation_id,
            "tool_id": self.tool_id,
            "capability": self.capability.value,
            "arguments": dict(self.arguments),
            "task_id": self.task_id,
            "run_id": self.run_id,
            "requested_by": self.requested_by,
            "timeout_seconds": self.timeout_seconds,
            "labels": list(self.labels),
            "metadata": dict(self.metadata),
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            invocation_id=_require_text(payload, "invocation_id"),
            tool_id=_require_text(payload, "tool_id"),
            capability=ToolCapability(_require_text(payload, "capability")),
            arguments=_coerce_mapping(
                payload.get("arguments", {}),
                field_name="arguments",
            ),
            task_id=_optional_text_from_payload(payload, "task_id"),
            run_id=_optional_text_from_payload(payload, "run_id"),
            requested_by=_optional_text_from_payload(payload, "requested_by"),
            timeout_seconds=_coerce_optional_float(payload.get("timeout_seconds")),
            labels=_coerce_string_tuple(payload.get("labels", ()), field_name="labels"),
            metadata=_coerce_mapping(
                payload.get("metadata", {}),
                field_name="metadata",
            ),
            created_at=_parse_datetime(_require_text(payload, "created_at")),
        )


@dataclass(frozen=True, slots=True)
class ToolInvocationResult:
    """
    Terminal result from one governed tool invocation.
    """

    invocation_id: str
    tool_id: str
    status: ToolInvocationStatus
    output: Mapping[str, Any] = field(default_factory=dict)
    artifacts: tuple[ToolOutputArtifact, ...] = field(default_factory=tuple)
    failure: ToolFailure | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    finished_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "invocation_id",
            _normalize_identifier(self.invocation_id, label="invocation_id"),
        )
        object.__setattr__(
            self,
            "tool_id",
            _normalize_identifier(self.tool_id, label="tool_id"),
        )
        object.__setattr__(
            self,
            "output",
            _coerce_mapping(self.output, field_name="output"),
        )
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.started_at.tzinfo is None:
            raise ValueError("ToolInvocationResult started_at must be timezone-aware.")
        if self.finished_at.tzinfo is None:
            raise ValueError("ToolInvocationResult finished_at must be timezone-aware.")
        if self.finished_at < self.started_at:
            raise ValueError("ToolInvocationResult finished_at cannot predate started_at.")

        if self.status is ToolInvocationStatus.SUCCEEDED and self.failure is not None:
            raise ValueError("Successful tool invocations must not include failure details.")

        if self.status is not ToolInvocationStatus.SUCCEEDED and self.failure is None:
            raise ValueError("Unsuccessful tool invocations must include failure details.")

    @property
    def latency_ms(self) -> int:
        delta = self.finished_at - self.started_at
        return int(delta.total_seconds() * 1000)

    @classmethod
    def succeeded(
        cls,
        *,
        request: ToolInvocationRequest,
        output: Mapping[str, Any] | None = None,
        artifacts: tuple[ToolOutputArtifact, ...] | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            invocation_id=request.invocation_id,
            tool_id=request.tool_id,
            status=ToolInvocationStatus.SUCCEEDED,
            output=dict(output or {}),
            artifacts=tuple(artifacts or ()),
            started_at=started_at or datetime.now(tz=UTC),
            finished_at=finished_at or datetime.now(tz=UTC),
            metadata=dict(metadata or {}),
        )

    @classmethod
    def failed(
        cls,
        *,
        request: ToolInvocationRequest,
        status: ToolInvocationStatus,
        failure: ToolFailure,
        output: Mapping[str, Any] | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        if status is ToolInvocationStatus.SUCCEEDED:
            raise ValueError("Use ToolInvocationResult.succeeded for successful results.")

        return cls(
            invocation_id=request.invocation_id,
            tool_id=request.tool_id,
            status=status,
            output=dict(output or {}),
            artifacts=(),
            failure=failure,
            started_at=started_at or datetime.now(tz=UTC),
            finished_at=finished_at or datetime.now(tz=UTC),
            metadata=dict(metadata or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "invocation_id": self.invocation_id,
            "tool_id": self.tool_id,
            "status": self.status.value,
            "output": dict(self.output),
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "failure": self.failure.to_dict() if self.failure else None,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "latency_ms": self.latency_ms,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        failure_payload = payload.get("failure")
        raw_artifacts = payload.get("artifacts", ())

        if failure_payload is not None and not isinstance(failure_payload, Mapping):
            raise TypeError("failure must be a mapping or None.")
        if not isinstance(raw_artifacts, Iterable) or isinstance(raw_artifacts, str):
            raise TypeError("artifacts must be an iterable of mappings.")

        artifacts: list[ToolOutputArtifact] = []
        for raw_artifact in raw_artifacts:
            if not isinstance(raw_artifact, Mapping):
                raise TypeError("artifacts must contain only mappings.")
            artifacts.append(ToolOutputArtifact.from_dict(raw_artifact))

        return cls(
            invocation_id=_require_text(payload, "invocation_id"),
            tool_id=_require_text(payload, "tool_id"),
            status=ToolInvocationStatus(_require_text(payload, "status")),
            output=_coerce_mapping(payload.get("output", {}), field_name="output"),
            artifacts=tuple(artifacts),
            failure=(
                ToolFailure.from_dict(failure_payload)
                if isinstance(failure_payload, Mapping)
                else None
            ),
            started_at=_parse_datetime(_require_text(payload, "started_at")),
            finished_at=_parse_datetime(_require_text(payload, "finished_at")),
            metadata=_coerce_mapping(
                payload.get("metadata", {}),
                field_name="metadata",
            ),
        )


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_identifier(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_identifier(value, label="optional_identifier")


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _normalize_labels(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for raw_value in values:
        cleaned = raw_value.strip().lower().replace(" ", "-")
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _coerce_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")
    return dict(value)


def _coerce_string_tuple(value: Any, *, field_name: str) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, Iterable):
        raise TypeError(f"{field_name} must be a string or iterable of strings.")

    values: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"{field_name} must contain only strings.")
        values.append(item)

    return tuple(values)


def _coerce_optional_float(value: Any) -> float | None:
    if value is None:
        return None
    return float(value)


def _require_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string.")
    return value


def _optional_text_from_payload(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string or None.")
    return value


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Serialized datetimes must be timezone-aware.")
    return parsed
