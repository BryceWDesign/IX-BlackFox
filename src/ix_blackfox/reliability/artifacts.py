from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from ix_blackfox.reliability.runner import ReliabilityLabRunResult


class ReliabilityArtifactError(RuntimeError):
    """
    Raised when a reliability artifact cannot be safely persisted.
    """


class ReliabilityReceiptEventType(StrEnum):
    """
    Canonical receipt events for Wave 4 reliability-lab evidence bundles.
    """

    LAB_RUN_REPORTED = auto()
    ARTIFACT_WRITTEN = auto()
    BUNDLE_FINALIZED = auto()


@dataclass(frozen=True, slots=True)
class ReliabilityArtifact:
    """
    One persisted Wave 4 reliability artifact.
    """

    name: str
    uri: str
    media_type: str
    sha256: str
    size_bytes: int
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.size_bytes < 0:
            raise ValueError("ReliabilityArtifact size_bytes must be non-negative.")
        object.__setattr__(self, "name", _normalize_text(self.name, label="name"))
        object.__setattr__(self, "uri", _normalize_relative_uri(self.uri))
        object.__setattr__(
            self,
            "media_type",
            _normalize_text(self.media_type, label="media_type"),
        )
        object.__setattr__(self, "sha256", _normalize_sha256(self.sha256))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "uri": self.uri,
            "media_type": self.media_type,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ReliabilityReceipt:
    """
    Tamper-evident receipt for reliability artifact creation.
    """

    receipt_id: str
    event_type: ReliabilityReceiptEventType
    summary: str
    report_id: str
    bundle_id: str
    previous_receipt_id: str | None
    previous_chain_digest: str | None
    chain_digest: str
    created_at: datetime
    artifact_uri: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "receipt_id",
            _normalize_token(self.receipt_id, label="receipt_id"),
        )
        object.__setattr__(
            self,
            "summary",
            _normalize_text(self.summary, label="summary"),
        )
        object.__setattr__(
            self,
            "report_id",
            _normalize_token(self.report_id, label="report_id"),
        )
        object.__setattr__(
            self,
            "bundle_id",
            _normalize_token(self.bundle_id, label="bundle_id"),
        )
        object.__setattr__(
            self,
            "previous_receipt_id",
            _normalize_optional_token(
                self.previous_receipt_id,
                label="previous_receipt_id",
            ),
        )
        object.__setattr__(
            self,
            "previous_chain_digest",
            _normalize_optional_sha256(self.previous_chain_digest),
        )
        object.__setattr__(
            self,
            "chain_digest",
            _normalize_sha256(self.chain_digest),
        )
        object.__setattr__(
            self,
            "artifact_uri",
            _normalize_optional_relative_uri(self.artifact_uri),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))
        _require_aware_datetime(self.created_at, label="created_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "event_type": self.event_type.value,
            "summary": self.summary,
            "report_id": self.report_id,
            "bundle_id": self.bundle_id,
            "previous_receipt_id": self.previous_receipt_id,
            "previous_chain_digest": self.previous_chain_digest,
            "chain_digest": self.chain_digest,
            "created_at": self.created_at.isoformat(),
            "artifact_uri": self.artifact_uri,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ReliabilityArtifactBundle:
    """
    Persisted artifact bundle for one Wave 4 reliability lab run.
    """

    bundle_id: str
    report_id: str
    artifacts: tuple[ReliabilityArtifact, ...]
    receipts: tuple[ReliabilityReceipt, ...]
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "bundle_id",
            _normalize_token(self.bundle_id, label="bundle_id"),
        )
        object.__setattr__(
            self,
            "report_id",
            _normalize_token(self.report_id, label="report_id"),
        )
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        object.__setattr__(self, "receipts", tuple(self.receipts))
        object.__setattr__(self, "metadata", dict(self.metadata))
        _require_aware_datetime(self.created_at, label="created_at")

    @property
    def artifact_count(self) -> int:
        return len(self.artifacts)

    @property
    def receipt_count(self) -> int:
        return len(self.receipts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "report_id": self.report_id,
            "artifact_count": self.artifact_count,
            "receipt_count": self.receipt_count,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "receipts": [receipt.to_dict() for receipt in self.receipts],
            "created_at": self.created_at.isoformat(),
            "metadata": dict(self.metadata),
        }


class ReliabilityReceiptLedger:
    """
    Thread-safe chained receipt ledger for one reliability artifact bundle.
    """

    def __init__(self) -> None:
        self._receipts: list[ReliabilityReceipt] = []
        self._lock = RLock()

    def record(
        self,
        *,
        event_type: ReliabilityReceiptEventType,
        summary: str,
        report_id: str,
        bundle_id: str,
        artifact_uri: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> ReliabilityReceipt:
        with self._lock:
            previous = self._receipts[-1] if self._receipts else None
            previous_receipt_id = previous.receipt_id if previous else None
            previous_chain_digest = previous.chain_digest if previous else None
            created_at = datetime.now(tz=UTC)
            receipt_id = f"reliability-receipt-{uuid4().hex}"
            digest = _receipt_digest(
                receipt_id=receipt_id,
                event_type=event_type,
                summary=summary,
                report_id=report_id,
                bundle_id=bundle_id,
                previous_receipt_id=previous_receipt_id,
                previous_chain_digest=previous_chain_digest,
                created_at=created_at,
                artifact_uri=artifact_uri,
                metadata=dict(metadata or {}),
            )
            receipt = ReliabilityReceipt(
                receipt_id=receipt_id,
                event_type=event_type,
                summary=summary,
                report_id=report_id,
                bundle_id=bundle_id,
                previous_receipt_id=previous_receipt_id,
                previous_chain_digest=previous_chain_digest,
                chain_digest=digest,
                created_at=created_at,
                artifact_uri=artifact_uri,
                metadata=dict(metadata or {}),
            )
            self._receipts.append(receipt)
            return receipt

    def receipts(self) -> tuple[ReliabilityReceipt, ...]:
        with self._lock:
            return tuple(self._receipts)

    def to_dict(self) -> dict[str, Any]:
        receipts = self.receipts()
        return {
            "receipt_count": len(receipts),
            "receipts": [receipt.to_dict() for receipt in receipts],
        }


@dataclass(frozen=True, slots=True)
class ReliabilityArtifactStore:
    """
    Filesystem-backed store for Wave 4 reliability evidence bundles.

    The store writes only below artifact_root. Absolute paths, home-relative
    paths, and traversal are rejected so reliability reporting cannot be used as
    a host filesystem escape path.
    """

    artifact_root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifact_root", self.artifact_root.expanduser().resolve())

    def write_run_result(
        self,
        result: ReliabilityLabRunResult,
        *,
        bundle_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> ReliabilityArtifactBundle:
        effective_bundle_id = _normalize_token(
            bundle_id or f"reliability-bundle-{uuid4().hex}",
            label="bundle_id",
        )
        report_id = result.report.report_id
        bundle_root = f"reliability/{effective_bundle_id}"
        ledger = ReliabilityReceiptLedger()

        ledger.record(
            event_type=ReliabilityReceiptEventType.LAB_RUN_REPORTED,
            summary="Reliability lab run result accepted for artifact persistence.",
            report_id=report_id,
            bundle_id=effective_bundle_id,
            metadata={
                "decision": result.decision,
                "passed": result.passed,
                "suite_id": result.report.suite.suite_id,
            },
        )

        artifacts: list[ReliabilityArtifact] = []
        artifacts.append(
            self.write_json(
                relative_path=f"{bundle_root}/report.json",
                payload=result.report.to_dict(),
                metadata={"artifact_kind": "reliability-report"},
            )
        )
        artifacts.append(
            self.write_json(
                relative_path=f"{bundle_root}/metrics-summary.json",
                payload=result.metrics_summary.to_dict(),
                metadata={"artifact_kind": "reliability-metrics-summary"},
            )
        )
        artifacts.append(
            self.write_json(
                relative_path=f"{bundle_root}/observations.json",
                payload={
                    "observations": [
                        observation.to_dict()
                        for observation in result.observations
                    ]
                },
                metadata={"artifact_kind": "repair-metric-observations"},
            )
        )
        artifacts.append(
            self.write_json(
                relative_path=f"{bundle_root}/external-results.json",
                payload={
                    "external_results": [
                        scenario_result.to_dict()
                        for scenario_result in result.external_results
                    ]
                },
                metadata={"artifact_kind": "external-scenario-results"},
            )
        )

        for artifact in artifacts:
            ledger.record(
                event_type=ReliabilityReceiptEventType.ARTIFACT_WRITTEN,
                summary=f"Reliability artifact written: {artifact.uri}",
                report_id=report_id,
                bundle_id=effective_bundle_id,
                artifact_uri=artifact.uri,
                metadata=artifact.to_dict(),
            )

        receipts_artifact = self.write_json(
            relative_path=f"{bundle_root}/receipts.json",
            payload=ledger.to_dict(),
            metadata={"artifact_kind": "reliability-receipt-ledger"},
        )
        artifacts.append(receipts_artifact)

        ledger.record(
            event_type=ReliabilityReceiptEventType.ARTIFACT_WRITTEN,
            summary=f"Reliability receipt ledger written: {receipts_artifact.uri}",
            report_id=report_id,
            bundle_id=effective_bundle_id,
            artifact_uri=receipts_artifact.uri,
            metadata=receipts_artifact.to_dict(),
        )
        ledger.record(
            event_type=ReliabilityReceiptEventType.BUNDLE_FINALIZED,
            summary="Reliability artifact bundle finalized.",
            report_id=report_id,
            bundle_id=effective_bundle_id,
            metadata={
                "artifact_count": len(artifacts) + 1,
                "report_id": report_id,
            },
        )

        bundle = ReliabilityArtifactBundle(
            bundle_id=effective_bundle_id,
            report_id=report_id,
            artifacts=tuple(artifacts),
            receipts=ledger.receipts(),
            metadata={
                "artifact_root": str(self.artifact_root),
                "suite_id": result.report.suite.suite_id,
                "decision": result.decision,
                "passed": result.passed,
                **dict(metadata or {}),
            },
        )
        manifest_artifact = self.write_json(
            relative_path=f"{bundle_root}/manifest.json",
            payload=bundle.to_dict(),
            metadata={"artifact_kind": "reliability-bundle-manifest"},
        )
        return ReliabilityArtifactBundle(
            bundle_id=bundle.bundle_id,
            report_id=bundle.report_id,
            artifacts=(*bundle.artifacts, manifest_artifact),
            receipts=bundle.receipts,
            created_at=bundle.created_at,
            metadata={
                **dict(bundle.metadata),
                "manifest_uri": manifest_artifact.uri,
            },
        )

    def write_json(
        self,
        *,
        relative_path: str,
        payload: Mapping[str, Any],
        metadata: Mapping[str, Any] | None = None,
    ) -> ReliabilityArtifact:
        text = json.dumps(dict(payload), indent=2, sort_keys=True, ensure_ascii=False)
        return self.write_text(
            relative_path=relative_path,
            text=f"{text}\n",
            media_type="application/json",
            metadata=metadata,
        )

    def write_text(
        self,
        *,
        relative_path: str,
        text: str,
        media_type: str = "text/plain",
        metadata: Mapping[str, Any] | None = None,
    ) -> ReliabilityArtifact:
        payload = text.encode("utf-8")
        return self.write_bytes(
            relative_path=relative_path,
            payload=payload,
            media_type=media_type,
            metadata={"encoding": "utf-8", **dict(metadata or {})},
        )

    def write_bytes(
        self,
        *,
        relative_path: str,
        payload: bytes,
        media_type: str = "application/octet-stream",
        metadata: Mapping[str, Any] | None = None,
    ) -> ReliabilityArtifact:
        destination = self.resolve_relative_path(relative_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        uri = destination.relative_to(self.artifact_root).as_posix()
        return ReliabilityArtifact(
            name=destination.name,
            uri=uri,
            media_type=media_type,
            sha256=digest,
            size_bytes=len(payload),
            metadata={
                "artifact_root": str(self.artifact_root),
                "relative_path": uri,
                **dict(metadata or {}),
            },
        )

    def resolve_relative_path(self, relative_path: str) -> Path:
        cleaned = relative_path.strip().replace("\\", "/")
        if not cleaned:
            raise ReliabilityArtifactError("Artifact relative_path must not be empty.")
        if cleaned.startswith("/") or cleaned.startswith("~"):
            raise ReliabilityArtifactError(
                f"Artifact path must be relative: {relative_path!r}."
            )

        candidate = Path(cleaned)
        if candidate.is_absolute():
            raise ReliabilityArtifactError(
                f"Artifact path must be relative: {relative_path!r}."
            )

        destination = (self.artifact_root / candidate).resolve()
        if not _is_relative_to(destination, self.artifact_root):
            raise ReliabilityArtifactError(
                f"Artifact path escapes artifact root: {relative_path!r}."
            )
        return destination


def _receipt_digest(
    *,
    receipt_id: str,
    event_type: ReliabilityReceiptEventType,
    summary: str,
    report_id: str,
    bundle_id: str,
    previous_receipt_id: str | None,
    previous_chain_digest: str | None,
    created_at: datetime,
    artifact_uri: str | None,
    metadata: Mapping[str, Any],
) -> str:
    payload = {
        "receipt_id": receipt_id,
        "event_type": event_type.value,
        "summary": summary,
        "report_id": report_id,
        "bundle_id": bundle_id,
        "previous_receipt_id": previous_receipt_id,
        "previous_chain_digest": previous_chain_digest,
        "created_at": created_at.isoformat(),
        "artifact_uri": artifact_uri,
        "metadata": dict(metadata),
    }
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _normalize_relative_uri(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("uri must not be empty.")
    if cleaned.startswith("/") or cleaned.startswith("~") or "/../" in cleaned:
        raise ValueError(f"uri must be a safe relative path: {value!r}.")
    if cleaned == ".." or cleaned.startswith("../") or cleaned.endswith("/.."):
        raise ValueError(f"uri must be a safe relative path: {value!r}.")
    return cleaned


def _normalize_optional_relative_uri(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_relative_uri(value)


def _normalize_token(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace("_", "-").replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_token(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    return _normalize_token(value, label=label)


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_sha256(value: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) != 64:
        raise ValueError("SHA-256 digest must be 64 hexadecimal characters.")
    int(cleaned, 16)
    return cleaned


def _normalize_optional_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_sha256(value)


def _require_aware_datetime(value: datetime, *, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware.")


def _string_tuple(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(_normalize_text(value, label="value") for value in values)
