from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ix_blackfox.sandbox.contracts import (
    SandboxBackendKind,
    SandboxCommandRequest,
    SandboxCommandResult,
    SandboxExecutionStatus,
)
from ix_blackfox.sandbox.egress import SandboxEgressAuditBundle, network_policy_digest
from ix_blackfox.sandbox.workspace import SandboxArtifactManifest

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/#-]*$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")


@dataclass(frozen=True, slots=True)
class SandboxRunReceipt:
    receipt_id: str
    request_id: str
    profile_id: str
    profile_digest: str
    request_digest: str
    backend: SandboxBackendKind
    status: SandboxExecutionStatus
    passed: bool
    exit_code: int | None
    duration_ms: int
    network_policy_digest: str
    command_result_digest: str
    created_at: datetime
    expected_head_sha: str | None = None
    artifact_manifest_digest: str | None = None
    egress_audit_bundle_digest: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "receipt_id", _normalize_id(self.receipt_id, label="receipt_id"))
        object.__setattr__(self, "request_id", _normalize_id(self.request_id, label="request_id"))
        object.__setattr__(self, "profile_id", _normalize_id(self.profile_id, label="profile_id"))
        object.__setattr__(self, "profile_digest", _normalize_sha256(self.profile_digest, label="profile_digest"))
        object.__setattr__(self, "request_digest", _normalize_sha256(self.request_digest, label="request_digest"))
        if self.exit_code is not None and self.exit_code < 0:
            raise ValueError("exit_code must be non-negative when provided.")
        if self.duration_ms < 0:
            raise ValueError("duration_ms must be non-negative.")
        object.__setattr__(
            self,
            "network_policy_digest",
            _normalize_sha256(self.network_policy_digest, label="network_policy_digest"),
        )
        object.__setattr__(
            self,
            "command_result_digest",
            _normalize_sha256(self.command_result_digest, label="command_result_digest"),
        )
        _require_aware_datetime(self.created_at, label="created_at")
        object.__setattr__(
            self,
            "expected_head_sha",
            _normalize_optional_sha(self.expected_head_sha, label="expected_head_sha"),
        )
        object.__setattr__(
            self,
            "artifact_manifest_digest",
            _normalize_optional_sha256(
                self.artifact_manifest_digest,
                label="artifact_manifest_digest",
            ),
        )
        object.__setattr__(
            self,
            "egress_audit_bundle_digest",
            _normalize_optional_sha256(
                self.egress_audit_bundle_digest,
                label="egress_audit_bundle_digest",
            ),
        )
        object.__setattr__(self, "metadata", _normalize_str_mapping(self.metadata, label="metadata"))

    @property
    def digest(self) -> str:
        return _sha256_json(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "profile_id": self.profile_id,
            "profile_digest": self.profile_digest,
            "request_digest": self.request_digest,
            "backend": self.backend.value,
            "status": self.status.value,
            "passed": self.passed,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "network_policy_digest": self.network_policy_digest,
            "command_result_digest": self.command_result_digest,
            "created_at": self.created_at.isoformat(),
            "expected_head_sha": self.expected_head_sha,
            "artifact_manifest_digest": self.artifact_manifest_digest,
            "egress_audit_bundle_digest": self.egress_audit_bundle_digest,
            "metadata": dict(sorted(self.metadata.items())),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class SandboxReceiptBundle:
    bundle_id: str
    created_at: datetime
    receipts: tuple[SandboxRunReceipt, ...]
    expected_head_sha: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "bundle_id", _normalize_id(self.bundle_id, label="bundle_id"))
        _require_aware_datetime(self.created_at, label="created_at")
        object.__setattr__(self, "receipts", tuple(sorted(self.receipts, key=lambda item: item.receipt_id)))
        object.__setattr__(
            self,
            "expected_head_sha",
            _normalize_optional_sha(self.expected_head_sha, label="expected_head_sha"),
        )
        object.__setattr__(self, "metadata", _normalize_str_mapping(self.metadata, label="metadata"))
        receipt_ids = tuple(receipt.receipt_id for receipt in self.receipts)
        if len(set(receipt_ids)) != len(receipt_ids):
            raise ValueError("sandbox receipt bundle must not contain duplicate receipt_id values.")
        if self.expected_head_sha is not None:
            for receipt in self.receipts:
                if receipt.expected_head_sha != self.expected_head_sha:
                    raise ValueError("sandbox receipt expected_head_sha does not match bundle expected_head_sha.")

    @property
    def passed(self) -> bool:
        return bool(self.receipts) and all(receipt.passed for receipt in self.receipts)

    @property
    def receipt_count(self) -> int:
        return len(self.receipts)

    @property
    def passed_count(self) -> int:
        return sum(1 for receipt in self.receipts if receipt.passed)

    @property
    def failed_count(self) -> int:
        return sum(1 for receipt in self.receipts if not receipt.passed)

    @property
    def digest(self) -> str:
        return _sha256_json(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "bundle_id": self.bundle_id,
            "created_at": self.created_at.isoformat(),
            "expected_head_sha": self.expected_head_sha,
            "passed": self.passed,
            "receipt_count": self.receipt_count,
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "receipts": [receipt.to_dict() for receipt in self.receipts],
            "metadata": dict(sorted(self.metadata.items())),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class SandboxRunReceiptBuilder:
    def build(
        self,
        *,
        request: SandboxCommandRequest,
        result: SandboxCommandResult,
        artifact_manifest: SandboxArtifactManifest | None = None,
        egress_audit_bundle: SandboxEgressAuditBundle | None = None,
        receipt_id: str | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> SandboxRunReceipt:
        if result.request_id != request.request_id:
            raise ValueError("sandbox result request_id does not match command request.")
        if artifact_manifest is not None:
            _validate_artifact_manifest(request, result, artifact_manifest)
        if egress_audit_bundle is not None:
            _validate_egress_audit_bundle(request, egress_audit_bundle)
        command_result_digest = _sha256_json(result.to_dict())
        return SandboxRunReceipt(
            receipt_id=receipt_id if receipt_id is not None else f"receipt-{request.request_id}",
            request_id=request.request_id,
            profile_id=request.profile.profile_id,
            profile_digest=request.profile.digest,
            request_digest=request.digest,
            backend=request.profile.backend,
            status=result.status,
            passed=result.passed,
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
            network_policy_digest=network_policy_digest(request.profile.network),
            command_result_digest=command_result_digest,
            created_at=datetime.now(tz=UTC),
            expected_head_sha=request.expected_head_sha,
            artifact_manifest_digest=artifact_manifest.digest if artifact_manifest is not None else None,
            egress_audit_bundle_digest=egress_audit_bundle.digest if egress_audit_bundle is not None else None,
            metadata=metadata if metadata is not None else {"builder": "wave6.sandbox.receipt"},
        )


def _validate_artifact_manifest(
    request: SandboxCommandRequest,
    result: SandboxCommandResult,
    artifact_manifest: SandboxArtifactManifest,
) -> None:
    if artifact_manifest.profile_id != request.profile.profile_id:
        raise ValueError("artifact manifest profile_id does not match sandbox request profile_id.")
    if artifact_manifest.profile_digest != request.profile.digest:
        raise ValueError("artifact manifest profile_digest does not match sandbox request profile_digest.")
    if result.artifact_manifest_sha256 is not None and result.artifact_manifest_sha256 != artifact_manifest.digest:
        raise ValueError("sandbox result artifact_manifest_sha256 does not match artifact manifest digest.")


def _validate_egress_audit_bundle(
    request: SandboxCommandRequest,
    egress_audit_bundle: SandboxEgressAuditBundle,
) -> None:
    if egress_audit_bundle.profile_id != request.profile.profile_id:
        raise ValueError("egress audit bundle profile_id does not match sandbox request profile_id.")
    if egress_audit_bundle.profile_digest != request.profile.digest:
        raise ValueError("egress audit bundle profile_digest does not match sandbox request profile_digest.")
    expected_policy_digest = network_policy_digest(request.profile.network)
    if egress_audit_bundle.network_policy_digest != expected_policy_digest:
        raise ValueError("egress audit bundle network_policy_digest does not match sandbox request network policy.")


def _sha256_json(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalize_id(value: str, *, label: str) -> str:
    cleaned = _normalize_text(value, label=label)
    if not _SAFE_ID_RE.fullmatch(cleaned):
        raise ValueError(f"{label} contains unsupported characters.")
    if ".." in cleaned:
        raise ValueError(f"{label} must not contain '..'.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_sha256(value: str, *, label: str) -> str:
    cleaned = _normalize_text(value.lower(), label=label)
    if not _SHA256_RE.fullmatch(cleaned):
        raise ValueError(f"{label} must be a 64-character lowercase SHA-256 digest.")
    return cleaned


def _normalize_optional_sha256(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    return _normalize_sha256(value, label=label)


def _normalize_optional_sha(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    cleaned = _normalize_text(value.lower(), label=label)
    if not _HEX_SHA_RE.fullmatch(cleaned):
        raise ValueError(f"{label} must be a hexadecimal commit identifier.")
    return cleaned


def _normalize_str_mapping(values: Mapping[str, str], *, label: str) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in values.items():
        normalized[_normalize_id(key, label=f"{label}_key")] = _normalize_text(value, label=f"{label}_value")
    return dict(sorted(normalized.items()))


def _require_aware_datetime(value: datetime, *, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware.")
