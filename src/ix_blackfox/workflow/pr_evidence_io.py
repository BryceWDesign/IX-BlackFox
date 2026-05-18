from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from ix_blackfox.workflow.pr_evidence_pack import (
    ArtifactAttestation,
    ArtifactAttestationKind,
    EvidenceArtifact,
    EvidenceArtifactKind,
    PullRequestApproval,
    PullRequestEvidencePack,
    PullRequestIdentity,
    ReviewDecision,
    ReviewerKind,
)


class PullRequestEvidencePackNormalizer:
    def from_file(self, path: Path) -> PullRequestEvidencePack:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, Mapping):
            raise ValueError("PR evidence pack JSON must be an object.")
        return self.from_mapping(cast(Mapping[str, Any], payload))

    def from_mapping(self, payload: Mapping[str, Any]) -> PullRequestEvidencePack:
        artifacts_payload = _require_sequence(payload, "artifacts")
        approvals_payload = _optional_sequence(payload.get("approvals"), key="approvals")
        return PullRequestEvidencePack(
            pack_id=_require_str(payload, "pack_id"),
            pull_request=self.pull_request_from_mapping(
                _require_mapping(payload, "pull_request")
            ),
            created_at=_parse_datetime(
                _require_str(payload, "created_at"),
                label="created_at",
            ),
            summary=_require_str(payload, "summary"),
            changed_files=tuple(
                _require_str_value(value, "changed_files")
                for value in _require_sequence(payload, "changed_files")
            ),
            requested_checks=tuple(
                _require_str_value(value, "requested_checks")
                for value in _require_sequence(payload, "requested_checks")
            ),
            artifacts=tuple(
                self.artifact_from_mapping(artifact) for artifact in artifacts_payload
            ),
            approvals=tuple(
                self.approval_from_mapping(approval) for approval in approvals_payload
            ),
            metadata=_optional_mapping(payload.get("metadata")),
        )

    def pull_request_from_mapping(self, payload: Mapping[str, Any]) -> PullRequestIdentity:
        return PullRequestIdentity(
            provider=_require_str(payload, "provider"),
            repository=_require_str(payload, "repository"),
            pull_request_id=_require_str(payload, "pull_request_id"),
            base_ref=_require_str(payload, "base_ref"),
            head_ref=_require_str(payload, "head_ref"),
            head_sha=_require_str(payload, "head_sha"),
            author=_require_str(payload, "author"),
        )

    def artifact_from_mapping(self, payload: Any) -> EvidenceArtifact:
        if not isinstance(payload, Mapping):
            raise ValueError("artifact entries must be JSON objects.")
        artifact = cast(Mapping[str, Any], payload)
        return EvidenceArtifact(
            artifact_id=_require_str(artifact, "artifact_id"),
            kind=_artifact_kind_from_value(_require_str(artifact, "kind")),
            uri=_require_str(artifact, "uri"),
            produced_by=_require_str(artifact, "produced_by"),
            sha256=_optional_str(artifact.get("sha256"), label="sha256"),
            size_bytes=_optional_int(artifact.get("size_bytes"), label="size_bytes"),
            head_sha=_optional_str(artifact.get("head_sha"), label="head_sha"),
            attestations=tuple(
                self.attestation_from_mapping(attestation)
                for attestation in _optional_sequence(
                    artifact.get("attestations"),
                    key="attestations",
                )
            ),
            metadata=_optional_mapping(artifact.get("metadata")),
        )

    def attestation_from_mapping(self, payload: Any) -> ArtifactAttestation:
        if not isinstance(payload, Mapping):
            raise ValueError("attestation entries must be JSON objects.")
        attestation = cast(Mapping[str, Any], payload)
        return ArtifactAttestation(
            attestation_id=_require_str(attestation, "attestation_id"),
            kind=_attestation_kind_from_value(_require_str(attestation, "kind")),
            uri=_require_str(attestation, "uri"),
            produced_by=_require_str(attestation, "produced_by"),
            predicate_type=_require_str(attestation, "predicate_type"),
            sha256=_require_str(attestation, "sha256"),
            size_bytes=_require_int(attestation, "size_bytes"),
            head_sha=_require_str(attestation, "head_sha"),
            subject_sha256=_require_str(attestation, "subject_sha256"),
            verified=_optional_bool(attestation.get("verified"), default=False, label="verified"),
            metadata=_optional_mapping(attestation.get("metadata")),
        )

    def approval_from_mapping(self, payload: Any) -> PullRequestApproval:
        if not isinstance(payload, Mapping):
            raise ValueError("approval entries must be JSON objects.")
        approval = cast(Mapping[str, Any], payload)
        return PullRequestApproval(
            approval_id=_require_str(approval, "approval_id"),
            reviewer_id=_require_str(approval, "reviewer_id"),
            reviewer_kind=_reviewer_kind_from_value(
                _require_str(approval, "reviewer_kind")
            ),
            decision=_review_decision_from_value(_require_str(approval, "decision")),
            decided_at=_parse_datetime(
                _require_str(approval, "decided_at"),
                label="decided_at",
            ),
            note=_require_str(approval, "note"),
            evidence_refs=tuple(
                _require_str_value(value, "evidence_refs")
                for value in _optional_sequence(
                    approval.get("evidence_refs"),
                    key="evidence_refs",
                )
            ),
            roles=tuple(
                _require_str_value(value, "roles")
                for value in _optional_sequence(approval.get("roles"), key="roles")
            ),
        )


def load_pr_evidence_pack(path: Path) -> PullRequestEvidencePack:
    return PullRequestEvidencePackNormalizer().from_file(path)


def _artifact_kind_from_value(value: str) -> EvidenceArtifactKind:
    cleaned = _enum_value(value)
    try:
        return EvidenceArtifactKind(cleaned)
    except ValueError as exc:
        raise ValueError(f"unsupported evidence artifact kind: {value!r}.") from exc


def _attestation_kind_from_value(value: str) -> ArtifactAttestationKind:
    cleaned = _enum_value(value)
    try:
        return ArtifactAttestationKind(cleaned)
    except ValueError as exc:
        raise ValueError(f"unsupported artifact attestation kind: {value!r}.") from exc


def _reviewer_kind_from_value(value: str) -> ReviewerKind:
    cleaned = _enum_value(value)
    try:
        return ReviewerKind(cleaned)
    except ValueError as exc:
        raise ValueError(f"unsupported reviewer kind: {value!r}.") from exc


def _review_decision_from_value(value: str) -> ReviewDecision:
    cleaned = _enum_value(value)
    try:
        return ReviewDecision(cleaned)
    except ValueError as exc:
        raise ValueError(f"unsupported review decision: {value!r}.") from exc


def _enum_value(value: str) -> str:
    return value.strip().lower().replace("-", "_")


def _parse_datetime(value: str, *, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid ISO datetime string.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware.")
    return parsed.astimezone(UTC)


def _require_mapping(payload: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = payload.get(key)
    if not isinstance(value, Mapping):
        raise ValueError(f"PR evidence pack field '{key}' must be an object.")
    return cast(Mapping[str, Any], value)


def _require_sequence(payload: Mapping[str, Any], key: str) -> Sequence[Any]:
    value = payload.get(key)
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise ValueError(f"PR evidence pack field '{key}' must be a list.")
    return value


def _optional_sequence(value: Any, *, key: str) -> Sequence[Any]:
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise ValueError(f"PR evidence pack field '{key}' must be a list when provided.")
    return value


def _require_str(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError(f"PR evidence pack field '{key}' must be a string.")
    return value


def _require_int(payload: Mapping[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"PR evidence pack field '{key}' must be an integer.")
    return value


def _require_str_value(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} entries must be strings.")
    return value


def _optional_str(value: Any, *, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string when provided.")
    return value


def _optional_int(value: Any, *, label: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} must be an integer when provided.")
    return value


def _optional_bool(value: Any, *, default: bool, label: str) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean when provided.")
    return value


def _optional_mapping(value: Any) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("metadata must be an object when provided.")
    normalized: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError("metadata keys must be strings.")
        normalized[key] = item
    return normalized
