from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ix_blackfox.live_gateway.models import (
    WAVE14_EVIDENCE_SCHEMA_VERSION,
    AuthoritySubject,
    EvidenceEvaluation,
    EvidenceIssue,
    EvidenceVerification,
)
from ix_blackfox.operating.models import digest_payload

_EVIDENCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DEFAULT_MAX_EVIDENCE_BYTES = 1 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class TrustedEvidenceIssuer:
    """Trusted HMAC issuer key loaded through an environment-backed config boundary."""

    issuer: str
    key_id: str
    secret_env: str
    allowed_kinds: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.issuer.strip() or not self.key_id.strip() or not self.secret_env.strip():
            raise ValueError("TrustedEvidenceIssuer fields must not be empty.")
        normalized = tuple(sorted({kind.strip() for kind in self.allowed_kinds if kind.strip()}))
        if not normalized:
            raise ValueError("TrustedEvidenceIssuer allowed_kinds must not be empty.")
        object.__setattr__(self, "allowed_kinds", normalized)

    def to_dict(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "key_id": self.key_id,
            "secret_env": self.secret_env,
            "allowed_kinds": list(self.allowed_kinds),
        }


@dataclass(frozen=True, slots=True)
class EvidencePolicy:
    """Evidence conditions that must hold before a configured tool can execute."""

    policy_id: str
    required_kinds: tuple[str, ...] = ()
    human_approval_kind: str = ""
    target_bound_kinds: tuple[str, ...] = ()
    single_use_kinds: tuple[str, ...] = ()
    accepted_statuses: tuple[str, ...] = ("passed", "approved", "verified")
    allowed_issuers: tuple[str, ...] = ()
    human_approval_issuers: tuple[str, ...] = ()
    max_age_seconds: int = 3600
    require_signature: bool = True
    require_repository_match: bool = True
    require_revision_match: bool = True

    def __post_init__(self) -> None:
        if not self.policy_id.strip():
            raise ValueError("EvidencePolicy policy_id must not be empty.")
        for field_name, values in (
            ("required_kinds", self.required_kinds),
            ("target_bound_kinds", self.target_bound_kinds),
            ("single_use_kinds", self.single_use_kinds),
            ("accepted_statuses", self.accepted_statuses),
            ("allowed_issuers", self.allowed_issuers),
            ("human_approval_issuers", self.human_approval_issuers),
        ):
            normalized = tuple(sorted({value.strip() for value in values if value.strip()}))
            object.__setattr__(self, field_name, normalized)
        object.__setattr__(self, "human_approval_kind", self.human_approval_kind.strip())
        if self.human_approval_kind:
            if not self.require_signature:
                raise ValueError("Human approval evidence must require signatures.")
            if self.human_approval_kind not in self.target_bound_kinds:
                raise ValueError("Human approval evidence must be exact-subject bound.")
            if not self.human_approval_issuers:
                raise ValueError("Human approval evidence must name trusted human approval issuers.")
            if self.human_approval_kind not in self.single_use_kinds:
                raise ValueError("Human approval evidence must be single-use to prevent replay.")
            if self.allowed_issuers and not set(self.human_approval_issuers).issubset(
                set(self.allowed_issuers)
            ):
                raise ValueError("human_approval_issuers must be included in allowed_issuers.")
        if not set(self.single_use_kinds).issubset(set(self.target_bound_kinds)):
            raise ValueError("single_use_kinds must also be exact-subject target_bound_kinds.")
        if self.max_age_seconds <= 0:
            raise ValueError("EvidencePolicy max_age_seconds must be positive.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "required_kinds": list(self.required_kinds),
            "human_approval_kind": self.human_approval_kind,
            "target_bound_kinds": list(self.target_bound_kinds),
            "single_use_kinds": list(self.single_use_kinds),
            "accepted_statuses": list(self.accepted_statuses),
            "allowed_issuers": list(self.allowed_issuers),
            "human_approval_issuers": list(self.human_approval_issuers),
            "max_age_seconds": self.max_age_seconds,
            "require_signature": self.require_signature,
            "require_repository_match": self.require_repository_match,
            "require_revision_match": self.require_revision_match,
        }


@dataclass(frozen=True, slots=True)
class SignedEvidenceArtifact:
    """HMAC-authenticated evidence bound to repository/revision and optional exact action."""

    evidence_id: str
    kind: str
    issuer: str
    key_id: str
    status: str
    repository_id: str
    revision: str
    produced_at: str
    target_digest: str = ""
    payload: Mapping[str, Any] = field(default_factory=dict)
    digest: str = ""
    signature: str = ""

    def __post_init__(self) -> None:
        if not _EVIDENCE_ID.fullmatch(self.evidence_id):
            raise ValueError("Invalid evidence_id.")
        for label, value in (
            ("kind", self.kind),
            ("issuer", self.issuer),
            ("key_id", self.key_id),
            ("status", self.status),
            ("repository_id", self.repository_id),
            ("revision", self.revision),
            ("produced_at", self.produced_at),
        ):
            if not value.strip():
                raise ValueError(f"{label} must not be empty.")
        if self.target_digest and not _HEX_SHA256.fullmatch(self.target_digest):
            raise ValueError("target_digest must be a lowercase SHA-256 digest.")
        if self.digest and not _HEX_SHA256.fullmatch(self.digest):
            raise ValueError("digest must be a lowercase SHA-256 digest.")
        if self.signature and not _HEX_SHA256.fullmatch(self.signature):
            raise ValueError("signature must be a lowercase HMAC-SHA256 value.")
        object.__setattr__(self, "payload", dict(self.payload))
        _parse_timestamp(self.produced_at)

    def unsigned_payload(self) -> dict[str, Any]:
        return {
            "schema_version": WAVE14_EVIDENCE_SCHEMA_VERSION,
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "issuer": self.issuer,
            "key_id": self.key_id,
            "status": self.status,
            "repository_id": self.repository_id,
            "revision": self.revision,
            "produced_at": self.produced_at,
            "target_digest": self.target_digest,
            "payload": dict(self.payload),
        }

    @property
    def computed_digest(self) -> str:
        return digest_payload(self.unsigned_payload())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.unsigned_payload(),
            "digest": self.digest or self.computed_digest,
            "signature": self.signature,
        }

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> SignedEvidenceArtifact:
        if payload.get("schema_version") != WAVE14_EVIDENCE_SCHEMA_VERSION:
            raise ValueError("Unsupported Wave 14 evidence schema_version.")
        raw_payload = payload.get("payload", {})
        if not isinstance(raw_payload, Mapping):
            raise ValueError("Evidence payload must be an object.")
        return cls(
            evidence_id=_text(payload, "evidence_id"),
            kind=_text(payload, "kind"),
            issuer=_text(payload, "issuer"),
            key_id=_text(payload, "key_id"),
            status=_text(payload, "status"),
            repository_id=_text(payload, "repository_id"),
            revision=_text(payload, "revision"),
            produced_at=_text(payload, "produced_at"),
            target_digest=str(payload.get("target_digest", "")),
            payload=dict(raw_payload),
            digest=_text(payload, "digest"),
            signature=str(payload.get("signature", "")),
        )


@dataclass(slots=True)
class EvidenceStore:
    """Filesystem evidence store with traversal protection and cryptographic verification."""

    root: Path
    trusted_keys: Mapping[tuple[str, str], bytes]
    trusted_issuer_kinds: Mapping[tuple[str, str], tuple[str, ...]] = field(default_factory=dict)
    max_evidence_bytes: int = _DEFAULT_MAX_EVIDENCE_BYTES

    def __post_init__(self) -> None:
        self.root = self.root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.trusted_keys = dict(self.trusted_keys)
        self.trusted_issuer_kinds = {
            key: tuple(sorted(set(kinds)))
            for key, kinds in self.trusted_issuer_kinds.items()
        }
        if self.max_evidence_bytes <= 0:
            raise ValueError("max_evidence_bytes must be positive.")

    def write(self, artifact: SignedEvidenceArtifact) -> Path:
        path = self._path_for(artifact.evidence_id)
        body = json.dumps(
            artifact.to_dict(),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        ) + "\n"
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(body, encoding="utf-8")
        temporary.replace(path)
        return path

    def load(self, evidence_id: str) -> SignedEvidenceArtifact:
        path = self._path_for(evidence_id)
        if path.stat().st_size > self.max_evidence_bytes:
            raise ValueError("Evidence artifact exceeded the configured size limit.")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, Mapping):
            raise ValueError("Evidence artifact root must be an object.")
        return SignedEvidenceArtifact.from_mapping(payload)

    def verify_many(
        self,
        evidence_ids: Sequence[str],
        *,
        subject: AuthoritySubject,
        policy: EvidencePolicy,
        now: datetime | None = None,
    ) -> EvidenceEvaluation:
        when = now or datetime.now(tz=UTC)
        verifications: list[EvidenceVerification] = []
        valid_by_kind: dict[str, list[SignedEvidenceArtifact]] = {}
        global_issues: list[EvidenceIssue] = []

        for evidence_id in tuple(dict.fromkeys(evidence_ids)):
            verification, artifact = self.verify_one(
                evidence_id,
                subject=subject,
                policy=policy,
                now=when,
            )
            verifications.append(verification)
            if verification.passed and artifact is not None:
                valid_by_kind.setdefault(artifact.kind, []).append(artifact)

        missing = tuple(
            kind for kind in policy.required_kinds if not valid_by_kind.get(kind)
        )
        for kind in missing:
            global_issues.append(
                EvidenceIssue(
                    code="required_evidence_missing",
                    summary=f"Required evidence kind is missing or invalid: {kind}.",
                )
            )

        human_approval = False
        if policy.human_approval_kind:
            for artifact in valid_by_kind.get(policy.human_approval_kind, []):
                decision = str(artifact.payload.get("decision", "")).strip().lower()
                reviewer_kind = str(artifact.payload.get("reviewer_kind", "")).strip().lower()
                reviewer_id = str(artifact.payload.get("reviewer_id", "")).strip()
                if (
                    artifact.status.lower() == "approved"
                    and decision == "approve"
                    and reviewer_kind == "human"
                    and reviewer_id
                ):
                    human_approval = True
                    break

        valid_ids = tuple(
            sorted(
                verification.evidence_id
                for verification in verifications
                if verification.passed
            )
        )
        return EvidenceEvaluation(
            policy_id=policy.policy_id,
            required_kinds=policy.required_kinds,
            valid_evidence_ids=valid_ids,
            missing_kinds=missing,
            human_approval_satisfied=human_approval,
            verifications=tuple(verifications),
            issues=tuple(global_issues),
        )

    def verify_one(
        self,
        evidence_id: str,
        *,
        subject: AuthoritySubject,
        policy: EvidencePolicy,
        now: datetime,
    ) -> tuple[EvidenceVerification, SignedEvidenceArtifact | None]:
        issues: list[EvidenceIssue] = []
        try:
            artifact = self.load(evidence_id)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            issue = EvidenceIssue(
                code="evidence_load_failed",
                summary=f"Evidence could not be loaded: {exc}",
                evidence_id=evidence_id,
            )
            return (
                EvidenceVerification(
                    evidence_id=evidence_id,
                    kind="",
                    issuer="",
                    passed=False,
                    issues=(issue,),
                ),
                None,
            )

        if artifact.evidence_id != evidence_id:
            issues.append(_issue("evidence_id_mismatch", "Evidence id does not match requested reference.", artifact))
        if artifact.digest != artifact.computed_digest:
            issues.append(_issue("evidence_digest_mismatch", "Evidence canonical digest is invalid.", artifact))

        key = self.trusted_keys.get((artifact.issuer, artifact.key_id))
        if policy.require_signature:
            if key is None:
                issues.append(_issue("evidence_issuer_untrusted", "Evidence issuer/key is not trusted by the gateway.", artifact))
            else:
                expected = hmac.new(key, artifact.digest.encode("ascii"), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, artifact.signature):
                    issues.append(_issue("evidence_signature_invalid", "Evidence HMAC signature is invalid.", artifact))

        allowed_kinds = self.trusted_issuer_kinds.get((artifact.issuer, artifact.key_id), ())
        if allowed_kinds and artifact.kind not in allowed_kinds:
            issues.append(
                _issue(
                    "evidence_kind_not_allowed_for_issuer",
                    "Evidence issuer/key is not trusted to assert this evidence kind.",
                    artifact,
                    {"allowed_kinds": list(allowed_kinds)},
                )
            )
        if policy.allowed_issuers and artifact.issuer not in policy.allowed_issuers:
            issues.append(_issue("evidence_issuer_not_allowed", "Evidence issuer is not allowed by this policy.", artifact))
        if (
            policy.human_approval_kind
            and artifact.kind == policy.human_approval_kind
            and artifact.issuer not in policy.human_approval_issuers
        ):
            issues.append(
                _issue(
                    "human_approval_issuer_not_allowed",
                    "Human approval evidence was not issued by a configured human authority issuer.",
                    artifact,
                )
            )
        if artifact.status.lower() not in {status.lower() for status in policy.accepted_statuses}:
            issues.append(_issue("evidence_status_rejected", "Evidence status is not accepted by policy.", artifact))
        if policy.require_repository_match and artifact.repository_id != subject.repository_id:
            issues.append(_issue("evidence_repository_mismatch", "Evidence repository does not match the authority subject.", artifact))
        if policy.require_revision_match and artifact.revision != subject.revision:
            issues.append(_issue("evidence_revision_mismatch", "Evidence revision does not match the authority subject.", artifact))
        if artifact.kind in policy.target_bound_kinds and artifact.target_digest != subject.digest:
            issues.append(_issue("evidence_target_mismatch", "Evidence is not bound to the exact authority subject.", artifact))

        age_seconds = (now - _parse_timestamp(artifact.produced_at)).total_seconds()
        if age_seconds < -300:
            issues.append(_issue("evidence_from_future", "Evidence timestamp is materially in the future.", artifact))
        elif age_seconds > policy.max_age_seconds:
            issues.append(_issue("evidence_stale", "Evidence exceeds the configured maximum age.", artifact, {"age_seconds": age_seconds}))

        passed = not issues
        return (
            EvidenceVerification(
                evidence_id=artifact.evidence_id,
                kind=artifact.kind,
                issuer=artifact.issuer,
                passed=passed,
                digest=artifact.digest,
                status=artifact.status,
                issues=tuple(issues),
            ),
            artifact,
        )

    def _path_for(self, evidence_id: str) -> Path:
        if not _EVIDENCE_ID.fullmatch(evidence_id):
            raise ValueError("Invalid evidence id.")
        path = (self.root / f"{evidence_id}.json").resolve()
        if path.parent != self.root:
            raise ValueError("Evidence path escaped the configured evidence root.")
        return path


def issue_signed_evidence(
    *,
    evidence_id: str,
    kind: str,
    issuer: str,
    key_id: str,
    secret: bytes,
    status: str,
    repository_id: str,
    revision: str,
    target_digest: str = "",
    payload: Mapping[str, Any] | None = None,
    produced_at: str | None = None,
) -> SignedEvidenceArtifact:
    """Create one canonical HMAC-authenticated evidence artifact."""

    timestamp = produced_at or datetime.now(tz=UTC).isoformat()
    unsigned = SignedEvidenceArtifact(
        evidence_id=evidence_id,
        kind=kind,
        issuer=issuer,
        key_id=key_id,
        status=status,
        repository_id=repository_id,
        revision=revision,
        produced_at=timestamp,
        target_digest=target_digest,
        payload={} if payload is None else dict(payload),
    )
    digest = unsigned.computed_digest
    signature = hmac.new(secret, digest.encode("ascii"), hashlib.sha256).hexdigest()
    return SignedEvidenceArtifact(
        evidence_id=unsigned.evidence_id,
        kind=unsigned.kind,
        issuer=unsigned.issuer,
        key_id=unsigned.key_id,
        status=unsigned.status,
        repository_id=unsigned.repository_id,
        revision=unsigned.revision,
        produced_at=unsigned.produced_at,
        target_digest=unsigned.target_digest,
        payload=unsigned.payload,
        digest=digest,
        signature=signature,
    )


def _issue(
    code: str,
    summary: str,
    artifact: SignedEvidenceArtifact,
    metadata: Mapping[str, Any] | None = None,
) -> EvidenceIssue:
    return EvidenceIssue(
        code=code,
        summary=summary,
        evidence_id=artifact.evidence_id,
        metadata={} if metadata is None else dict(metadata),
    )


def _text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Evidence field {key!r} must be a non-empty string.")
    return value.strip()


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Evidence produced_at must be timezone-aware.")
    return parsed.astimezone(UTC)
