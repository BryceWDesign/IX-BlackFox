from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.sandbox.contracts import (
    SandboxCommandRequest,
    SandboxNetworkAllowRule,
    SandboxNetworkMode,
    SandboxNetworkPolicy,
    SandboxProfile,
)

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/#-]*$")
_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class SandboxEgressDecisionStatus(StrEnum):
    ALLOWED = auto()
    ALLOWED_VIA_PROXY = auto()
    DENIED = auto()
    OFFLINE_CACHE_ONLY = auto()


@dataclass(frozen=True, slots=True)
class SandboxEgressRequest:
    request_id: str
    host: str
    port: int
    protocol: str = "tcp"
    purpose: str = "unspecified sandbox egress request"
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", _normalize_id(self.request_id, label="request_id"))
        object.__setattr__(self, "host", _normalize_host(self.host))
        _require_port(self.port)
        object.__setattr__(self, "protocol", _normalize_protocol(self.protocol))
        object.__setattr__(self, "purpose", _normalize_text(self.purpose, label="purpose"))
        object.__setattr__(self, "metadata", _normalize_str_mapping(self.metadata, label="metadata"))

    @property
    def endpoint_key(self) -> tuple[str, str, int]:
        return (self.protocol, self.host, self.port)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "purpose": self.purpose,
            "metadata": dict(sorted(self.metadata.items())),
        }


@dataclass(frozen=True, slots=True)
class SandboxEgressDecision:
    decision_id: str
    profile_id: str
    profile_digest: str
    network_policy_digest: str
    network_mode: SandboxNetworkMode
    request: SandboxEgressRequest
    status: SandboxEgressDecisionStatus
    reason: str
    evaluated_at: datetime
    matched_rule: SandboxNetworkAllowRule | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision_id", _normalize_id(self.decision_id, label="decision_id"))
        object.__setattr__(self, "profile_id", _normalize_id(self.profile_id, label="profile_id"))
        object.__setattr__(self, "profile_digest", _normalize_sha256(self.profile_digest, label="profile_digest"))
        object.__setattr__(
            self,
            "network_policy_digest",
            _normalize_sha256(self.network_policy_digest, label="network_policy_digest"),
        )
        object.__setattr__(self, "reason", _normalize_text(self.reason, label="reason"))
        _require_aware_datetime(self.evaluated_at, label="evaluated_at")
        object.__setattr__(self, "metadata", _normalize_str_mapping(self.metadata, label="metadata"))
        if self.status is SandboxEgressDecisionStatus.ALLOWED and self.matched_rule is None:
            raise ValueError("allowed egress decisions require a matched_rule.")
        if self.status is SandboxEgressDecisionStatus.ALLOWED_VIA_PROXY and self.matched_rule is None:
            raise ValueError("proxy egress decisions require a matched_rule.")

    @property
    def allowed(self) -> bool:
        return self.status in (
            SandboxEgressDecisionStatus.ALLOWED,
            SandboxEgressDecisionStatus.ALLOWED_VIA_PROXY,
        )

    @property
    def digest(self) -> str:
        return _sha256_json(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "decision_id": self.decision_id,
            "profile_id": self.profile_id,
            "profile_digest": self.profile_digest,
            "network_policy_digest": self.network_policy_digest,
            "network_mode": self.network_mode.value,
            "request": self.request.to_dict(),
            "status": self.status.value,
            "allowed": self.allowed,
            "reason": self.reason,
            "evaluated_at": self.evaluated_at.isoformat(),
            "matched_rule": self.matched_rule.to_dict() if self.matched_rule is not None else None,
            "metadata": dict(sorted(self.metadata.items())),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class SandboxEgressAuditBundle:
    bundle_id: str
    profile_id: str
    profile_digest: str
    network_policy_digest: str
    created_at: datetime
    decisions: tuple[SandboxEgressDecision, ...] = field(default_factory=tuple)
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "bundle_id", _normalize_id(self.bundle_id, label="bundle_id"))
        object.__setattr__(self, "profile_id", _normalize_id(self.profile_id, label="profile_id"))
        object.__setattr__(self, "profile_digest", _normalize_sha256(self.profile_digest, label="profile_digest"))
        object.__setattr__(
            self,
            "network_policy_digest",
            _normalize_sha256(self.network_policy_digest, label="network_policy_digest"),
        )
        _require_aware_datetime(self.created_at, label="created_at")
        object.__setattr__(self, "decisions", tuple(self.decisions))
        object.__setattr__(self, "metadata", _normalize_str_mapping(self.metadata, label="metadata"))
        for decision in self.decisions:
            if decision.profile_digest != self.profile_digest:
                raise ValueError("egress decision profile_digest does not match audit bundle.")
            if decision.network_policy_digest != self.network_policy_digest:
                raise ValueError("egress decision network_policy_digest does not match audit bundle.")

    @property
    def allowed_count(self) -> int:
        return sum(1 for decision in self.decisions if decision.allowed)

    @property
    def denied_count(self) -> int:
        return sum(1 for decision in self.decisions if not decision.allowed)

    @property
    def digest(self) -> str:
        return _sha256_json(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "bundle_id": self.bundle_id,
            "profile_id": self.profile_id,
            "profile_digest": self.profile_digest,
            "network_policy_digest": self.network_policy_digest,
            "created_at": self.created_at.isoformat(),
            "allowed_count": self.allowed_count,
            "denied_count": self.denied_count,
            "decisions": [decision.to_dict() for decision in self.decisions],
            "metadata": dict(sorted(self.metadata.items())),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class SandboxEgressGuard:
    def evaluate(
        self,
        profile: SandboxProfile,
        request: SandboxEgressRequest,
        *,
        decision_id: str | None = None,
    ) -> SandboxEgressDecision:
        policy = profile.network
        matched_rule = _matching_rule(policy, request)
        if policy.mode is SandboxNetworkMode.DENY_ALL:
            status = SandboxEgressDecisionStatus.DENIED
            reason = "deny_all network policy blocks all sandbox egress."
            matched_rule = None
        elif policy.mode is SandboxNetworkMode.ALLOWLIST:
            if matched_rule is None:
                status = SandboxEgressDecisionStatus.DENIED
                reason = "egress endpoint is not present in the sandbox network allowlist."
            else:
                status = SandboxEgressDecisionStatus.ALLOWED
                reason = "egress endpoint matched an explicit sandbox network allowlist rule."
        elif policy.mode is SandboxNetworkMode.PROXY_LOGGED:
            if matched_rule is None:
                status = SandboxEgressDecisionStatus.DENIED
                reason = "proxy_logged egress requires an explicit matching allowlist rule."
            else:
                status = SandboxEgressDecisionStatus.ALLOWED_VIA_PROXY
                reason = "egress endpoint is allowed only through an auditable proxy path."
        elif policy.mode is SandboxNetworkMode.OFFLINE_PACKAGE_CACHE:
            status = SandboxEgressDecisionStatus.OFFLINE_CACHE_ONLY
            reason = "offline_package_cache mode denies direct network egress from the sandbox."
            matched_rule = None
        else:
            status = SandboxEgressDecisionStatus.DENIED
            reason = "unsupported sandbox network policy mode."
            matched_rule = None
        return SandboxEgressDecision(
            decision_id=decision_id if decision_id is not None else f"egress-{request.request_id}",
            profile_id=profile.profile_id,
            profile_digest=profile.digest,
            network_policy_digest=network_policy_digest(policy),
            network_mode=policy.mode,
            request=request,
            status=status,
            reason=reason,
            evaluated_at=datetime.now(tz=UTC),
            matched_rule=matched_rule,
            metadata={"guard": "wave6.egress"},
        )

    def evaluate_command_request(
        self,
        command_request: SandboxCommandRequest,
        egress_request: SandboxEgressRequest,
        *,
        decision_id: str | None = None,
    ) -> SandboxEgressDecision:
        return self.evaluate(
            command_request.profile,
            egress_request,
            decision_id=decision_id,
        )

    def audit_bundle(
        self,
        profile: SandboxProfile,
        requests: tuple[SandboxEgressRequest, ...],
        *,
        bundle_id: str,
    ) -> SandboxEgressAuditBundle:
        decisions = tuple(
            self.evaluate(profile, request, decision_id=f"{bundle_id}-{index + 1}")
            for index, request in enumerate(requests)
        )
        return SandboxEgressAuditBundle(
            bundle_id=bundle_id,
            profile_id=profile.profile_id,
            profile_digest=profile.digest,
            network_policy_digest=network_policy_digest(profile.network),
            created_at=datetime.now(tz=UTC),
            decisions=decisions,
            metadata={"guard": "wave6.egress"},
        )


def network_policy_digest(policy: SandboxNetworkPolicy) -> str:
    return _sha256_json(policy.to_dict())


def _matching_rule(
    policy: SandboxNetworkPolicy,
    request: SandboxEgressRequest,
) -> SandboxNetworkAllowRule | None:
    for rule in policy.allowlist:
        if (rule.protocol, rule.host, rule.port) == request.endpoint_key:
            return rule
    return None


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


def _normalize_host(value: str) -> str:
    cleaned = _normalize_text(value.lower(), label="host")
    if "://" in cleaned or "/" in cleaned or ".." in cleaned:
        raise ValueError("host must be a hostname, not a URL or path.")
    if not _HOST_RE.fullmatch(cleaned):
        raise ValueError("host contains unsupported characters.")
    return cleaned


def _normalize_protocol(value: str) -> str:
    cleaned = _normalize_text(value.lower(), label="protocol")
    if cleaned not in {"tcp", "udp", "https"}:
        raise ValueError("protocol must be tcp, udp, or https.")
    return cleaned


def _normalize_sha256(value: str, *, label: str) -> str:
    cleaned = _normalize_text(value.lower(), label=label)
    if not _SHA256_RE.fullmatch(cleaned):
        raise ValueError(f"{label} must be a 64-character lowercase SHA-256 digest.")
    return cleaned


def _normalize_str_mapping(values: Mapping[str, str], *, label: str) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in values.items():
        normalized[_normalize_id(key, label=f"{label}_key")] = _normalize_text(value, label=f"{label}_value")
    return dict(sorted(normalized.items()))


def _require_port(value: int) -> None:
    if value < 1 or value > 65535:
        raise ValueError("port must be in the range 1-65535.")


def _require_aware_datetime(value: datetime, *, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware.")
