from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ix_blackfox.authority_crypto.encoding import (
    AuthorityProofError,
    canonical_bytes,
    digest,
)
from ix_blackfox.authority_crypto.trust import TrustPolicy, fingerprint
from ix_blackfox.autonomy.contracts import (
    OperationError,
    identifier,
    integer,
    json_object,
    object_fields,
    text,
)

CONTRACT = "wave19.requirements.v1"
SOURCES = ("provider", "test", "simulation")
MAX_CHAIN = 4


@dataclass(frozen=True, slots=True)
class VerificationConfig:
    provider: Path
    test: Path
    simulation: Path

    @classmethod
    def parse(cls, raw: Any, base: Path) -> VerificationConfig:
        data = object_fields(raw, set(SOURCES), "verification trust")
        return cls(*(base / text(data[role], role, 4096) for role in SOURCES))

    def policies(self, authority: TrustPolicy) -> dict[str, TrustPolicy]:
        try:
            policies = {role: TrustPolicy.load(getattr(self, role)) for role in SOURCES}
        except OverflowError as exc:
            raise AuthorityProofError(
                "Verification trust policy contains an invalid time."
            ) from exc
        validate_roles(policies, authority)
        return policies


def validate_roles(policies: dict[str, TrustPolicy], authority: TrustPolicy) -> None:
    if set(policies) != set(SOURCES):
        raise OperationError(
            "Verification requires provider, test, and simulation trust policies."
        )
    used = {fingerprint(key.key) for key in authority.keys}
    domains = {(authority.deployment_id, authority.stream_id)}
    for policy in policies.values():
        keys = {fingerprint(key.key) for key in policy.keys}
        domain = (policy.deployment_id, policy.stream_id)
        if used & keys or domain in domains:
            raise OperationError(
                "Verification trust roles require distinct keys and signing domains.",
                503,
            )
        used.update(keys)
        domains.add(domain)


def trust_binding(policies: dict[str, TrustPolicy]) -> str:
    return digest(
        {
            role: {
                "domain": [policy.deployment_id, policy.stream_id],
                "keys": sorted(
                    [key.key_id, fingerprint(key.key), key.algorithm]
                    for key in policy.keys
                ),
            }
            for role, policy in policies.items()
        }
    )


def sha256(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise OperationError("Expected a lowercase SHA-256 digest.")
    return value


def criteria(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= 64:
        raise OperationError("A requirement set requires 1–64 criteria.")
    result = []
    seen = set()
    for row in raw:
        item = object_fields(
            row,
            {"id", "version", "description", "step_id", "source", "check", "expected"},
            "criterion",
        )
        name = identifier(item["id"])
        source = identifier(item["source"])
        if name in seen or source not in SOURCES:
            raise OperationError(
                "Criterion IDs must be unique and sources must be configured roles."
            )
        seen.add(name)
        result.append(
            {
                "id": name,
                "version": integer(item["version"], "criterion version", 1, 2**31 - 1),
                "description": text(item["description"], "criterion description"),
                "step_id": identifier(item["step_id"]),
                "source": source,
                "check": identifier(item["check"]),
                "expected": json_object(item["expected"], "expected result", 8192),
            }
        )
    return sorted(result, key=lambda item: item["id"])


def check_coverage(
    requirements: list[dict[str, Any]],
    plan: dict[str, Any],
    *,
    rollback: bool = False,
) -> None:
    steps = plan["steps"]
    if any(row["step_id"] not in steps for row in requirements):
        raise OperationError(
            "Every criterion must refer to a step in the execution plan."
        )
    for name, step in steps.items():
        observed = [
            row
            for row in requirements
            if row["step_id"] == name and row["source"] == "provider"
        ]
        expected = (
            step["recovery"]["expected_outcome"]
            if rollback
            else step["expected_outcome"]
        )
        if len(observed) != 1 or canonical_bytes(
            observed[0]["expected"]
        ) != canonical_bytes(expected):
            raise OperationError(
                "Each step requires one provider criterion matching its planned outcome or rollback obligation."
            )


def parse_contract(raw: Any, plan: dict[str, Any]) -> dict[str, Any]:
    data = object_fields(
        raw,
        {"schema_version", "change", "requirements", "rollback_requirements"},
        "verification contract",
    )
    if data["schema_version"] != CONTRACT or len(canonical_bytes(data)) > 65536:
        raise OperationError("Unsupported or oversized verification contract.")
    change = object_fields(
        data["change"], {"id", "version", "summary", "artifact_sha256"}, "change"
    )
    normalized = {
        "id": identifier(change["id"]),
        "version": integer(change["version"], "change version", 1, 2**31 - 1),
        "summary": text(change["summary"], "change summary"),
        "artifact_sha256": sha256(change["artifact_sha256"]),
    }
    requirements = criteria(data["requirements"])
    rollback = criteria(data["rollback_requirements"])
    check_coverage(requirements, plan)
    check_coverage(rollback, plan, rollback=True)
    return {
        "schema_version": CONTRACT,
        "change": normalized,
        "requirements": requirements,
        "rollback_requirements": rollback,
    }
