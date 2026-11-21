"""Check the signed quota proof and recompute its claims from retained artifacts."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Any

from ix_blackfox.authority_crypto.encoding import (
    canonical_bytes,
    decode64,
    digest,
    read_document,
    strict_json,
)
from ix_blackfox.authority_crypto.trust import TrustPolicy
from ix_blackfox.verification.contracts import SOURCES
from ix_blackfox.verification.proof import verify_bundle


def check(condition: bool, label: str) -> None:
    if not condition:
        raise ValueError(label)


def verify_artifacts(
    path: Path, bundle: dict[str, Any]
) -> dict[tuple[str, str], dict[str, Any]]:
    observed = {}
    for record in bundle["records"]:
        assessment = record["content"]["assessment"]
        operation = assessment["plan"]["operation_id"]
        change = assessment["binding"]["contract"]["change"]
        check(
            hashlib.sha256((path / f"{operation}-change.json").read_bytes()).hexdigest()
            == change["artifact_sha256"],
            f"Change bytes do not match {operation}.",
        )
        for name, envelopes in assessment["proofs"].items():
            target = read_document(path / f"{operation}-{name}-target.json")
            check(
                digest({key: value for key, value in target.items() if key != "digest"})
                == target["digest"],
                "Evidence target digest mismatch.",
            )
            artifact = (path / f"{operation}-{name}-artifact.json").read_bytes()
            result = strict_json(artifact)
            snapshot = result["provider_snapshot"]
            request = target["request_id"]
            check(
                snapshot["request_id"] == request,
                "Provider read has another attempt ID.",
            )
            for envelope in envelopes:
                statement = strict_json(decode64(envelope["payload"]))["body"]
                check(
                    hashlib.sha256(artifact).hexdigest()
                    == statement["artifact_sha256"],
                    "Collector output bytes differ from signed hash.",
                )
                check(
                    statement["target_digest"] == target["digest"],
                    "Evidence target mismatch.",
                )
                match result["check"]:
                    case "applied-quota":
                        actual = {"limit": snapshot["limit"]}
                    case "quota-boundary":
                        probes = result["probes"]
                        check(
                            all(probe["request_id"] == request for probe in probes),
                            "Boundary probe used another provider version.",
                        )
                        actual = {
                            "boundary_ok": [probe["allowed"] for probe in probes]
                            == [True, False]
                        }
                    case "burst-model":
                        model = result["simulation"]
                        actual = {
                            "blocked": sum(
                                demand > snapshot["limit"] for demand in model["demand"]
                            )
                        }
                        check(
                            model["blocked"] == actual["blocked"],
                            "Simulation output mismatch.",
                        )
                    case _:
                        raise ValueError("Unknown check in quota proof.")
                check(
                    canonical_bytes(statement["value"]) == canonical_bytes(actual),
                    "Signed value differs from retained output.",
                )
                observed[(operation, name)] = actual
    return observed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("proof", type=Path)
    path = parser.parse_args().proof
    authority = TrustPolicy.load(path / "authority.json")
    policies = {role: TrustPolicy.load(path / f"{role}.json") for role in SOURCES}
    results = {}
    all_observed = {}
    for operation, expected in [("quota-8", "verified"), ("quota-20", "rolled_back")]:
        bundle = read_document(path / f"{operation}-bundle.json")
        verdict = verify_bundle(bundle, authority, policies, operation_id=operation)
        check(verdict["outcome_at_closure"] == expected, "Unexpected signed verdict.")
        all_observed.update(verify_artifacts(path, bundle))
        results[operation] = {
            "outcome_at_closure": expected,
            "current": verdict["current"],
        }
    check(all_observed[("quota-8", "quota")] == {"limit": 8}, "Initial quota differs.")
    check(
        all_observed[("quota-20", "quota")] == {"limit": 10}, "Clamped quota differs."
    )
    check(
        all_observed[("restore-quota-8", "restored")] == {"limit": 8},
        "Recovery quota differs.",
    )
    print(
        canonical_bytes(
            {
                "passed": True,
                "criteria_outputs_checked": len(all_observed),
                "operations": results,
            }
        ).decode()
    )


if __name__ == "__main__":
    main()
