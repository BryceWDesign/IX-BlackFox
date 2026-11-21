"""Collect and sign one criterion from the loopback quota service."""

from __future__ import annotations

import argparse
import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
from urllib.request import Request, urlopen

from ix_blackfox.authority_crypto.encoding import (
    canonical_bytes,
    read_document,
    strict_json,
)
from ix_blackfox.authority_crypto.signing import LocalSigner, SigningController
from ix_blackfox.authority_crypto.trust import TrustPolicy
from ix_blackfox.verification.proof import EVIDENCE_TYPE

PASSWORD = "WAVE19_SOURCE_PASSWORD"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=Path)
    parser.add_argument("key_directory", type=Path)
    parser.add_argument("port", type=int)
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args()
    target = read_document(args.target)
    criterion = target["criterion"]
    role = criterion["source"]

    def read(path: str) -> dict[str, object]:
        request = Request(
            f"http://127.0.0.1:{args.port}{path}",
            headers={"Authorization": "Bearer " + os.environ["WAVE19_READ_TOKEN"]},
        )
        with urlopen(request, timeout=5) as response:
            return strict_json(response.read(8193))

    observed_at = datetime.now(UTC).isoformat()
    snapshot = read("/quota")
    if snapshot["request_id"] != target["request_id"]:
        raise RuntimeError(
            "Provider state is not attributed to the authorized attempt."
        )
    limit = snapshot["limit"]
    if type(limit) is not int:
        raise RuntimeError("Provider returned an invalid quota.")
    record = {"check": criterion["check"], "provider_snapshot": snapshot}
    if criterion["check"] == "applied-quota":
        value: dict[str, object] = {"limit": limit}
    elif criterion["check"] == "quota-boundary":
        probes = [read(f"/probe/{limit}"), read(f"/probe/{limit + 1}")]
        if any(probe["request_id"] != target["request_id"] for probe in probes):
            raise RuntimeError("Provider state changed during the boundary test.")
        record["probes"] = probes
        value = {"boundary_ok": [probe["allowed"] for probe in probes] == [True, False]}
    elif criterion["check"] == "burst-model":
        demand = [1, 8, 9, 3]
        blocked = sum(units > limit for units in demand)
        record["simulation"] = {"demand": demand, "blocked": blocked}
        value = {"blocked": blocked}
    else:
        raise RuntimeError("Unknown check.")
    artifact = canonical_bytes(record)
    args.artifact.write_bytes(artifact)
    signing = SigningController(
        LocalSigner.load(
            args.key_directory / "authority-signing-key.pem", PASSWORD, role, "Ed25519"
        ),
        TrustPolicy.load(args.key_directory / "trust-policy.json"),
    )
    print(
        canonical_bytes(
            signing.envelope(
                EVIDENCE_TYPE,
                {
                    "target_digest": target["digest"],
                    "observed_at": observed_at,
                    "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
                    "status": "pass",
                    "value": value,
                },
            )
        ).decode()
    )


if __name__ == "__main__":
    main()
