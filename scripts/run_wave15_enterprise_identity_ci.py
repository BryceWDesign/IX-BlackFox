from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from ix_blackfox.live_gateway.wave15_demo import run_wave15_demo


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Wave 15 enterprise identity live-network proof.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = args.root.resolve()
    wave15_root = root / ".blackfox-artifacts" / "wave15"
    proof_workdir = wave15_root / "proof-workdir"

    if proof_workdir.exists():
        shutil.rmtree(proof_workdir)

    result = run_wave15_demo(proof_workdir)
    summary = {
        "schema_version": "wave15.enterprise_identity_ci_summary.v1",
        **result,
        "claim_boundary": (
            "This proof demonstrates local cryptographic OIDC/JWT verification, bounded delegated "
            "authority, revocation, pre-upstream denial, identity-bound authority subjects, and "
            "durable receipt-chain integrity. It does not claim DoD authorization, FedRAMP, cATO, "
            "AWS certification, or production identity-provider integration."
        ),
    }
    output = wave15_root / "wave15-enterprise-identity-summary.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if bool(result.get("passed")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
