from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from ix_blackfox.live_gateway.demo import run_demo


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Wave 14 live authority gateway proof.")
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    output_root = root / ".blackfox-artifacts" / "wave14"
    output_root.mkdir(parents=True, exist_ok=True)
    demo_root = output_root / "live-gateway-demo"
    if demo_root.exists():
        shutil.rmtree(demo_root)
    result = run_demo(demo_root)
    summary = {
        "schema_version": "wave14.live_authority_gateway_ci_summary.v1",
        "wave": "14",
        "passed": bool(result["passed"]),
        "proof": result,
        "scope_note": (
            "This local integration proof uses real HTTP requests, environment-backed agent "
            "authentication, real pre-tool enforcement, HMAC-authenticated evidence, "
            "single-use target-bound human approval with replay rejection, a real upstream "
            "file side effect after authorization, operator-authenticated receipt inspection, "
            "and a durable receipt chain. It is not a production "
            "identity provider, PKI, compliance certification, or deployment authorization."
        ),
    }
    output = output_root / "wave14-live-authority-gateway-summary.json"
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
