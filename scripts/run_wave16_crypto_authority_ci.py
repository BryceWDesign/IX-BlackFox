from __future__ import annotations

import argparse
import json
from pathlib import Path

from ix_blackfox.live_gateway.wave16_demo import run_wave16_demo


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Wave 16 local signed-authority proof over real sockets."
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    result = run_wave16_demo(args.root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
