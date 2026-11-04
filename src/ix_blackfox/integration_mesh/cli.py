from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from ix_blackfox.integration_mesh.audit import AuditRelay
from ix_blackfox.integration_mesh.ledger import MeshLedger
from ix_blackfox.live_gateway.config import load_gateway_config
from ix_blackfox.live_gateway.service import LiveAuthorityGateway


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="blackfox mesh",
        description="Enterprise integration mesh operator commands.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("status", "relay", "requeue-audit", "inspect-request"):
        child = sub.add_parser(command)
        child.add_argument("--config", required=True)
        if command == "inspect-request":
            child.add_argument("--request-id", required=True)
        if command == "relay":
            child.add_argument("--limit", type=int, default=100)
        if command == "requeue-audit":
            child.add_argument("--sink-id", required=True)
            child.add_argument("--sequence", type=int, required=True)
    args = parser.parse_args(list(argv) if argv is not None else None)
    config = load_gateway_config(Path(args.config))
    if config.mesh is None:
        parser.error("Configuration has no [mesh] table.")
    gateway = LiveAuthorityGateway.from_config(config)
    try:
        if args.command == "inspect-request":
            request = MeshLedger(config.mesh.database).inspect_request(args.request_id)
            print(json.dumps({"request": request}, indent=2))
            return 0 if request else 1
        if args.command == "status":
            print(
                json.dumps(
                    {
                        "gateway": gateway.status(),
                        "mesh": MeshLedger(config.mesh.database).status(),
                    },
                    indent=2,
                )
            )
            return 0 if gateway.status()["ready"] else 1
        gateway.validate_mesh_credentials(config.mesh.audit_sinks)
        relay = AuditRelay(config.mesh, gateway.receipt_store)
        if args.command == "requeue-audit":
            sink = next(
                (s for s in config.mesh.audit_sinks if s.sink_id == args.sink_id), None
            )
            if sink is None:
                parser.error("Unknown audit sink.")
            relay.requeue(sink, args.sequence)
            print(
                json.dumps(
                    {
                        "requeued": True,
                        "sink_id": sink.sink_id,
                        "sequence": args.sequence,
                    }
                )
            )
            return 0
        if not 1 <= args.limit <= 1000:
            parser.error("--limit must be between 1 and 1000.")
        results = []
        for sink in config.mesh.audit_sinks:
            added = relay.sync(sink, args.limit)
            deliveries = []
            for _ in range(args.limit):
                result = relay.deliver_one(sink)
                deliveries.append(result)
                if result["state"] != "delivered":
                    break
            results.append(
                {"sink_id": sink.sink_id, "enqueued": added, "deliveries": deliveries}
            )
        print(json.dumps({"sinks": results, "mesh": relay.ledger.status()}, indent=2))
        return 1 if relay.ledger.status()["outbox"].get("dead", 0) else 0
    finally:
        gateway.receipt_store.close()


if __name__ == "__main__":
    raise SystemExit(main())
