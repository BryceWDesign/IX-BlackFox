from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from ix_blackfox.authority_crypto.encoding import digest
from ix_blackfox.integration_mesh.audit import receipt_event
from ix_blackfox.live_gateway.service import LiveAuthorityGateway


def test_produced_audit_event_matches_public_schema(
    gateway: LiveAuthorityGateway,
) -> None:
    gateway.handle_api(
        payload={
            "agent_id": "engineering-agent",
            "tool_name": "service.submit",
            "arguments": {"revision": "a" * 40, "payload": {}},
        },
        headers={},
    )
    record = gateway.receipt_store.recent()[0]
    signing = gateway.receipt_store.signing
    assert signing is not None
    source = digest(
        {"deployment": signing.policy.deployment_id, "stream": signing.policy.stream_id}
    )
    event = receipt_event(record, source)
    root = Path(__file__).resolve().parents[2]
    schema = json.loads((root / "schemas/wave17-audit-event.schema.json").read_text())
    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(event)
