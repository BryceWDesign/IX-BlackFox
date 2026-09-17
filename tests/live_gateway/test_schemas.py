from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ix_blackfox.live_gateway.models import (
    WAVE14_EVIDENCE_SCHEMA_VERSION,
    WAVE14_RECEIPT_SCHEMA_VERSION,
)


def test_wave14_schemas_are_stable_draft_2020_12_objects() -> None:
    for path in _schema_paths():
        schema = _load(path)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["$id"].endswith(f"/schemas/{path.name}")
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False


def test_wave14_evidence_and_receipt_schema_versions_match_runtime() -> None:
    evidence = _load(_schema_dir() / "wave14-authority-evidence.schema.json")
    receipt = _load(_schema_dir() / "wave14-authority-receipt.schema.json")
    assert evidence["properties"]["schema_version"]["const"] == WAVE14_EVIDENCE_SCHEMA_VERSION
    assert receipt["properties"]["schema_version"]["const"] == WAVE14_RECEIPT_SCHEMA_VERSION


def test_wave14_ci_schema_proves_denied_calls_do_not_reach_upstream() -> None:
    schema = _load(_schema_dir() / "wave14-live-gateway-ci-summary.schema.json")
    proof = schema["properties"]["proof"]["properties"]
    assert proof["scope_block_upstream_count"]["const"] == 0
    assert proof["origin_block_http_status"]["const"] == 403
    assert proof["origin_block_upstream_count"]["const"] == 0
    assert proof["evidence_block_upstream_count"]["const"] == 0
    assert proof["mcp_allow_upstream_count"]["const"] == 1
    assert proof["replay_block_http_status"]["const"] == 409
    assert proof["replay_block_upstream_count"]["const"] == 1
    assert proof["api_allow_upstream_count"]["const"] == 2
    assert proof["unauthenticated_receipt_inspection_status"]["const"] == 401
    assert proof["operator_receipt_inspection_status"]["const"] == 200


def _schema_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "schemas"


def _schema_paths() -> tuple[Path, ...]:
    return tuple(sorted(_schema_dir().glob("wave14-*.schema.json")))


def _load(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload
