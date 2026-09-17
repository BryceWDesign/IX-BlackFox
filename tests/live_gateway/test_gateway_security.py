from __future__ import annotations

import base64
import json
from dataclasses import replace
from pathlib import Path

import pytest

from ix_blackfox.live_gateway.config import GatewayServerConfig, load_gateway_config
from ix_blackfox.live_gateway.evidence import issue_signed_evidence
from ix_blackfox.live_gateway.models import LiveAuthorityStatus
from ix_blackfox.live_gateway.service import LiveAuthorityGateway

_AGENT_TOKEN = "agent-test-token-0123456789abcdef012345"
_CI_SECRET = "ci-test-secret-0123456789abcdef012345"
_HUMAN_SECRET = "human-test-secret-0123456789abcdef012"
_OPERATOR_TOKEN = "operator-test-token-0123456789abcdef012"


def _source_config() -> Path:
    return Path(__file__).resolve().parents[2] / "examples" / "wave14" / "blackfox.gateway.toml"


def _set_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BLACKFOX_WAVE14_CI_KEY", _CI_SECRET)
    monkeypatch.setenv("BLACKFOX_WAVE14_HUMAN_KEY", _HUMAN_SECRET)
    monkeypatch.setenv("BLACKFOX_WAVE14_AGENT_TOKEN", _AGENT_TOKEN)
    monkeypatch.setenv("BLACKFOX_WAVE14_OPERATOR_TOKEN", _OPERATOR_TOKEN)


def _gateway(monkeypatch: pytest.MonkeyPatch, path: Path | None = None) -> LiveAuthorityGateway:
    _set_secrets(monkeypatch)
    return LiveAuthorityGateway.from_config(load_gateway_config(path or _source_config()))


def _modern_tool_payload(*, revision: str = "abc123", agent_id: str = "coding-agent-07") -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "filesystem.write_file",
            "arguments": {
                "path": "docs/a.txt",
                "content": "bounded",
                "revision": revision,
            },
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.ix-blackfox/agentId": agent_id,
                "io.ix-blackfox/evidenceRefs": [],
            },
        },
    }


def _modern_headers(*, revision_header: str = "abc123") -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": "filesystem.write_file",
        "Mcp-Param-Revision": revision_header,
        "X-BlackFox-Agent-Token": _AGENT_TOKEN,
    }


def test_route_bound_mcp_parameter_header_mismatch_fails_before_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = _gateway(monkeypatch)
    payload = _modern_tool_payload(revision="abc123")
    raw = json.dumps(payload).encode("utf-8")

    response = gateway.handle_mcp(
        payload=payload,
        headers=_modern_headers(revision_header="different"),
        raw_body=raw,
    )

    assert response.status == 400
    decoded = json.loads(response.body)
    assert decoded["error"]["code"] == -32020
    assert "disagrees" in decoded["error"]["message"]


def test_route_bound_mcp_parameter_header_accepts_base64_sentinel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = _gateway(monkeypatch)
    payload = _modern_tool_payload(revision="abc123")
    raw = json.dumps(payload).encode("utf-8")
    encoded = base64.b64encode(b"abc123").decode("ascii")

    response = gateway.handle_mcp(
        payload=payload,
        headers=_modern_headers(revision_header=f"=?base64?{encoded}?="),
        raw_body=raw,
    )

    # Transport/body binding passed.  The request is still correctly stopped because
    # this test supplies no CI/human authority evidence.
    assert response.status == 428
    decoded = json.loads(response.body)
    assert decoded["error"]["code"] in {-32051, -32052}


def test_mcp_passthrough_requires_agent_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = _gateway(monkeypatch)
    payload = {"jsonrpc": "2.0", "id": 7, "method": "ping", "params": {}}
    raw = json.dumps(payload).encode("utf-8")

    response = gateway.handle_mcp(
        payload=payload,
        headers={"MCP-Protocol-Version": "2025-11-25"},
        raw_body=raw,
    )

    assert response.status == 401
    decoded = json.loads(response.body)
    assert decoded["error"]["code"] == -32054


def test_invalid_mcp_agent_claim_returns_400_instead_of_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = _gateway(monkeypatch)
    payload = _modern_tool_payload(agent_id="___")
    raw = json.dumps(payload).encode("utf-8")

    response = gateway.handle_mcp(
        payload=payload,
        headers=_modern_headers(),
        raw_body=raw,
    )

    assert response.status == 400


def test_invalid_api_agent_claim_returns_400_instead_of_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = _gateway(monkeypatch)
    response = gateway.handle_api(
        payload={
            "agent_id": "___",
            "tool_name": "filesystem.write_file",
            "arguments": {"path": "docs/a.txt", "revision": "abc123"},
        },
        headers={"X-BlackFox-Agent-Token": _AGENT_TOKEN},
    )
    assert response.status == 400


def test_route_level_human_approval_is_independent_execution_condition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _set_secrets(monkeypatch)
    altered = tmp_path / "gateway.toml"
    source = _source_config().read_text(encoding="utf-8")
    source = (
        source.replace('tool_name = "filesystem.write_file"', 'tool_name = "filesystem.read_file"')
        .replace('capability = "file_write"', 'capability = "file_read"')
        .replace('capability = "write_workspace"', 'capability = "read_workspace"')
        .replace('tool_ids = ["filesystem.write_file"]', 'tool_ids = ["filesystem.read_file"]')
        .replace('api_path = "/tools/write"', 'api_path = "/tools/read"')
        .replace("requires_human_review = true", "requires_human_review = false")
    )
    altered.write_text(source, encoding="utf-8")
    gateway = LiveAuthorityGateway.from_config(load_gateway_config(altered))
    evidence = issue_signed_evidence(
        evidence_id="ci-only",
        kind="test_result",
        issuer="ci",
        key_id="ci-hmac-v1",
        secret=_CI_SECRET.encode("utf-8"),
        status="passed",
        repository_id="ix-blackfox",
        revision="abc123",
        payload={"passed": True},
    )
    gateway.evidence_store.write(evidence)

    prepared = gateway.prepare_authority(
        agent_id="coding-agent-07",
        tool_name="filesystem.read_file",
        arguments={"path": "docs/a.txt", "revision": "abc123"},
        evidence_ids=(evidence.evidence_id,),
        protocol="blackfox-api/v1",
    )

    assert prepared.decision.agent_authorization.allowed is True
    assert prepared.decision.status is LiveAuthorityStatus.REVIEW_REQUIRED
    assert prepared.decision.allowed is False
    assert prepared.decision.reason_codes == ("human_authority_required",)


def test_generic_route_can_omit_path_binding_for_non_path_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_secrets(monkeypatch)
    config = load_gateway_config(_source_config())
    original = config.routes[0]
    generic = replace(original, path_argument="", mcp_header_bindings=())
    gateway = LiveAuthorityGateway.from_config(replace(config, routes=(generic,)))

    subject = gateway.build_subject(
        agent_id="coding-agent-07",
        tool_name="filesystem.write_file",
        arguments={"revision": "abc123", "content": "non-path action"},
        protocol="blackfox-api/v1",
    )

    assert subject.path == ""
    assert subject.revision == "abc123"


def test_server_origin_allowlist_normalizes_http_origins() -> None:
    server = GatewayServerConfig(allowed_origins=("HTTPS://EXAMPLE.COM/",))
    assert server.allowed_origins == ("https://example.com",)


def test_api_rejects_falsy_non_string_agent_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = _gateway(monkeypatch)
    response = gateway.handle_api(
        payload={
            "agent_id": 0,
            "tool_name": "filesystem.write_file",
            "arguments": {"path": "docs/a.txt", "revision": "abc123"},
        },
        headers={"X-BlackFox-Agent-Token": _AGENT_TOKEN},
    )
    assert response.status == 400
    assert json.loads(response.body)["error"] == "agent_id must be a string"


@pytest.mark.parametrize("surface", ["mcp", "api"])
def test_evidence_reference_count_is_bounded_before_authority(
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
) -> None:
    gateway = _gateway(monkeypatch)
    evidence_ids = [f"evidence-{index}" for index in range(65)]

    if surface == "mcp":
        payload = _modern_tool_payload()
        meta = payload["params"]["_meta"]  # type: ignore[index]
        meta["io.ix-blackfox/evidenceRefs"] = evidence_ids  # type: ignore[index]
        response = gateway.handle_mcp(
            payload=payload,
            headers=_modern_headers(),
            raw_body=json.dumps(payload).encode("utf-8"),
        )
        detail = json.loads(response.body)["error"]["data"]["detail"]
    else:
        response = gateway.handle_api(
            payload={
                "agent_id": "coding-agent-07",
                "tool_name": "filesystem.write_file",
                "arguments": {"path": "docs/a.txt", "revision": "abc123"},
                "context": {"evidence_refs": evidence_ids},
            },
            headers={"X-BlackFox-Agent-Token": _AGENT_TOKEN},
        )
        detail = json.loads(response.body)["detail"]

    assert response.status == 403
    assert "At most 64 evidence references" in detail


@pytest.mark.parametrize("surface", ["mcp", "api"])
def test_evidence_reference_length_is_bounded_before_authority(
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
) -> None:
    gateway = _gateway(monkeypatch)
    oversized = "e" * 129

    if surface == "mcp":
        payload = _modern_tool_payload()
        meta = payload["params"]["_meta"]  # type: ignore[index]
        meta["io.ix-blackfox/evidenceRefs"] = [oversized]  # type: ignore[index]
        response = gateway.handle_mcp(
            payload=payload,
            headers=_modern_headers(),
            raw_body=json.dumps(payload).encode("utf-8"),
        )
        detail = json.loads(response.body)["error"]["data"]["detail"]
    else:
        response = gateway.handle_api(
            payload={
                "agent_id": "coding-agent-07",
                "tool_name": "filesystem.write_file",
                "arguments": {"path": "docs/a.txt", "revision": "abc123"},
                "context": {"evidence_refs": [oversized]},
            },
            headers={"X-BlackFox-Agent-Token": _AGENT_TOKEN},
        )
        detail = json.loads(response.body)["detail"]

    assert response.status == 403
    assert "must not exceed 128 characters" in detail
