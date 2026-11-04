from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from ix_blackfox.authority_crypto.cli import generate_keys
from ix_blackfox.live_gateway.config import load_gateway_config
from ix_blackfox.live_gateway.evidence import issue_signed_evidence
from ix_blackfox.live_gateway.service import LiveAuthorityGateway

ROOT = Path(__file__).resolve().parents[2]
REVISION = "a" * 40


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    for name, value in {
        "SIGNING_PASSWORD": "p" * 32,
        "CI_KEY": "c" * 64,
        "HUMAN_KEY": "h" * 64,
        "AGENT_TOKEN": "a" * 64,
        "OPERATOR_TOKEN": "o" * 64,
        "GITHUB_TOKEN": "g" * 64,
        "JIRA_BASIC": "j" * 64,
        "SERVICE_TOKEN": "s" * 64,
        "MCP_TOKEN": "m" * 64,
        "AUDIT_TOKEN": "e" * 64,
    }.items():
        monkeypatch.setenv("BLACKFOX_" + name, value)
    generate_keys(
        tmp_path / "receipt-keys",
        "BLACKFOX_SIGNING_PASSWORD",
        "enterprise-authority",
        "test-deployment",
        "test-stream",
    )
    config_path = tmp_path / "gateway.toml"
    config_path.write_text((ROOT / "examples/wave17/blackfox.gateway.toml").read_text())
    config = load_gateway_config(config_path)
    assert config.mesh is not None
    mesh = replace(
        config.mesh,
        connectors=tuple(
            replace(
                c,
                base_url="http://127.0.0.1:1" + ("/mcp" if c.kind == "mcp" else ""),
                allow_loopback_http=True,
            )
            for c in config.mesh.connectors
        ),
        audit_sinks=tuple(
            replace(s, url="http://127.0.0.1:1/events", allow_loopback_http=True)
            for s in config.mesh.audit_sinks
        ),
    )
    instance = LiveAuthorityGateway.from_config(replace(config, mesh=mesh))
    yield instance
    instance.receipt_store.close()


def authorized(
    gateway: LiveAuthorityGateway,
    tool: str = "service.submit",
    *,
    key: str = "request-1",
    body: dict[str, Any] | None = None,
    protocol: str = "blackfox-api/v1",
    approval: str = "human-1",
) -> tuple[dict[str, Any], dict[str, str]]:
    arguments = {
        "revision": REVISION,
        "payload": body or {"message": "approved submission"},
    }
    subject = gateway.build_subject(
        agent_id="engineering-agent",
        tool_name=tool,
        arguments=arguments,
        protocol=protocol,
    )
    for evidence in (
        issue_signed_evidence(
            evidence_id="ci-result",
            kind="test_result",
            issuer="ci",
            key_id="ci-hmac-v1",
            secret=b"c" * 64,
            status="passed",
            repository_id="example/engineering",
            revision=REVISION,
            payload={"passed": True},
        ),
        issue_signed_evidence(
            evidence_id=approval,
            kind="human_approval",
            issuer="human-review",
            key_id="human-hmac-v1",
            secret=b"h" * 64,
            status="approved",
            repository_id="example/engineering",
            revision=REVISION,
            target_digest=subject.digest,
            payload={
                "decision": "approve",
                "reviewer_kind": "human",
                "reviewer_id": "test-reviewer",
            },
        ),
    ):
        gateway.evidence_store.write(evidence)
    return {
        "agent_id": "engineering-agent",
        "tool_name": tool,
        "arguments": arguments,
        "context": {"evidence_refs": ["ci-result", approval]},
    }, {"X-BlackFox-Agent-Token": "a" * 64, "X-BlackFox-Idempotency-Key": key}
