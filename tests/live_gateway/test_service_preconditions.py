from __future__ import annotations

from pathlib import Path

import pytest

from ix_blackfox.live_gateway.config import load_gateway_config
from ix_blackfox.live_gateway.http_server import serve_gateway
from ix_blackfox.live_gateway.service import LiveAuthorityGateway


def _gateway(monkeypatch: pytest.MonkeyPatch) -> LiveAuthorityGateway:
    root = Path(__file__).resolve().parents[2]
    monkeypatch.setenv("BLACKFOX_WAVE14_CI_KEY", "ci-test-secret-0123456789abcdef012345")
    monkeypatch.setenv("BLACKFOX_WAVE14_HUMAN_KEY", "human-test-secret-0123456789abcdef012")
    monkeypatch.setenv("BLACKFOX_WAVE14_AGENT_TOKEN", "agent-test-token-0123456789abcdef012345")
    monkeypatch.setenv("BLACKFOX_WAVE14_OPERATOR_TOKEN", "operator-test-token-0123456789abcdef012")
    config = load_gateway_config(root / "examples" / "wave14" / "blackfox.gateway.toml")
    return LiveAuthorityGateway.from_config(config)


def test_route_rejects_missing_path_before_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = _gateway(monkeypatch)

    with pytest.raises(ValueError, match="requires a non-empty 'path'"):
        gateway.build_subject(
            agent_id="coding-agent-07",
            tool_name="filesystem.write_file",
            arguments={"revision": "abc123", "content": "unsafe default target"},
            protocol="mcp/2026-07-28",
        )


def test_revision_bound_policy_rejects_missing_revision_before_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = _gateway(monkeypatch)

    with pytest.raises(ValueError, match="requires a non-empty 'revision'"):
        gateway.build_subject(
            agent_id="coding-agent-07",
            tool_name="filesystem.write_file",
            arguments={"path": "docs/readme.md", "content": "revisionless"},
            protocol="mcp/2026-07-28",
        )


def test_gateway_readiness_fails_when_configured_evidence_keys_are_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path(__file__).resolve().parents[2]
    monkeypatch.delenv("BLACKFOX_WAVE14_CI_KEY", raising=False)
    monkeypatch.delenv("BLACKFOX_WAVE14_HUMAN_KEY", raising=False)
    monkeypatch.delenv("BLACKFOX_WAVE14_AGENT_TOKEN", raising=False)
    monkeypatch.delenv("BLACKFOX_WAVE14_OPERATOR_TOKEN", raising=False)
    config = load_gateway_config(root / "examples" / "wave14" / "blackfox.gateway.toml")
    gateway = LiveAuthorityGateway.from_config(config)

    status = gateway.status()

    assert status["ready"] is False
    assert len(status["missing_trusted_key_bindings"]) == 2
    assert status["missing_agent_credentials"] == ["coding-agent-07"]
    assert status["operator_token_missing"] is True


def test_agent_token_authenticates_exact_registered_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = _gateway(monkeypatch)

    agent_id, error = gateway.authenticate_agent(  # noqa: SLF001 - security contract test
        headers={"X-BlackFox-Agent-Token": "agent-test-token-0123456789abcdef012345"},
        claimed_agent_id="coding-agent-07",
    )

    assert error == ""
    assert agent_id == "coding-agent-07"


def test_agent_token_rejects_missing_or_impersonated_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = _gateway(monkeypatch)

    missing_id, missing_error = gateway.authenticate_agent(  # noqa: SLF001
        headers={},
        claimed_agent_id="coding-agent-07",
    )
    impersonated_id, impersonated_error = gateway.authenticate_agent(  # noqa: SLF001
        headers={"X-BlackFox-Agent-Token": "agent-test-token-0123456789abcdef012345"},
        claimed_agent_id="another-agent",
    )

    assert missing_id == ""
    assert "credential is required" in missing_error
    assert impersonated_id == ""
    assert "does not match" in impersonated_error


def test_operator_token_protects_operator_surfaces(monkeypatch: pytest.MonkeyPatch) -> None:
    gateway = _gateway(monkeypatch)
    assert gateway.operator_authorized({}) is False
    assert gateway.operator_authorized(
        {"X-BlackFox-Operator-Token": "operator-test-token-0123456789abcdef012"}
    ) is True
    assert gateway.operator_authorized(
        {"Authorization": "Bearer operator-test-token-0123456789abcdef012"}
    ) is True


def test_authority_context_changes_when_policy_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    gateway = _gateway(monkeypatch)
    first = gateway.build_subject(
        agent_id="coding-agent-07",
        tool_name="filesystem.write_file",
        arguments={"path": "docs/a.md", "revision": "abc123", "content": "x"},
        protocol="mcp/2026-07-28",
    )
    source = Path(__file__).resolve().parents[2] / "examples" / "wave14" / "blackfox.gateway.toml"
    altered_path = tmp_path / "altered.gateway.toml"
    altered_path.write_text(
        source.read_text(encoding="utf-8").replace("max_age_seconds = 3600", "max_age_seconds = 1800"),
        encoding="utf-8",
    )
    altered = LiveAuthorityGateway.from_config(load_gateway_config(altered_path))
    second = altered.build_subject(
        agent_id="coding-agent-07",
        tool_name="filesystem.write_file",
        arguments={"path": "docs/a.md", "revision": "abc123", "content": "x"},
        protocol="mcp/2026-07-28",
    )
    assert first.arguments_digest == second.arguments_digest
    assert first.authority_context_digest != second.authority_context_digest
    assert first.digest != second.digest


def test_public_server_entrypoint_refuses_not_ready_gateway(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path(__file__).resolve().parents[2]
    monkeypatch.delenv("BLACKFOX_WAVE14_CI_KEY", raising=False)
    monkeypatch.delenv("BLACKFOX_WAVE14_HUMAN_KEY", raising=False)
    monkeypatch.delenv("BLACKFOX_WAVE14_AGENT_TOKEN", raising=False)
    monkeypatch.delenv("BLACKFOX_WAVE14_OPERATOR_TOKEN", raising=False)
    config = load_gateway_config(root / "examples" / "wave14" / "blackfox.gateway.toml")
    gateway = LiveAuthorityGateway.from_config(config)

    with pytest.raises(RuntimeError, match="gateway is not ready"):
        serve_gateway(gateway)


def test_subject_path_is_canonicalized_before_digest_and_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = _gateway(monkeypatch)
    subject = gateway.build_subject(
        agent_id="coding-agent-07",
        tool_name="filesystem.write_file",
        arguments={"path": "docs//nested/./a.md", "revision": "abc123", "content": "x"},
        protocol="mcp/2026-07-28",
    )
    assert subject.path == "docs/nested/a.md"

    with pytest.raises(ValueError, match="path traversal is not allowed"):
        gateway.build_subject(
            agent_id="coding-agent-07",
            tool_name="filesystem.write_file",
            arguments={"path": "docs/../src/escape.py", "revision": "abc123"},
            protocol="mcp/2026-07-28",
        )
