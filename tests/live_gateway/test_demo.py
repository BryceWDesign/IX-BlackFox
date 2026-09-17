from __future__ import annotations

from pathlib import Path

from ix_blackfox.live_gateway.demo import run_demo


def test_wave14_real_network_demo_proves_denial_before_upstream_and_allowed_execution(tmp_path: Path) -> None:
    result = run_demo(tmp_path)

    assert result["passed"] is True
    assert result["auth_block_http_status"] == 401
    assert result["auth_block_upstream_count"] == 0
    assert result["scope_block_http_status"] == 403
    assert result["scope_block_upstream_count"] == 0
    assert result["evidence_block_http_status"] == 428
    assert result["evidence_block_upstream_count"] == 0
    assert result["mcp_allow_http_status"] == 200
    assert result["mcp_allow_upstream_count"] == 1
    assert result["replay_block_http_status"] == 409
    assert result["replay_block_upstream_count"] == 1
    assert result["api_allow_http_status"] == 200
    assert result["api_allow_upstream_count"] == 2
    assert result["mcp_output_exists"] is True
    assert result["mcp_output_matches"] is True
    assert result["api_output_exists"] is True
    assert result["api_output_matches"] is True
    assert result["unauthenticated_receipt_inspection_status"] == 401
    assert result["operator_receipt_inspection_status"] == 200
    assert result["receipt_chain"]["passed"] is True
