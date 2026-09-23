from pathlib import Path

from ix_blackfox.live_gateway.wave15_demo import run_wave15_demo


def test_wave15_real_network_identity_and_delegation_proof(tmp_path: Path) -> None:
    result = run_wave15_demo(tmp_path)
    assert result["passed"] is True
    assert result["identity_mode"] == "federated_required"
    assert result["static_credential_status"] == 401
    assert result["wrong_audience_status"] == 401
    assert result["expired_token_status"] == 401
    assert result["missing_delegation_status"] == 401
    assert result["delegation_scope_status"] == 403
    assert result["upstream_count_after_denials"] == 0
    assert result["allowed_status"] == 200
    assert result["upstream_count_after_allow"] == 1
    assert result["revoked_token_status"] == 401
    assert result["upstream_count_after_revocation"] == 1
    assert result["output_matches"] is True
    assert result["identity_context_digest"] == result["subject_identity_context_digest"]
    assert result["receipt_chain"]["passed"] is True
