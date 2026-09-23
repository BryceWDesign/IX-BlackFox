from pathlib import Path

from ix_blackfox.live_gateway.cli import main
from ix_blackfox.live_gateway.config import load_gateway_config
from ix_blackfox.live_gateway.enterprise_identity import IdentityRevocationStore
from ix_blackfox.live_gateway.wave15_demo import _wave15_config


def test_operator_cli_persists_jti_revocation(tmp_path: Path) -> None:
    jwks = tmp_path / "jwks.json"
    jwks.write_text('{"keys": []}', encoding="utf-8")
    config_path = tmp_path / "gateway.toml"
    config_path.write_text(_wave15_config(9001, jwks), encoding="utf-8")

    result = main(
        [
            "revoke-identity",
            "--config",
            str(config_path),
            "--kind",
            "jti",
            "--value",
            "compromised-token-17",
            "--reason",
            "incident-response",
        ]
    )
    assert result == 0
    config = load_gateway_config(config_path)
    store = IdentityRevocationStore(config.identity_revocation_database)
    assert store.is_revoked(kind="jti", value="compromised-token-17") is True
