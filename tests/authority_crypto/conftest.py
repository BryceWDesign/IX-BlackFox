from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ix_blackfox.authority_crypto.cli import public_trust_document
from ix_blackfox.authority_crypto.signing import LocalSigner, SigningController
from ix_blackfox.authority_crypto.trust import TrustPolicy
from ix_blackfox.live_gateway.config import load_gateway_config
from ix_blackfox.live_gateway.receipts import AuthorityReceiptStore
from ix_blackfox.live_gateway.service import LiveAuthorityGateway


@pytest.fixture
def controller() -> SigningController:
    key = ed25519.Ed25519PrivateKey.generate()
    pem = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
    policy = TrustPolicy.from_dict(
        public_trust_document(pem, "test-key", "deployment", "stream")
    )
    return SigningController(LocalSigner("test-key", "Ed25519", key), policy)


@pytest.fixture
def store(tmp_path: Path, controller: SigningController) -> AuthorityReceiptStore:
    return AuthorityReceiptStore(tmp_path / "receipts.sqlite3", controller)


def denial() -> dict[str, object]:
    return {
        "record_type": "denial",
        "recorded_at": "2026-09-30T00:00:00+00:00",
        "protocol": "blackfox-api/v1",
        "subject": {"agent_id": "test-agent", "tool_name": "filesystem.write_file"},
        "authority_decision": {"status": "block", "reason_codes": ["test_denial"]},
        "authenticated_principal": {},
        "evidence_refs": [],
        "evaluated_evidence_digests": {},
        "single_use_evidence_claims": [],
        "upstream_attempted": False,
        "upstream_status": 0,
        "upstream_response_sha256": "",
        "upstream_error": "test",
        "execution_state": "not_attempted",
        "executed": False,
    }


@pytest.fixture
def signed_gateway(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, controller: SigningController
) -> LiveAuthorityGateway:
    root = Path(__file__).resolve().parents[2]
    for key, value in {
        "BLACKFOX_WAVE14_CI_KEY": "c" * 64,
        "BLACKFOX_WAVE14_HUMAN_KEY": "h" * 64,
        "BLACKFOX_WAVE14_AGENT_TOKEN": "a" * 64,
        "BLACKFOX_WAVE14_OPERATOR_TOKEN": "o" * 64,
    }.items():
        monkeypatch.setenv(key, value)
    config = replace(
        load_gateway_config(root / "examples/wave14/blackfox.gateway.toml"),
        evidence_root=tmp_path / "evidence",
        receipt_database=tmp_path / "receipts.sqlite3",
        identity_revocation_database=tmp_path / "revocations.sqlite3",
    )
    gateway = LiveAuthorityGateway.from_config(config)
    gateway.receipt_store = AuthorityReceiptStore(config.receipt_database, controller)
    return gateway
