from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ix_blackfox.authority_crypto.cli import public_trust_document
from ix_blackfox.authority_crypto.signing import LocalSigner, SigningController
from ix_blackfox.authority_crypto.trust import TrustPolicy
from ix_blackfox.live_gateway.receipts import AuthorityReceiptStore


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
