from __future__ import annotations

from pathlib import Path

import jsonschema

from ix_blackfox.authority_crypto.encoding import read_document
from ix_blackfox.authority_crypto.trust import TrustPolicy
from ix_blackfox.authority_crypto.verification import verify_bundle
from ix_blackfox.live_gateway.wave16_demo import run_wave16_demo


def test_real_live_proof_artifacts_conform_to_schemas(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    result = run_wave16_demo(tmp_path)
    assert result["passed"]
    artifacts = tmp_path / ".blackfox-artifacts/wave16"
    bundle = read_document(artifacts / "authority-bundle.json")
    trust = read_document(artifacts / "trust-policy.json")
    verification = verify_bundle(
        bundle,
        TrustPolicy.from_dict(trust),
        expected_checkpoint=read_document(artifacts / "external-checkpoint.json"),
    )
    values = {
        "trust-policy": [trust],
        "receipt-bundle": [bundle],
        "crypto-authority-ci-summary": [result],
        "verification": [verification.to_dict()],
        "authority-receipt": bundle["receipts"],
        "dsse-envelope": [
            bundle["checkpoint"],
            *[r["attestation"] for r in bundle["receipts"]],
        ],
    }
    for name, documents in values.items():
        schema = read_document(root / f"schemas/wave16-{name}.schema.json")
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        )
        for document in documents:
            validator.validate(document)
