from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ix_blackfox.authority_crypto.cli import generate_keys, main
from ix_blackfox.authority_crypto.encoding import AuthorityProofError, read_document
from ix_blackfox.authority_crypto.signing import (
    LocalSigner,
    SigningConfig,
    SigningController,
)
from ix_blackfox.authority_crypto.trust import TrustPolicy
from ix_blackfox.live_gateway.receipts import AuthorityReceiptStore
from tests.authority_crypto.conftest import denial


def test_public_cli_verifies_after_private_key_is_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("TEST_KEY_PASSWORD", "fixture-password-123456789")
    keys = tmp_path / "keys"
    assert (
        main(
            [
                "keygen",
                "--directory",
                str(keys),
                "--password-env",
                "TEST_KEY_PASSWORD",
                "--key-id",
                "key",
                "--deployment-id",
                "deployment",
                "--stream-id",
                "stream",
            ]
        )
        == 0
    )
    policy_path = keys / "trust-policy.json"
    private = keys / "authority-signing-key.pem"
    signer = LocalSigner.load(private, "TEST_KEY_PASSWORD", "key", "Ed25519")
    controller = SigningController(signer, TrustPolicy.load(policy_path))
    store = AuthorityReceiptStore(tmp_path / "receipts.db", controller)
    store.append(denial())
    bundle = store.export_bundle()
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(bundle))
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text(json.dumps(bundle["checkpoint"]))
    private.unlink()
    monkeypatch.delenv("TEST_KEY_PASSWORD")
    del signer, store, controller
    assert (
        main(
            [
                "verify",
                "--bundle",
                str(bundle_path),
                "--trust-policy",
                str(policy_path),
                "--checkpoint",
                str(checkpoint),
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert '"checkpoint_matched": true' in output and "fixture-password" not in output
    assert (
        main(
            [
                "verify",
                "--bundle",
                str(bundle_path),
                "--trust-policy",
                str(policy_path),
                "--allow-unanchored",
            ]
        )
        == 0
    )
    assert '"checkpoint_matched": false' in capsys.readouterr().out
    bundle["receipts"][0]["executed"] = True
    bundle_path.write_text(json.dumps(bundle))
    assert (
        main(
            [
                "verify",
                "--bundle",
                str(bundle_path),
                "--trust-policy",
                str(policy_path),
                "--checkpoint",
                str(checkpoint),
            ]
        )
        == 1
    )


def test_keygen_refuses_overwrite_and_weak_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TEST_KEY_PASSWORD", "short")
    with pytest.raises(AuthorityProofError):
        generate_keys(
            tmp_path / "keys", "TEST_KEY_PASSWORD", "key", "deployment", "stream"
        )
    monkeypatch.setenv("TEST_KEY_PASSWORD", "fixture-password-123456789")
    generate_keys(tmp_path / "keys", "TEST_KEY_PASSWORD", "key", "deployment", "stream")
    with pytest.raises(FileExistsError):
        generate_keys(
            tmp_path / "keys", "TEST_KEY_PASSWORD", "key", "deployment", "stream"
        )
    if os.name != "nt":
        private = tmp_path / "keys/authority-signing-key.pem"
        assert private.stat().st_mode & 0o077 == 0
        private.chmod(0o644)
        with pytest.raises(AuthorityProofError):
            LocalSigner.load(private, "TEST_KEY_PASSWORD", "key", "Ed25519")


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"provider": "local"},
        {"provider": "aws_kms", "private_key": "key"},
        {
            "provider": "local",
            "key_id": "key",
            "algorithm": "Ed25519",
            "trust_policy": "trust",
            "private_key": "key",
            "password_env": "PASSWORD",
            "unknown": "bad",
        },
    ],
)
def test_invalid_signing_configuration_is_rejected_without_fallback(
    tmp_path: Path, payload: dict[str, str]
) -> None:
    with pytest.raises(AuthorityProofError):
        SigningConfig.parse(payload, tmp_path)


def test_verify_requires_explicit_anchor_decision() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["verify", "--bundle", "bundle.json", "--trust-policy", "trust.json"])
    assert exc.value.code == 2


def test_external_services_unrequested_are_not_run_and_exit_nonzero(
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[2]
    env = {**os.environ, "PYTHONPATH": str(root / "src")}
    report = tmp_path / "services.json"
    result = subprocess.run(
        [
            sys.executable,
            str(root / "scripts/validate_wave16_external_services.py"),
            "--output",
            str(report),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    payload = read_document(report)
    assert result.returncode == 1 and payload["passed"] is False
    assert all(
        service["status"] == "NOT_RUN" for service in payload["services"].values()
    )


def test_export_cli_uses_configured_signer_and_refuses_existing_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TEST_KEY_PASSWORD", "fixture-password-123456789")
    keys = tmp_path / "keys"
    generate_keys(keys, "TEST_KEY_PASSWORD", "key", "deployment", "stream")
    policy_path = keys / "trust-policy.json"
    signer = LocalSigner.load(
        keys / "authority-signing-key.pem", "TEST_KEY_PASSWORD", "key", "Ed25519"
    )
    store = AuthorityReceiptStore(
        tmp_path / "signed-receipts.sqlite3",
        SigningController(signer, TrustPolicy.load(policy_path)),
    )
    store.append(denial())
    root = Path(__file__).resolve().parents[2]
    config = tmp_path / "gateway.toml"
    source = (
        (root / "examples/wave14/blackfox.gateway.toml")
        .read_text()
        .replace(
            ".blackfox-artifacts/wave14/authority-receipts.sqlite3",
            "signed-receipts.sqlite3",
        )
    )
    source += '\n[receipt_signing]\nprovider="local"\nkey_id="key"\nalgorithm="Ed25519"\ntrust_policy="keys/trust-policy.json"\nprivate_key="keys/authority-signing-key.pem"\npassword_env="TEST_KEY_PASSWORD"\n'
    config.write_text(source)
    bundle = tmp_path / "exported.json"
    checkpoint = tmp_path / "external.json"
    args = [
        "export",
        "--config",
        str(config),
        "--output",
        str(bundle),
        "--checkpoint-output",
        str(checkpoint),
    ]
    assert main(args) == 0
    assert (
        main(
            [
                "verify",
                "--bundle",
                str(bundle),
                "--trust-policy",
                str(policy_path),
                "--checkpoint",
                str(checkpoint),
            ]
        )
        == 0
    )
    assert main(args) == 1
