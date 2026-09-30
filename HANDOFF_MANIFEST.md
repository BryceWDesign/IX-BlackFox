# IX-BlackFox Wave 16 full handoff

Release **0.4.0**, Cryptographic Authority Receipts and Externally Anchored Trust.

## Delivered behavior

Configured live gateways commit signed authorization before governed API/MCP dispatch, reevaluate current identity/evidence/trust, and append a linked signed outcome observation. Failure before dispatch refuses execution; failure to record an outcome after dispatch reports uncertainty and prevents an unsafe retry. Historical configurations remain in their original unsigned mode.

## Contents

- Complete original project source, tests, documentation, schemas, workflows and assets, plus the Wave 16 extension.
- `src/ix_blackfox/authority_crypto`: canonical encoding, DSSE and pinned public trust, encrypted local/KMS/PKCS11 signers, public stream verifier, CLI and optional Cosign adapter.
- Integrated live gateway, real socket/file-write proof and external-service validator.
- Adversarial security, provider-contract, CLI, schema and live runner tests.
- Six Wave 16 public schemas; Ubuntu/Windows Python 3.11–3.13 CI configuration.
- Operator contract, claims ledger, changelog and roadmap.
- Public proof artifacts and validation logs under `validation/wave16`.
- `dist/ix_blackfox-0.4.0-py3-none-any.whl`, verified in an isolated environment.
- `FILE_MANIFEST.json`, per-file hashes excluding the manifest itself; the ZIP SHA-256 is supplied alongside the ZIP.

## Acceptance evidence

1,734 tests pass; Ruff and strict mypy pass; source and installed-wheel live proofs pass. Consult `VALIDATION_REPORT.md` and the machine-readable release validation. Live AWS/HSM/Sigstore and remote CI remain unrun. No real credentials, signing private keys, runtime SQLite databases, virtual environments or caches are included.

## First steps

Extract the ZIP, open the contained repository directory and use the README PowerShell commands to create a virtual environment and reproduce the proof. Preserve the evaluation-only LICENSE/NOTICE/COMMERCIAL terms. Provision your own IdP, signing keys, trusted public policy, evidence issuers, protected upstream access and independent checkpoint retention before evaluating a deployment. The supplied public proof keys are demo fixtures.
