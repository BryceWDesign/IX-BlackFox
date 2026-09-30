# IX-BlackFox Wave 16 validation report

Version **0.4.0**, validated 2026-09-30. This report describes the reconstructed and delivered source tree. The earlier interrupted workspace's results are not used as validation of this release.

| Executed check | Result |
|---|---|
| Full pytest suite, Linux Python 3.12.14 | **1,734 passed, 0 failed, 0 skipped**, 34.90 seconds |
| Ruff, source/tests/scripts | PASS |
| Strict mypy | PASS, 271 source files |
| Python compileall | PASS |
| Real local API/MCP socket proof | PASS, 17 checks, 9 signed receipts, 2 actual file writes |
| Installed-wheel public verification from `/tmp`, without source on import path | PASS |
| Installed-wheel live socket/file-write proof | PASS |
| Wheel build and clean-environment installation | PASS |
| Original LICENSE, NOTICE.md, COMMERCIAL.md bytes | Unchanged |

The existing 1,615 tests passed after reconstruction; the final suite includes 119 additional security, CLI, schema and proof cases. Logs and machine-readable results are under `validation/wave16`. The main development environment used cryptography 46.0.0; the clean wheel environment used cryptography 50.0.2. Complete tool versions and input/archive licensing hashes are recorded in `release-validation.json`.

## Evidence interpretation

The proof provisions a local synthetic IdP and HMAC CI/reviewer fixtures, then performs two real loopback HTTP file writes. A separate database connection and public-key verifier check each committed authorization before the write. Temporary private keys, receipt database and evidence are removed before a separate process verifies the public bundle.

The shipped public policy is a demo trust fixture. The shipped checkpoint is co-packaged for reproducibility and does not itself prove independent retention. Production trust provisioning and an independently controlled expected-checkpoint channel are deployment responsibilities. Signature verification establishes the gateway's endorsed statement; it does not establish the truth of arbitrary remote side effects or a personal public-key human signature.

## Not executed

Live AWS KMS, physical HSM signing, Cosign binary/Sigstore issuance, production IdP interoperability, production checkpoint retention, performance/load/HA, power-loss/crash campaigns and Windows/Python 3.11/3.13 execution were not performed here. The GitHub Actions matrix is configured, but remote CI was not run. No remote green badge, government authorization, certification or physical key-custody claim is made.

KMS digest signatures are checked using real cryptographic fixtures and a real botocore Stubber API contract. PKCS11 session/key attributes and RSA signatures use contract fixtures. Sigstore subprocess options and failure propagation use fixtures. These tests do not substitute for live external validation. `external-services-NOT_RUN.json` records the expected nonzero result when no external service was requested.

## Reproduce

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,aws-kms]"
.\.venv\Scripts\python.exe -m ruff check src tests scripts
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts/run_wave16_crypto_authority_ci.py --root .
```

See `docs/wave16-cryptographic-authority.md` for trust provisioning, provider configuration, external validation, rotation/revocation and independent public verification. Controlling evaluation-only license terms are preserved. Historical Wave 15 handoff reports remain under `validation/history`, clearly identified as historical.
