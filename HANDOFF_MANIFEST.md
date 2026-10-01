# IX-BlackFox Wave 16.1 full handoff

Release **0.4.1**, signed-ledger performance and verifier hardening.

Complete source, tests, documentation, public schemas, GitHub workflows, original assets and unchanged evaluation-only license terms are included. `dist/ix_blackfox-0.4.1-py3-none-any.whl` is the installable release. `FILE_MANIFEST.json` hashes every delivered file except itself; the ZIP digest is supplied alongside the ZIP. No Git metadata, virtual environments, private signing keys, credentials, runtime databases or caches are packaged.

## Evidence

1,784 tests pass with no failures or skips on Linux Python 3.11, 3.12 and 3.13. Ruff, strict mypy (271 source files), compileall, 17-check socket/file-write proofs and clean installed-wheel public/live verification pass. Measured normal signed appends remain approximately 1.1–1.3 ms through 5,000 receipts in this local microbenchmark. Full recovery/audit and independent-writer commits retain history-dependent replay. See `VALIDATION_REPORT.md` for precise measurements and limits.

Current evidence is under `validation/wave16_1`; the earlier Wave 16 evidence is historical. `docs/wave16-hardening.md` explains cache trust, recovery, multiwriter boundaries, denial contracts and both encoding profiles. Fixed vectors are in `examples/wave16/canonicalization-vectors.json`; original benchmark sources are preserved as text under `validation/wave16_1/baseline-source`.

## Apply and verify

Follow `WINDOWS_HANDOFF.md`. Use the existing Git checkout to preserve its history. Install `.[dev,aws-kms]`, run lint/types/tests/proof, inspect the diff, then commit and push. Remote Ubuntu/Windows Python 3.11–3.13 CI must run after the push; this local handoff cannot guarantee or claim that remote result.

Approval remains HMAC-authenticated evidence. Live AWS/HSM/Sigstore, production IdP, production throughput/HA, independent checkpoint service and certification remain unvalidated or unprovisioned. No private credentials or physical key-custody claim is introduced.
