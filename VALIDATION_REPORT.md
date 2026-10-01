# IX-BlackFox Wave 16.1 validation report

Version **0.4.1**, validated **2026-10-01 UTC** (2026-09-30 in Arizona). All results below were executed against this hardening source. Earlier release evidence remains historical under `validation/wave16` and `validation/history/wave16_0`.

| Executed environment | Full suite | Ruff | Strict mypy | Live API/MCP proof |
|---|---|---|---|---|
| Linux Python 3.11.16 | **1,784 passed, 0 failed, 0 skipped** (43.68s) | PASS | PASS, 271 files | PASS, 17 checks |
| Linux Python 3.12.14 | **1,784 passed, 0 failed, 0 skipped** (37.43s) | PASS | PASS, 271 files | PASS, 17 checks |
| Linux Python 3.13.15 | **1,784 passed, 0 failed, 0 skipped** (38.66s) | PASS | PASS, 271 files | PASS, 17 checks |

Source/tests/scripts compile successfully. The 0.4.1 wheel builds and installs in a clean environment; its public verifier and live proof run from `/tmp` with isolated Python mode, without the source tree on the import path. The original LICENSE, NOTICE.md and COMMERCIAL.md bytes are unchanged. Complete versions and hashes are in `validation/wave16_1/release-validation.json`.

## Review findings resolved

- Normal signed appends verify one transition using replay-derived private head/authorization/claim state, instead of loading and verifying all prior receipts twice. Startup, external commits, changed trust policy, audit and export retain full verification.
- Signing is outside SQLite transactions. An optimistic generation/policy check guards the short write transaction. Failed inserts do not advance state; conflicting writes retry or refuse.
- Older independently retained checkpoints authenticate a prefix of a newer valid bundle. Rollback, signed forks, malformed counts and wrong-domain prefixes fail.
- Evaluated denials bind subject/decision/principal/evidence and forbid allowed decisions or execution. Minimal pre-evaluation denials have an exact separate historical contract.
- Legacy finite digest bytes are preserved; non-finite values fail. Both canonicalization profiles are documented with fixed byte/hash vectors.

**50 additional hardening tests** cover these cases, cache recovery, concurrent independent stores, detached parent data, signer/SQLite lock ordering and a deterministic 1,000-append no-history-read regression. Baseline reproduction passed all original 1,734 tests before changes.

## Measured signed-append microbenchmark

Python 3.12.14, local Ed25519, minimal pre-evaluation denial, temporary SQLite WAL with synchronous FULL, 25 consecutive appends at each starting count. The comparison loads the preserved original append and verifier source. It does not measure full governed-call latency or a cloud signer. No measurements were extrapolated.

| Existing receipts before batch | Original median append | Hardened median append |
|---|---|---|
| 100 | 145.62 ms | 1.15 ms |
| 500 | 609.84 ms | 1.11 ms |
| 1,000 | Not measured | 1.27 ms |
| 5,000 | Not measured | 1.19 ms |

The hardened stream reached **5,025 receipts** and its full independent audit passed in **3.78s**. Full audit intentionally remains linear. Reproduce using the benchmark command in `docs/wave16-hardening.md`; raw data and original source hashes are included.

**Measured scope:** one long-lived store per stream. Commits from another connection and policy changes deliberately trigger full replay to preserve historical-tamper detection. Sustained multiwriter scalability is not established and can still incur history-dependent recovery cost. Multiple independent stores are tested for bounded concurrency correctness. Replay-derived state uses memory proportional to stream history; production retention and HA remain deployment work.

## Proof interpretation and limits

Each interpreter's real loopback proof passes 17 checks, producing 9 signed receipts and two independently witnessed file writes. The exported public record still verifies in a separate process after temporary private state is removed. The demo IdP, CI evidence and HMAC reviewer are synthetic. Signatures establish the gateway's endorsed statements, not truth of arbitrary side effects or independently attributable human approval.

**Windows and remote GitHub Actions were not executed here.** The Ubuntu/Windows Python 3.11–3.13 workflow is retained; push this source and wait for those jobs before asserting remote CI green. No live AWS KMS, physical HSM, Sigstore issuance, production IdP validation, production load/HA, crash/power-loss campaign, government authorization or certification is claimed. Human personal public-key approvals remain NOT_IMPLEMENTED.

## Reproduce on Windows

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,aws-kms]"
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts/run_wave16_crypto_authority_ci.py --root .
```

`WINDOWS_HANDOFF.md` covers applying this release to an existing Git checkout and pushing it without rewriting repository history.
