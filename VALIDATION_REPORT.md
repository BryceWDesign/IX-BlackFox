# IX-BlackFox 0.5.0 validation report

Wave 17 Enterprise Integration Mesh, validated November 4, 2026. The table contains executed local results against this release source.

| Environment | Complete suite | Ruff | Strict mypy | Real HTTP mesh proof |
| --- | --- | --- | --- | --- |
| Linux Python 3.11.17 | **1,864 passed** (46.69s) | PASS | PASS, 278 files | PASS, 17 checks |
| Linux Python 3.12.14 | **1,864 passed** (45.19s) | PASS | PASS, 278 files | PASS, 17 checks |
| Linux Python 3.13.5 | **1,864 passed** (42.34s) | PASS | PASS, 278 files | PASS, 17 checks |

All three suite runs have zero failures and zero skips. The 79 integration-mesh tests include native request routing, destination-bound approval, scoped request reservations, concurrency, restart recovery, credential isolation, controlled post-dispatch storage failures, cached-result integrity, redirect refusal, named MCP lifecycle routing, audit backoff and dead-event recovery. Focused statement coverage for the mesh package is 92%; coverage does not establish that every possible failure mode has been exercised.

## Executed network proof

Each runtime passes all 17 checks. The proof uses real local HTTP listeners and writes 29 provider-side records only after a separate SQLite reader observes committed public-key signed authorization. It validates native GitHub Check Run and Jira issue payloads, JSON service writes, named MCP initialization/session/discovery and governed tool calls. A denied action causes no provider effect. A duplicate command causes no second effect. Ingress credentials do not reach the provider.

The audit relay delivers all 59 signed receipts. A deliberately rejected first delivery is retried with the same event ID, producing 60 delivery attempts for 59 unique events. Re-synchronization adds no duplicate records. The complete receipt bundle passes the public verifier in a separate process with its pinned test trust policy and retained test checkpoint, with no unresolved authorizations.

These local protocol providers are test infrastructure. No hosted GitHub App, Jira tenant, production MCP service or SIEM account was used. Public proof artifacts are validation fixtures; they are not deployment trust roots or independently operated production anchors.

## Measured local command latency

| Python | Samples | Median | p95 | Maximum |
| --- | --- | --- | --- | --- |
| 3.11.17 | 25 | 31.61 ms | 36.29 ms | 37.17 ms |
| 3.12.14 | 25 | 27.61 ms | 36.89 ms | 38.07 ms |
| 3.13.5 | 25 | 29.65 ms | 40.09 ms | 40.33 ms |

Measurements include client and provider loopback HTTP, identity/evidence/approval evaluation, request reservation, synchronous SQLite FULL/WAL durability, local Ed25519 authorization/outcome signing, independent pre-dispatch observation and response-cache persistence. Evidence issuance occurs outside the timed call. These small local measurements are not a production throughput claim, cloud-signing result, service-level objective or capacity forecast. Raw results accompany each runtime's proof.

## Compatibility and installed package

The real local network proofs for Wave 14, Wave 15 and Wave 16 pass on Python 3.12. The full suite on all three runtimes also preserves their regression coverage. Normal signed append verification retains the Wave 16.1 cache and replay boundaries; this release does not claim a new append-only microbenchmark result or improved multiwriter scalability.

The 0.5.0 wheel builds, installs into an isolated environment and imports all 277 discoverable submodules. All 279 packaged Python source-file bytes match the source tree. Running the mesh network proof from outside the repository in Python isolated mode passes all 17 checks using that installed wheel. Python source in source/tests/scripts parses successfully. License, notice, commercial terms and original logo bytes match the uploaded baseline.

## Reproduce

```console
python -m venv .venv
python -m pip install -e ".[dev,aws-kms]"
python -m ruff check .
python -m mypy src
python -m pytest -q
python scripts/run_wave14_live_gateway_ci.py --root .
python scripts/run_wave15_enterprise_identity_ci.py --root .
python scripts/run_wave16_crypto_authority_ci.py --root .
python scripts/run_wave17_integration_mesh_ci.py --root .
```

Activate the virtual environment or invoke its Python executable directly. Dependency versions, exact tested-file hashes, preserved-asset hashes, raw test/type/lint logs, public proof artifacts and installed-wheel results are under `validation/wave17`. The current source inventory digest is `66389d88f4fd4e023fe6e92e1c9c93114a7f37d44ccf9a54f12e7fd38981556b`.

## Deployment boundaries

GitHub Actions workflows are configured for Ubuntu/Windows and Python 3.11–3.13. Remote Actions and Windows were not executed locally. Production throughput, high availability, hosted provider permissions, live IdP/KMS/HSM/Sigstore integrations, independent production checkpoint retention and external certification remain outside these executed results. Human approval retains the existing HMAC-authenticated evidence contract rather than personal public-key approval signatures.

Mesh command reservations deliberately preserve ambiguous outcomes for reconciliation. There is no exactly-once external execution claim, distributed transaction, automatic command replay, retention pruning or automatic reservation repair. Audit delivery is at least once and requires receiver deduplication. See `docs/wave17-enterprise-integration-mesh.md` for the operational contract.
