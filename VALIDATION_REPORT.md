# IX-BlackFox 0.6.0 validation report

Wave 18 Governed Autonomy, validated on Linux on November 5, 2026.

| Python | Complete suite | Wave 18 suite | Ruff | Strict mypy | Wave 17 HTTP proof |
| --- | --- | --- | --- | --- | --- |
| 3.11.17 | 1,889 passed (65.70s) | 24 passed | Pass | Pass | 17 passed |
| 3.12.14 | 1,889 passed (48.54s) | 24 passed | Pass | Pass | 17 passed |
| 3.13.5 | 1,889 passed (59.42s) | 24 passed | Pass | Pass | 17 passed |

The three complete suite runs include the AWS SDK contract tests and have zero failures and zero skips. The focused Wave 18 suite includes real gateway and provider sockets, a separate read of provider effects, a separate verifier of signed pre-dispatch authorization, and a two-agent plan. Tests exercise direct-route bypass attempts, rejected or revoked authority, concurrency, changing conditions, stale observations, attempt and cost limits, recovery obligations, ambiguous transport across restart, and a simulated storage failure after the provider writes.

The earlier proof scripts for Waves 6, 7, 8, 9, and 11–16 ran successfully on Python 3.12. The Wave 17 proof ran on all three Python versions. Its signed receipt stream passed verification in a separate process. All 14 GitHub workflow files passed static validation with actionlint 1.7.7.

The 0.6.0 wheel built and installed in an isolated Python 3.12 environment. All 281 discoverable submodules imported. The installed package passed all 24 Wave 18 cases and 1,888 full-suite cases, with one optional AWS SDK case skipped because the wheel environment used the dev extra only.

Local validation covers loopback providers, the configured SQLite stores, local signing, and locally issued federated credentials. Hosted GitHub Actions, Windows execution, and production provider qualification remain pending. The recorded results are in [validation/wave18](validation/wave18/). Earlier release results remain in their versioned validation directories.

## Reproduce

```console
python -m pip install -e ".[dev,aws-kms]"
python -m ruff check .
python -m mypy src
python -m pytest -q
python -m pytest -q tests/autonomy
python scripts/run_wave17_integration_mesh_ci.py --root .
```
