# IX-BlackFox 0.7.0 validation report

Wave 19 Closed-Loop Verification was validated on November 6, 2026, on Debian GNU/Linux 13, x86-64, kernel 6.18.57.

| Python | Complete suite | Governed operations suite | Ruff | Strict mypy | Wave 17 network proof | Wave 19 network proof |
| --- | --- | --- | --- | --- | --- | --- |
| 3.11.17 | 1,906 passed, 70.94 s | 41 passed | Pass | 287 files, pass | 17 checks passed | Pass |
| 3.12.14 | 1,906 passed, 62.14 s | 41 passed | Pass | 287 files, pass | 17 checks passed | Pass |
| 3.13.5 | 1,906 passed, 70.20 s | 41 passed | Pass | 287 files, pass | 17 checks passed | Pass |

The complete suites had zero failures and zero skips. Each includes 1,889 preserved Wave 18 cases and 17 additional verification cases. The environment used pytest 9.2.0, Ruff 0.5.7, mypy 1.20.2, boto3 1.43.125, cryptography 50.0.2 and PyJWT 2.15.1. SQLite was 3.53.1 for Python 3.11 and 3.12 and 3.46.1 for Python 3.13. See [recorded commands and outputs](validation/wave19/) and the [Wave 18 baseline](validation/wave18/REPORT.md).

The live quota run applied and verified quota 8. A separate write for quota 20 returned HTTP 200, but an independently signed read observed quota 10. The tampered provider envelope received HTTP 403 and a verified closure received HTTP 409. A new authorized operation restored quota 8 and satisfied the signed rollback and boundary-test criteria. Both closure bundles were verified offline. A separate artifact audit reproduced eight signed collector results from the raw files in the [public proof](validation/wave19/public-proof/).

The integration runners for Waves 6, 7, 8, 9 and 11–16 passed on Python 3.12. The Wave 17 runner passed on all three Python versions. All 15 workflow files passed actionlint 1.7.7. The wheel and source distribution built successfully and passed Twine's strict metadata check. The installed wheel reported version 0.7.0, imported all 286 discoverable submodules, completed the quota proof and passed all 1,906 tests in a clean Python 3.12 environment with the AWS SDK extra installed.

## Reproduce local checks

Use each Python version from the table with its own environment. The recorded Linux runs installed the dev and AWS SDK extras with `uv pip install --python <interpreter> -e '.[dev,aws-kms]'`. The equivalent pip command appears below.

```console
python -m pip install -e ".[dev,aws-kms]"
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
python -m ruff check .
python -m mypy src
python -m pytest -q
python -m pytest -q tests/autonomy
python examples/wave19/run.py --output wave19-proof
python -I validation/wave19/audit_proof.py wave19-proof
python scripts/run_wave17_integration_mesh_ci.py --root . --output wave17-proof
actionlint -version
actionlint
```

The earlier integration runs used the checked-out validation revision as the head binding.

```bash
sha=$(git rev-parse HEAD)
for wave in 6_sandbox 7_model_repair 8_repository_intelligence 9_compliance_audit 11_agent_identity 12_assurance 13_review_board; do
  python "scripts/run_wave${wave}_ci.py" --head-sha "$sha"
done
for wave in 14_live_gateway 15_enterprise_identity 16_crypto_authority; do
  python "scripts/run_wave${wave}_ci.py" --root .
done
```

Packaging used `python -m build --outdir ../build-release` and `python -m twine check --strict ../build-release/*`. In a separate Python 3.12 environment, install the generated wheel with the `[dev,aws-kms]` extras and run `blackfox verification --help`, `python examples/wave19/run.py --output wheel-proof`, and `python -m pytest -q -o pythonpath=` from the source checkout. The empty pytest source-path override exercises the installed package. The quota example invokes `python -m ix_blackfox.verification.cli verify` in a separate process with the operation ID and all four pinned public policies.

## Scope

Local validation used loopback HTTP providers, SQLite, software Ed25519 signing and local test identities. Tests cover response loss across restart, persisted reservations, duplicate and conflicting evidence, altered signatures, role separation and revocation, stale evidence, concurrent follow-up approval and rollback failure. Live vendor endpoints, Windows runners and hosted GitHub Actions were not executed. The hosted check command `gh run list --repo BryceWDesign/IX-BlackFox --limit 1` stopped because no authenticated GitHub session was available.

See the [release audit](validation/wave19/RELEASE_AUDIT.md) and [verification boundary](docs/wave19-closed-loop-verification.md#verification-boundary).
