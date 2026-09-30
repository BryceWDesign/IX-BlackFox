# IX-BlackFox Wave 15 Validation Report

**Version:** 0.3.0  
**Wave:** 15 — Enterprise Identity & Delegated Authority  
**Validation date:** 2026-09-23

## Result

Wave 15 is implemented as a real extension of the live Wave 14 authority gateway.
The release adds federated workload identity, bounded delegated authority,
revocation, identity-bound action subjects, live-network proof, operator controls,
CI coverage, schemas, and documentation while preserving Wave 14 behavior for
static-token deployments.

## Executed validation

### Python compilation

`python -m compileall -q src tests scripts`

**Result:** PASS

### Repository test suite

The complete suite was executed in partitions because the execution sandbox kills
one monolithic pytest process before completion. Every collected test was still
executed.

- Partition A: **797 passed**
- Partition B: **347 passed**
- Partition C: **471 passed**
- **Total: 1,615 passed, 0 failed**

### Wave 15 focused suite

Wave 15 enterprise-identity tests, CI contracts, docs contracts, and the existing
live-gateway suite were executed together.

**Result:** PASS

### Real-network Wave 15 proof

`PYTHONPATH=src python scripts/run_wave15_enterprise_identity_ci.py --root <validation-root>`

**Result:** PASS

The proof demonstrated:

- static agent credentials rejected in `federated_required` mode: HTTP 401
- wrong-audience signed token rejected: HTTP 401
- expired signed token rejected: HTTP 401
- signed token missing required delegation rejected: HTTP 401
- out-of-scope delegated request blocked: HTTP 403
- upstream invocations after all denied cases: **0**
- authorized federated request executed: HTTP 200
- upstream invocations after allowed request: **1**
- token revoked by `jti` then rejected: HTTP 401
- upstream invocations after revocation attempt: **1**
- real upstream file side effect matched expected content
- authenticated identity-context digest matched the digest bound into the exact authority subject
- durable authority receipt chain verified with zero issues

The machine-readable proof is retained at:

`validation/wave15-enterprise-identity-summary.json`

### Packaging

Editable installation and wheel construction were tested using the locally
available build toolchain with build isolation disabled because the sandbox cannot
resolve PyPI.

**Result:** PASS

A standard wheel for `ix-blackfox 0.3.0` was produced successfully during
validation.

## Lint/type-check tooling limitation

The repository CI definition still requires:

- `python -m ruff check src tests scripts`
- `python -m mypy src`

Those two exact commands could not be executed in this sandbox because Ruff and
mypy are not installed here and outbound package installation is blocked by DNS.
An attempted installation failed before downloading any package. This report does
**not** label unexecuted tooling as passed.

The Wave 15 GitHub Actions workflow installs `.[dev]` and runs both gates on
Python 3.11, 3.12, and 3.13 before the full pytest suite and the live-network
proof. The handoff should therefore be considered locally test-green and
build-green, with Ruff/mypy requiring the normal connected CI environment for
final confirmation.

## Claim boundary

Wave 15 provides implementation evidence for federated workload identity,
short-lived signed credentials, least-privilege delegation, revocation,
pre-upstream enforcement, human-review composition, and durable traceability.

It does **not** claim DoD authorization, ATO/cATO, FedRAMP authorization, AWS
certification, production IdP integration, HSM/KMS custody, globally distributed
revocation, or an external transparency log.
