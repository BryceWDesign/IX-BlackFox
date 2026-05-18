<p align="center">
  <img src="IX-BlackFox-Logo.png" alt="IX-BlackFox Logo">
</p>

# IX-BlackFox

**AI proposes. Humans decide.**

## The control gap IX-BlackFox addresses

AI coding agents are moving into real software pipelines. That creates a control problem most organizations are not ready to prove: when an agent proposes a code change, can the team show what it attempted, what was allowed, what was blocked, what tests ran, what evidence was produced, and where a human made the final decision?

IX-BlackFox is built around that gap. It creates a governed execution layer for AI-assisted code-change workflows: policy gates, sandbox receipts, bounded workspace rules, deny-by-default execution controls, human approval checkpoints, test evidence, PR evidence packs, and tamper-evident run records.

The operating principle is not to stop teams from using AI. It is to make AI-assisted engineering work bounded, inspectable, evidence-producing, and human-reviewable.

IX-BlackFox is aimed at DevSecOps, platform engineering, security, compliance, and regulated software teams that want AI coding agents without losing control of the software delivery process.

## Technical summary

IX-BlackFox is a source-available governed AI engineering control plane for bounded patch-test-verify workflows.

The goal is not uncontrolled autonomous coding. The goal is a reviewable engineering runtime that can accept AI-assisted repair proposals only as untrusted inputs, route them through policy gates, execute controlled validation, preserve receipts, and expose evidence for human review.

## Current status

**Current stage: Wave 6 prototype/evidence layer implemented.**

IX-BlackFox has evolved beyond the Wave 5 organization-workflow layer into an early Wave 6 sandbox-evidence layer.

Wave 6 does **not** mean the project is production-ready, certified, defense-approved, or safe for operational deployment. In this repository, Wave 6 means the prototype now contains a hardened-execution-oriented evidence boundary:

- isolated workspace lifecycle
- container sandbox backend
- deny-all default egress policy
- egress audit decisions
- artifact manifests
- sandbox run receipts
- local signed artifact statements
- adversarial sandbox validation reports
- CI evidence generation for Wave 6 sandbox checks

This is still a research prototype. It is intended to make AI-assisted engineering actions more bounded, inspectable, testable, and reviewable.

## Implemented waves

| Wave | Status | Meaning |
|---:|---|---|
| 1 | Implemented | Governed multi-brain runtime scaffold |
| 2 | Implemented | Governed local patch-test-verify control plane |
| 3 | Implemented | Governed patch authoring and repair intelligence |
| 4 | Implemented | Reliability lab with scenario suites, adversarial tests, and repair metrics |
| 5 | Implemented | Organization-grade workflow with PR evidence packs, approvals, and CI integration |
| 6 | Prototype evidence layer implemented | Hardened sandbox execution layer with isolated workspaces, signed artifacts, and egress controls |

## Wave 6 scope currently implemented

The current Wave 6 layer includes:

| Area | Purpose |
|---|---|
| `src/ix_blackfox/sandbox/contracts.py` | Defines sandbox profiles, command requests, results, network policy, filesystem policy, resource limits, and deterministic digests |
| `src/ix_blackfox/sandbox/workspace.py` | Creates isolated workspace roots, stages declared mounts, rejects path escape and symlink abuse, and collects artifact manifests |
| `src/ix_blackfox/sandbox/container.py` | Builds and runs container sandbox commands using deny-all network, read-only root, dropped capabilities, no-new-privileges, resource limits, and declared mounts |
| `src/ix_blackfox/sandbox/local_audit.py` | Provides compatibility/dev execution evidence only; it is explicitly not hardened isolation |
| `src/ix_blackfox/sandbox/egress.py` | Produces auditable egress decisions for deny-all, allowlist, proxy-logged, and offline-cache network modes |
| `src/ix_blackfox/sandbox/receipt.py` | Binds sandbox command requests, results, profiles, network policy digests, artifact manifests, and egress audit bundles into receipts |
| `src/ix_blackfox/sandbox/signing.py` | Provides local deterministic HMAC-SHA256 signed artifact statements and verification reports |
| `src/ix_blackfox/sandbox/adversarial.py` | Produces adversarial validation reports for egress, receipt, path escape, symlink, and policy-block scenarios |
| `src/ix_blackfox/workflow/sandbox_receipt_evidence.py` | Converts sandbox receipt bundles into PR evidence artifacts and verifies them |
| `src/ix_blackfox/workflow/sandbox_adversarial_evidence.py` | Converts adversarial reports into PR evidence artifacts and verifies them |
| `.github/workflows/wave6-sandbox-evidence.yml` | Runs Wave 6 sandbox/evidence/adversarial tests and uploads a Wave 6 CI evidence payload |
| `scripts/run_wave6_sandbox_ci.py` | Generates deterministic Wave 6 sandbox CI evidence |

## Core trust boundary

Model output is never treated as authority.

A model may propose a repair, comment on evidence, or provide advisory review. It cannot approve itself, satisfy human authority, bypass sandbox policy, or make a change merge-ready by itself.

The core rule is:

> AI may propose. IX-BlackFox must gate, sandbox, test, record, and route for review. Humans retain authority.

## Wave 5 evidence gate

The Wave 5 gate can block a pull request when:

- required evidence artifacts are missing
- required evidence artifacts are missing SHA-256 digests
- required evidence artifacts are missing byte sizes
- required evidence artifacts are empty
- required evidence artifacts are not bound to the PR head SHA
- changed files are not declared
- governance receipts are missing
- reliability evidence is missing when required
- CI evidence is missing
- required CI checks are missing, pending, cancelled, timed out, or failed
- CI evidence does not match the PR repository
- CI evidence does not match the PR head SHA
- human approval is missing
- only model approval is present
- the PR author attempts to satisfy the human approval requirement
- any review rejects the change or requests changes

## Wave 6 sandbox evidence gate

The Wave 6 layer adds additional fail-closed evidence expectations:

- sandbox receipt bundles must be present when required
- sandbox receipt bundles must be bound to the PR head SHA
- local-audit receipts cannot satisfy hardened sandbox evidence
- sandbox receipts must use allowed hardened backend kinds
- sandbox receipts must bind artifact manifest digests when required
- sandbox receipts must bind egress audit bundle digests when required
- sandbox adversarial reports must be present when required
- sandbox adversarial reports must pass required scenarios
- sandbox adversarial reports must be bound to the PR head SHA
- sandbox artifacts must include deterministic digests and sizes
- signed artifact statements must verify against an allowed signer/key when checked

## Local Wave 5 PR gate command

Example:

```
python -m ix_blackfox.interface.cli workflow pr-gate \
  --evidence-pack artifacts/wave5/pr-evidence-pack.json \
  --ci-evidence artifacts/wave5/ci-evidence.json \
  --required-check pytest \
  --json
```
The command returns:

0 when the PR gate passes
1 when the PR gate blocks merge readiness
2 when input files or JSON structures are invalid
Wave 6 CI evidence command

Example:
```
python scripts/run_wave6_sandbox_ci.py --head-sha "$(git rev-parse HEAD)"
```

Default output:
```
.blackfox-artifacts/wave6/wave6-sandbox-ci-report.json
```
The generated payload includes:

Wave 6 adversarial report
adversarial verification result
PR evidence artifact representation
head-SHA binding
bounded claim note
GitHub Actions integration

Wave 5 workflow:
```
.github/workflows/wave5-pr-gate.yml
```

Wave 6 workflow:
```
.github/workflows/wave6-sandbox-evidence.yml
```

The Wave 6 workflow intentionally verifies the sandbox contracts, egress decisions, receipt evidence, adversarial harness, and CI payload generation without requiring Docker execution in CI. Container command construction and backend behavior are covered by tests using a fake executor so GitHub Actions remains stable and repeatable.

Local-audit backend warning

local_audit is not hardened isolation.

It exists for compatibility, local development, policy checking, and receipt/evidence shape validation. It must not be used as proof that untrusted code was isolated from the host.

Only allowed hardened backend kinds such as container, gvisor, or firecracker may satisfy hardened sandbox evidence checks. The current implemented real backend is the Docker-style container backend.

Container backend warning

The container backend applies security-oriented runtime flags such as:

deny-all network
read-only root filesystem
dropped Linux capabilities
no-new-privileges
process limits
memory limits
CPU limits
declared mounts only

This is useful sandbox-hardening evidence, but it is not a production security certification. The backend should be treated as a research prototype execution boundary until it is independently reviewed, stress-tested, and operated inside a properly hardened host environment.

Signed artifact warning

Wave 6 includes local HMAC-SHA256 signed artifact statements.

This proves that IX-BlackFox can bind artifact identity, signer identity, PR head SHA, profile digest, artifact manifest digest, and canonical statement body into a verifiable local signature.

It does not claim Sigstore, Rekor, GitHub artifact attestation, SLSA compliance, or public PKI verification. Those are future maturity paths, not current claims.

Testing

From the repository root:
```
python -m pytest
```
Useful targeted checks:
```
python -m pytest tests/workflow
python -m pytest tests/sandbox
python -m pytest tests/ci
python -m compileall -q src tests scripts
```
Wave 6 targeted check:
```
python -m pytest \
  tests/sandbox \
  tests/workflow/test_sandbox_receipt_evidence.py \
  tests/workflow/test_sandbox_adversarial_evidence.py \
  tests/ci/test_wave6_sandbox_ci_integration.py \
  -q
```
What IX-BlackFox does not claim

IX-BlackFox does not claim:

production readiness
safety certification
security certification
compliance certification
procurement status
official defense affiliation
autonomous authority
autonomous deployment approval
autonomous operational control
that any AI-generated repair is correct without evidence
that a local-audit run is hardened sandbox evidence
that a Docker/container run is equivalent to formal certification
that local HMAC signatures are equivalent to Sigstore, Rekor, SLSA, or public PKI attestation

This is a research prototype and governed engineering control-plane experiment, not an operational system.

Locked roadmap

| Wave | Locked meaning                                                                                                        |
| ---: | --------------------------------------------------------------------------------------------------------------------- |
|    1 | Governed multi-brain runtime scaffold                                                                                 |
|    2 | Governed local patch-test-verify control plane                                                                        |
|    3 | Governed patch authoring and repair intelligence                                                                      |
|    4 | Reliability lab with scenario suites, adversarial tests, and repair metrics                                           |
|    5 | Organization-grade workflow with PR evidence packs, approvals, and CI integration                                     |
|    6 | Hardened sandbox execution layer with isolated workspaces, signed artifacts, and egress controls                      |
|    7 | Model-agnostic repair intelligence with model comparison, routing, budget controls, and provider abstraction          |
|    8 | Repository intelligence layer with code graph, dependency mapping, impact analysis, and architectural memory          |
|    9 | Compliance/audit attestation layer with policy packs, evidence standards, reviewer signoff, and governance reports    |
|   10 | Full AI engineering operating system: multi-repo, multi-team, policy-governed, measurable, replayable, and reviewable |

This roadmap is the spine. It should not be renumbered or replaced.

Engineering principle

IX-BlackFox evolves through controlled engineering optimization, not uncontrolled mutation.

Every serious capability should be:

bounded
testable
auditable
reversible
policy-gated
evidence-producing
human-reviewable
honest about uncertainty
License

IX-BlackFox is governed by the IX-BlackFox Source-Available Evaluation License v1.0 beginning with the license-transition commit.

The current source is available for review and limited noncommercial, non-operational evaluation only. Commercial use, production use, hosted-service use, redistribution, modification, derivative deployment, government operational use, agency operational use, contractor use, procurement use, funded-pilot use, or organization-backed use requires prior written permission and a separate license agreement with Bryce Lovell.

Earlier versions released under Apache License 2.0 remain governed by their original license terms. Current license details are documented in LICENSE, COMMERCIAL.md, and NOTICE.md.
