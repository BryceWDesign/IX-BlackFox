<p align="center">
  <img src="IX-BlackFox-Logo.png" alt="IX-BlackFox Logo">
</p>

# IX-BlackFox

**AI proposes. Humans decide.**

IX-BlackFox is a source-available governed AI engineering control plane for bounded patch-test-verify workflows.

It is designed for the hard control problem around AI-assisted software engineering: when a model proposes a code change, can the team prove what was requested, what the model produced, what was compared, what was selected or blocked, what policy gates applied, what sandbox evidence was created, what receipts were preserved, and where human authority remained in control?

The goal is not uncontrolled autonomous coding.

The goal is a reviewable engineering runtime that treats model output as untrusted input, routes it through explicit policy and evidence gates, preserves receipts, and exposes the result for human review.

## The control gap IX-BlackFox addresses

AI coding agents are moving into real software pipelines. That creates a control problem most organizations are not ready to prove:

- What did the model attempt?
- What was allowed?
- What was blocked?
- Which model or provider was selected?
- Which model or provider was rejected?
- Why was one proposal preferred over another?
- Was the selected model also allowed to review itself?
- What tests ran?
- What sandbox/evidence boundary was used?
- What receipts were created?
- What evidence was exported?
- Where did a human make the final decision?

IX-BlackFox is built around that gap.

It creates a governed execution and evidence layer for AI-assisted code-change workflows: model routing, proposal comparison, role separation, policy gates, sandbox receipts, bounded workspace rules, deny-by-default execution controls, human approval checkpoints, test evidence, PR evidence packs, and tamper-evident run records.

The operating principle is not to stop teams from using AI.

The operating principle is to make AI-assisted engineering work bounded, inspectable, evidence-producing, and human-reviewable.

IX-BlackFox is aimed at DevSecOps, platform engineering, security, compliance, and regulated software teams that want AI coding assistance without losing control of the software delivery process.

## Current status

**Current stage: Wave 7 prototype/evidence layer implemented.**

IX-BlackFox has evolved beyond the Wave 6 sandbox-evidence layer into an early Wave 7 model-agnostic repair intelligence layer.

Wave 7 does **not** mean the project is production-ready, certified, defense-approved, compliance-approved, or safe for operational deployment.

In this repository, Wave 7 means the prototype now contains evidence-producing machinery for model-agnostic repair selection:

- provider-neutral brain/provider contracts
- provider health and budget evaluation
- budget-aware routing evidence
- deterministic model-output comparison
- model-role tribunal separation
- self-review prevention
- brain-backed patch proposal provider bridge
- multi-model repair proposal selection
- selected/rejected/blocked model evidence
- Wave 7 repair evidence ledger
- Wave 7 evidence export
- Wave 7 operator summary rendering
- Wave 7 verification summary rendering
- Wave 7 CI evidence generation

This remains a research prototype and governed engineering control-plane experiment.

## Implemented waves

| Wave | Status | Meaning |
|---:|---|---|
| 1 | Implemented | Governed multi-brain runtime scaffold |
| 2 | Implemented | Governed local patch-test-verify control plane |
| 3 | Implemented | Governed patch authoring and repair intelligence |
| 4 | Implemented | Reliability lab with scenario suites, adversarial tests, and repair metrics |
| 5 | Implemented | Organization-grade workflow with PR evidence packs, approvals, and CI integration |
| 6 | Prototype evidence layer implemented | Hardened sandbox execution layer with isolated workspaces, signed artifacts, and egress controls |
| 7 | Prototype evidence layer implemented | Model-agnostic repair intelligence with model comparison, routing, budget controls, and provider abstraction |

## Core trust boundary

Model output is never treated as authority.

A model may propose a repair, comment on evidence, generate a candidate patch proposal, or provide advisory review.

It cannot:

- approve itself
- satisfy human authority
- bypass policy
- bypass sandbox controls
- bypass workspace boundaries
- claim tests passed without evidence
- make a change merge-ready by itself
- convert a selected proposal into authorized execution

The core rule is:

> AI may propose. IX-BlackFox must gate, compare, sandbox, test, record, and route for review. Humans retain authority.

## Wave 7 scope currently implemented

The current Wave 7 layer includes:

| Area | Purpose |
|---|---|
| `src/ix_blackfox/brains/comparison.py` | Defines deterministic comparison contracts for model repair candidates, selected/rejected/blocked findings, score components, and comparison decisions |
| `src/ix_blackfox/brains/health.py` | Evaluates provider health, provider topology, latency, cost class, context budget, and eligibility before routing |
| `src/ix_blackfox/brains/router.py` | Adds health-aware and budget-aware routing evidence to brain selection |
| `src/ix_blackfox/brains/tribunal.py` | Enforces role separation around generator, critic, security reviewer, policy reviewer, evidence reviewer, and human review coordinator roles |
| `src/ix_blackfox/runtime/brain_proposal.py` | Bridges provider-neutral brain outputs into the existing patch proposal provider interface without granting execution authority |
| `src/ix_blackfox/runtime/brain_repair.py` | Compares multiple model repair proposal sources, selects one candidate, and blocks release when separated review fails |
| `src/ix_blackfox/runtime/brain_repair_evidence.py` | Records Wave 7 repair selection receipts, chained evidence, selection exports, and export receipts |
| `src/ix_blackfox/runtime/wave7_report.py` | Produces operator-readable and verification-readable Wave 7 reports |
| `scripts/run_wave7_model_repair_ci.py` | Generates deterministic offline Wave 7 model repair CI evidence |
| `.github/workflows/wave7-model-repair-evidence.yml` | Runs Wave 7 model repair evidence tests and uploads Wave 7 evidence artifacts |

## What Wave 7 proves in this repository

Wave 7 proves that IX-BlackFox can represent and test the following control path:

1. Multiple model/provider repair proposal sources exist.
2. Each proposal is treated as untrusted output.
3. Candidate proposals are scored with explicit comparison criteria.
4. The selected proposal is chosen deterministically.
5. Rejected and blocked candidates are recorded.
6. A tribunal role-separation check runs before release.
7. A model/provider cannot be the sole reviewer of its own repair candidate.
8. A selected candidate can be released only as a downstream proposal.
9. Selection evidence is recorded into a chained ledger.
10. Evidence is exported into reviewable JSON.
11. Operator and verification summaries explain what happened.
12. CI can generate a Wave 7 evidence artifact without requiring real model credentials.

## What Wave 7 does not prove

Wave 7 does not prove:

- the selected model-generated proposal is correct
- the selected model-generated proposal is safe
- the selected model-generated proposal should be merged
- tests passed
- deployment is authorized
- production readiness exists
- certification exists
- a model is trustworthy
- a provider is trustworthy
- autonomous execution is authorized
- human approval has been satisfied

Wave 7 adds evidence-producing model repair selection. It does not replace the rest of the governed patch-test-verify chain.

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

## Wave 7 model repair evidence gate

The Wave 7 layer adds evidence expectations around model repair selection:

- candidate repair proposals must be treated as untrusted model output
- comparison candidates must carry provider/model identity
- comparison candidates must carry deterministic score components
- selected, rejected, and blocked candidates must be reviewable
- provider health and budget eligibility must be visible in routing evidence
- model/provider selection must be deterministic
- role separation must prevent self-review
- a generator model must not satisfy review authority over its own output
- tribunal review must be routed or the selected proposal must be blocked
- selected proposal output must be bound by digest
- repair selection evidence must be exported
- chained evidence receipts must verify
- CI evidence must be generated without requiring live model access

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

Wave 7 CI evidence command

Example:
```
python scripts/run_wave7_model_repair_ci.py --head-sha "$(git rev-parse HEAD)"
```
Default output:
```
.blackfox-artifacts/wave7/wave7-model-repair-ci-report.json
```
The generated Wave 7 payload includes:

selected model repair source
selected model/brain identity
model comparison decision
selected/rejected/blocked candidate records
separated tribunal review decision
selected proposal digest
chained repair evidence receipts
exported Wave 7 selection evidence
bounded claim note

The Wave 7 CI scenario is deterministic and offline. It uses static provider outputs so GitHub Actions can verify the Wave 7 model comparison, role separation, and evidence export contracts without requiring model credentials, network access, Ollama, vLLM, OpenAI-compatible services, or local model servers.

GitHub Actions integration

Wave 5 workflow:
```
.github/workflows/wave5-pr-gate.yml
```
Wave 6 workflow:
```
.github/workflows/wave6-sandbox-evidence.yml
```
Wave 7 workflow:
```
.github/workflows/wave7-model-repair-evidence.yml
```
The Wave 6 workflow intentionally verifies the sandbox contracts, egress decisions, receipt evidence, adversarial harness, and CI payload generation without requiring Docker execution in CI. Container command construction and backend behavior are covered by tests using a fake executor so GitHub Actions remains stable and repeatable.

The Wave 7 workflow intentionally verifies model repair comparison, separated tribunal review, evidence ledger export, and CI payload generation without requiring live model execution. This keeps the evidence test stable, repeatable, and reviewable.

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
python -m pytest tests/brains
python -m pytest tests/runtime
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
Wave 7 targeted check:
```
python -m pytest \
  tests/brains \
  tests/runtime/test_brain_proposal.py \
  tests/runtime/test_brain_repair.py \
  tests/runtime/test_brain_repair_evidence.py \
  tests/runtime/test_wave7_report.py \
  tests/ci/test_wave7_model_repair_ci_integration.py \
  -q
```
Static checks:
```
ruff check .
mypy src
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
that model comparison proves model truthfulness
that a selected model proposal is safe to merge
that a selected model proposal has passed tests
that a model can approve itself
that local-audit execution is hardened sandbox evidence
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

The current source is available for review and limited noncommercial, non-operational evaluation only.

Commercial use, production use, hosted-service use, redistribution, modification, derivative deployment, government operational use, agency operational use, contractor use, procurement use, funded-pilot use, or organization-backed use requires prior written permission and a separate license agreement with Bryce Lovell.

Earlier versions released under Apache License 2.0 remain governed by their original license terms.

Current license details are documented in LICENSE, COMMERCIAL.md, and NOTICE.md.
