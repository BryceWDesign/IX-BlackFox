<p align="center">
  <img src="IX-BlackFox-Logo.png" alt="IX-BlackFox Logo">
</p>

# IX-BlackFox

**AI proposes. Humans decide.**

IX-BlackFox is a source-available governed AI engineering control plane for bounded patch-test-verify workflows.

The goal is not uncontrolled autonomous coding. The goal is a reviewable engineering runtime that can accept AI-assisted repair proposals only as untrusted inputs, route them through policy gates, execute controlled validation, preserve receipts, and expose evidence for human review.

## Current status

**Current stage: Wave 5 active / in progress.**

The repository has moved beyond Wave 4 by adding the first real Wave 5 organization-workflow layer:

- PR evidence-pack contract
- human approval policy matrix
- CI evidence normalization
- PR gate decision engine
- local/manual Wave 5 gate CLI
- manual/operator-run GitHub Actions workflow for Wave 5 PR gate evaluation

Wave 5 is **not complete**. The current implementation is an honest Wave 5 entry layer: it can evaluate whether a pull-request evidence pack has the required evidence, human approval, CI evidence, and head-SHA binding before being treated as merge-ready.

## Implemented waves

| Wave | Status | Meaning |
|---:|---|---|
| 1 | Implemented | Governed multi-brain runtime scaffold |
| 2 | Implemented | Governed local patch-test-verify control plane |
| 3 | Implemented | Governed patch authoring and repair intelligence |
| 4 | Implemented | Reliability lab with scenario suites, adversarial tests, and repair metrics |
| 5 | Active / in progress | Organization-grade workflow with PR evidence packs, approvals, and CI integration |

## Wave 5 scope currently implemented

The current Wave 5 layer includes:

| Area | Purpose |
|---|---|
| `src/ix_blackfox/workflow/pr_evidence_pack.py` | Defines the PR evidence-pack contract and fail-closed validation rules |
| `src/ix_blackfox/workflow/approval_policy.py` | Requires real human approval and treats model approval as advisory only |
| `src/ix_blackfox/workflow/ci_evidence.py` | Normalizes CI evidence and checks required CI conclusions |
| `src/ix_blackfox/workflow/pr_gate.py` | Combines evidence-pack, approval-policy, and CI evidence into a merge-readiness decision |
| `src/ix_blackfox/workflow/pr_evidence_io.py` | Loads PR evidence-pack JSON into typed workflow objects |
| `src/ix_blackfox/workflow/cli.py` | Provides the local/manual Wave 5 PR gate command |
| `.github/workflows/wave5-pr-gate.yml` | Adds a manual/operator-run GitHub Actions gate for evaluating supplied evidence files |

## Core trust boundary

Model output is never treated as authority.

A model may propose a repair, comment on evidence, or provide advisory review. It cannot approve itself, satisfy human authority, or make a change merge-ready by itself.

The core rule is:

> AI may propose. IX-BlackFox must gate, test, record, and route for review. Humans retain authority.

## What the Wave 5 gate checks

The current Wave 5 gate can block a pull request when:

- required evidence artifacts are missing
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

## Local Wave 5 gate command

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
GitHub Actions integration

The Wave 5 GitHub Actions workflow is intentionally manual/operator-run.

It does not fake human approval. It does not synthesize review data. It evaluates supplied evidence files and preserves the gate decision as an artifact for review.

Workflow file:
```
.github/workflows/wave5-pr-gate.yml
```
What IX-BlackFox does not claim

IX-BlackFox does not claim:

production readiness
certification
procurement status
official defense affiliation
autonomous authority
autonomous deployment approval
safety certification
security certification
that any AI-generated repair is correct without evidence
that Wave 5 is complete

This is a research prototype and governed engineering control-plane experiment, not an operational system.

Testing

From the repository root:
```
python -m pytest
```
Useful targeted checks:
```
python -m pytest tests/workflow
python -m pytest tests/reliability
python -m pytest tests/governance
python -m compileall -q src tests
```

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
