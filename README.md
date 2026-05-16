<p align="center">
  <img src="IX-BlackFox-Logo.png" alt="IX-BlackFox Logo">
</p>

# IX-BlackFox

**AI proposes. Humans decide.**

IX-BlackFox is a source-available governed AI engineering control plane for bounded patch-test-verify workflows.

Its purpose is not uncontrolled autonomous coding. Its purpose is to keep AI-assisted engineering inside reviewable boundaries: policy gates, controlled patch candidates, test execution, receipt chains, evidence bundles, reliability scenarios, adversarial checks, and human authority.

## Current status

**Current implemented wave: Wave 4.**

Wave 4 adds a reliability lab on top of the earlier governed patch-test-verify and repair-authoring layers. The current repository contains Wave 4 reliability components for scenario suites, adversarial tests, repair metrics, reliability reports, and artifact bundles.

**Wave 5 is not implemented yet.** Wave 5 is the next planned stage: organization-grade workflow with PR evidence packs, approvals, and CI integration.

## Implemented waves

| Wave | Status | Meaning |
|---:|---|---|
| 1 | Implemented | Governed multi-brain runtime scaffold |
| 2 | Implemented | Governed local patch-test-verify control plane |
| 3 | Implemented | Governed patch authoring and repair intelligence |
| 4 | Implemented | Reliability lab with scenario suites, adversarial tests, and repair metrics |
| 5 | Planned | Organization-grade workflow with PR evidence packs, approvals, and CI integration |

## What the current repo does

IX-BlackFox currently supports:

- bounded runtime scaffolding
- policy-aware execution paths
- local patch-test-verify workflows
- governed patch candidates
- repair proposal parsing and validation
- receipt generation
- run bundle and evidence output
- Wave 3 authored-repair handoff into Wave 2 execution
- Wave 4 reliability scenario suites
- adversarial fail-closed checks
- repair-quality metrics
- reliability reports and artifacts

## Core trust boundary

Model output is treated as untrusted input.

IX-BlackFox does not accept a repair simply because an AI or external provider proposed it. A repair must pass parsing, policy review, compilation, candidate selection, controlled execution, evidence capture, and human-reviewable reporting.

The key rule is:

> AI may propose. IX-BlackFox must gate, test, record, and route for review. Humans retain authority.

## What IX-BlackFox does not claim

IX-BlackFox does not claim:

- production readiness
- certification
- procurement status
- official defense affiliation
- autonomous authority
- deployment approval
- safety certification
- security certification
- that any AI-generated repair is correct without evidence

This is a research prototype, not an operational system.

## Repository structure

Important areas include:

| Path | Purpose |
|---|---|
| `src/ix_blackfox/runtime/` | Runtime control, repair execution, receipts, bundles, safeguards, replay, and Wave 3 handoff |
| `src/ix_blackfox/authoring/` | Patch-authoring models, evidence extraction, prompt contracts, parsers, compilers, policy, receipts, and candidate ranking |
| `src/ix_blackfox/reliability/` | Wave 4 reliability lab, scenario suites, adversarial harness, metrics, reports, and artifacts |
| `src/ix_blackfox/governance/` | Governance policy, approval, advisory, receipts, and decision models |
| `src/ix_blackfox/forge/` | Workspace, patch planning, command execution, regression handling, and governed command paths |
| `tests/` | Test coverage for runtime, authoring, governance, reliability, forge, memory, vault, tools, and related modules |

## Testing

From the repository root:

```
python -m pytest
```
To inspect the Wave 4 reliability lab directly, review:
```
tests/reliability/test_wave4_reliability_lab.py
src/ix_blackfox/reliability/
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
