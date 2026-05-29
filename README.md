<p align="center">
  <img src="IX-BlackFox-Logo.png" alt="IX-BlackFox Logo">
</p>

# IX-BlackFox

**AI proposes. Humans decide.**

IX-BlackFox is a source-available governed AI engineering control plane for AI-assisted code-change workflows.

It treats model output as untrusted input and wraps AI-generated or AI-assisted software changes with policy gates, evidence receipts, repository-impact analysis, sandbox/evidence boundaries, CI validation, audit-attestation reports, and human review.

The point is not autonomous coding.

The point is making AI-assisted engineering inspectable, testable, auditable, and bounded before anyone trusts the output.

## Why this matters

AI coding agents introduce a new software trust boundary.

For DevSecOps, software assurance, test/evaluation, and regulated engineering environments, the hard questions are not just “did the model write code?” The hard questions are:

- What did the model propose?
- What was selected, rejected, or blocked?
- Was the selected model allowed to review its own output?
- What files changed?
- What repository subsystems are affected?
- What tests are likely relevant?
- Did the change touch CI, scripts, policy, licensing, release metadata, or security-sensitive code?
- What validation commands should run?
- What evidence was generated?
- Are the evidence receipts chained and reviewable?
- Which policy pack was used for audit evaluation?
- Which evidence manifest was evaluated?
- Which controls passed, warned, blocked, or did not apply?
- Is the governance report digest-bound and inspectable?
- Was human signoff bound to the current audit subject and policy pack?
- Where did human authority remain in control?

IX-BlackFox is built around those questions.

## Current status

**Current stage: Wave 9 prototype/evidence layer implemented.**

Wave 9 adds a compliance/audit attestation layer for AI-assisted code-change governance:

- default audit policy pack
- evidence manifest standard
- control evaluator
- fail-closed audit disposition logic
- Wave 5 PR evidence bridge
- Wave 6 sandbox evidence bridge
- Wave 7 model-repair evidence bridge
- Wave 8 repository-intelligence evidence bridge
- digest-bound reviewer signoff validation
- human-authority gate
- model/system self-approval prevention
- deterministic governance report builder
- JSON schema contracts
- `blackfox audit` CLI commands
- offline CI audit evidence generation
- dedicated GitHub Actions workflow

This is a research prototype. It is not production-ready, certified, defense-approved, compliance-approved, formally verified, or authorized for operational deployment.

## Evidence chain

IX-BlackFox is built around evidence before trust:

```
model output
  -> policy gates
  -> sandbox/evidence boundary
  -> repository impact analysis
  -> validation commands
  -> digest-chained receipts
  -> audit policy pack
  -> evidence manifest
  -> control evaluation
  -> reviewer signoff validation
  -> governance report
  -> human review
```
The governing rule is:
```
AI may propose.
IX-BlackFox must gate, compare, sandbox, test, record, analyze impact, evaluate controls, and route for review.
Humans retain authority.
```
Implemented waves
| Wave | Status                               | Meaning                                                                                                               |
| ---: | ------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
|    1 | Implemented                          | Governed multi-brain runtime scaffold                                                                                 |
|    2 | Implemented                          | Governed local patch-test-verify control plane                                                                        |
|    3 | Implemented                          | Governed patch authoring and repair intelligence                                                                      |
|    4 | Implemented                          | Reliability lab with scenario suites, adversarial tests, and repair metrics                                           |
|    5 | Implemented                          | Organization-grade workflow with PR evidence packs, approvals, and CI integration                                     |
|    6 | Prototype evidence layer implemented | Hardened sandbox execution layer with isolated workspaces, signed artifacts, and egress controls                      |
|    7 | Prototype evidence layer implemented | Model-agnostic repair intelligence with model comparison, routing, budget controls, and provider abstraction          |
|    8 | Prototype evidence layer implemented | Repository intelligence layer with code graph, dependency mapping, impact analysis, and architectural memory          |
|    9 | Prototype evidence layer implemented | Compliance/audit attestation layer with policy packs, evidence standards, reviewer signoff, and governance reports    |
|   10 | Planned                              | Full AI engineering operating system: multi-repo, multi-team, policy-governed, measurable, replayable, and reviewable |
Wave 9 compliance/audit attestation

Wave 9 adds this review path:
```
policy pack
  -> evidence manifest
  -> evidence validation
  -> control evaluation
  -> signoff validation
  -> signoff authority summary
  -> deterministic governance report
```
Core implementation:
```
src/ix_blackfox/audit/
scripts/run_wave9_compliance_audit_ci.py
.github/workflows/wave9-compliance-audit.yml
schemas/wave9-evidence-manifest.schema.json
schemas/wave9-governance-report.schema.json
docs/wave9-compliance-audit-attestation.md
```
Wave 9 helps reviewers determine:

which policy pack was evaluated
which evidence artifacts were included
whether evidence was digest-bound and inspectable
whether internal evidence was bound to the reviewed head SHA
which controls passed, warned, blocked, or did not apply
whether provenance or attestation claims were verified or merely recorded
whether a human reviewer actually approved the current audit subject
whether model/system signoffs were kept advisory
why the final disposition is audit_ready, warning, or blocked

The default policy pack is:
```
ix-blackfox.wave9.default
```
The primary report schema is:
```
wave9.compliance_audit_attestation.v1
```
The evidence-manifest schema is:
```
wave9.evidence_manifest.v1
```
Wave 9 is deliberately fail-closed. Missing required evidence, malformed evidence, head-SHA mismatch, unverified provenance claims, missing human approval, or model/system self-approval attempts cannot produce audit_ready.

Why the Wave 9 CI report is blocked by default

The Wave 9 GitHub Actions workflow intentionally expects a valid blocked report.

That is correct.

CI can prove that the audit engine, policy pack, evidence manifest, report export, digest validation, and human-approval boundary are working. CI must not fabricate human signoff.

A valid blocked report is useful evidence because it says exactly why audit readiness has not been reached.

Commands

Run all tests:
```
python -m pytest
```
Run Wave 9 targeted checks:
```
python -m pytest \
  tests/audit \
  tests/ci/test_wave9_compliance_audit_ci_integration.py \
  tests/ci/test_wave9_compliance_audit_workflow_contract.py \
  tests/docs/test_wave9_compliance_audit_docs.py \
  tests/interface/test_audit_cli_routing.py \
  -q
```
Compile-check source, tests, and scripts:
```
python -m compileall -q src tests scripts
```
Generate a Wave 9 governance report:
```
blackfox audit report \
  --root . \
  --repository IX-BlackFox \
  --head-sha local \
  --scope "repository intelligence audit" \
  --claim "repository intelligence impact architecture_memory" \
  --output .blackfox-artifacts/wave9/wave9-compliance-audit-report.json
```
Validate a Wave 9 governance report:
```
blackfox audit validate \
  --report .blackfox-artifacts/wave9/wave9-compliance-audit-report.json
```
Gate on a Wave 9 governance report:
```
blackfox audit gate \
  --report .blackfox-artifacts/wave9/wave9-compliance-audit-report.json
```
Generate Wave 9 CI evidence:
```
python scripts/run_wave9_compliance_audit_ci.py --head-sha local
```
Default Wave 9 outputs:
```
.blackfox-artifacts/wave9/wave9-compliance-audit-report.json
.blackfox-artifacts/wave9/wave9-ci-engine-evidence.json
.blackfox-artifacts/wave9/wave9-compliance-audit-ci-summary.json
```
Wave 8 repository intelligence

Wave 8 added this review path:
```
inventory
  -> Python code graph
  -> dependency map
  -> source-test coverage map
  -> architectural memory
  -> conservative impact analysis
  -> digest-chained evidence
  -> exportable report
```
Core implementation:
```
src/ix_blackfox/repository/
scripts/run_wave8_repository_intelligence_ci.py
.github/workflows/wave8-repository-intelligence.yml
docs/wave8-repository-intelligence.md
```
Wave 8 helps reviewers determine what changed, what else may be affected, what tests are likely relevant, what subsystems are touched, whether sensitive review surfaces are involved, whether human review should be escalated, what validation commands should run, and what evidence chain was produced.

Wave 8 is conservative static evidence. It does not claim perfect repository understanding, complete dependency discovery, complete source-test mapping, complete runtime-effect analysis, patch safety, merge readiness, or approval authority.

What this project does not claim

IX-BlackFox does not claim:

production readiness
safety certification
security certification
compliance certification
official defense affiliation
government approval
ATO or cATO
procurement approval
deployment authority
operational authority
autonomous authority
autonomous deployment approval
patch safety
merge readiness
perfect repository understanding
perfect dependency mapping
complete source-test mapping
that a model can approve itself
that repository impact analysis replaces human review
that local sandbox evidence equals formal certification
that Wave 9 audit attestation equals formal compliance approval
that recorded provenance metadata equals verified provenance

This is a source-available research prototype and governed engineering control-plane experiment.

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
This roadmap should not be renumbered or replaced.

License

IX-BlackFox is governed by the IX-BlackFox Source-Available Evaluation License v1.0 beginning with the license-transition commit.

The current source is available for review and limited noncommercial, non-operational evaluation only.

Commercial use, production use, hosted-service use, redistribution, modification, derivative deployment, government operational use, agency operational use, contractor use, procurement use, funded-pilot use, or organization-backed use requires prior written permission and a separate license agreement with Bryce Lovell.

Earlier versions released under Apache License 2.0 remain governed by their original license terms.

Current license details are documented in LICENSE, COMMERCIAL.md, and NOTICE.md.
