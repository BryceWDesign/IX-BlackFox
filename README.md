<p align="center">
  <img src="IX-BlackFox-Logo.png" alt="IX-BlackFox Logo">
</p>

# IX-BlackFox

**AI proposes. Humans decide.**

IX-BlackFox is a source-available governed AI engineering control plane for AI-assisted code-change workflows.

It treats model output as untrusted input and wraps AI-generated or AI-assisted software changes with policy gates, evidence receipts, repository-impact analysis, sandbox/evidence boundaries, CI validation, and human review.

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
- Where did human authority remain in control?

IX-BlackFox is built around those questions.

## Current status

**Current stage: Wave 8 prototype/evidence layer implemented.**

Wave 8 adds deterministic repository intelligence:

- repository inventory snapshots
- file role and sensitivity classification
- Python AST code graph extraction
- dependency mapping
- source-test mapping
- subsystem inference
- architectural memory records
- conservative impact analysis
- recommended validation commands
- digest-chained evidence receipts
- exportable JSON reports
- CLI commands
- offline CI evidence generation
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
  -> human review
```
The governing rule is:
```
AI may propose.
IX-BlackFox must gate, compare, sandbox, test, record, analyze impact, and route for review.
Humans retain authority.
```
Implemented waves
| Wave | Status                               | Meaning                                                                                                      |
| ---: | ------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
|    1 | Implemented                          | Governed multi-brain runtime scaffold                                                                        |
|    2 | Implemented                          | Governed local patch-test-verify control plane                                                               |
|    3 | Implemented                          | Governed patch authoring and repair intelligence                                                             |
|    4 | Implemented                          | Reliability lab with scenario suites, adversarial tests, and repair metrics                                  |
|    5 | Implemented                          | Organization-grade workflow with PR evidence packs, approvals, and CI integration                            |
|    6 | Prototype evidence layer implemented | Hardened sandbox execution layer with isolated workspaces, signed artifacts, and egress controls             |
|    7 | Prototype evidence layer implemented | Model-agnostic repair intelligence with model comparison, routing, budget controls, and provider abstraction |
|    8 | Prototype evidence layer implemented | Repository intelligence layer with code graph, dependency mapping, impact analysis, and architectural memory |
|    9 | Planned                              | Compliance/audit attestation layer with policy packs, evidence standards, reviewer signoff, and governance reports |
|   10 | Planned                              | Full AI engineering operating system: multi-repo, multi-team, policy-governed, measurable, replayable, and reviewable |

Wave 8 repository intelligence

Wave 8 adds this review path:
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
Wave 8 helps reviewers determine:
what changed
what else may be affected
what tests are likely relevant
what subsystems are touched
whether sensitive review surfaces are involved
whether human review should be escalated
what validation commands should run
what evidence chain was produced

Wave 8 is conservative static evidence. It does not claim perfect repository understanding, complete dependency discovery, complete source-test mapping, complete runtime-effect analysis, patch safety, merge readiness, or approval authority.

Commands

Run tests:
```
python -m pytest
```
Run Wave 8 targeted checks:
```
python -m pytest \
  tests/repository \
  tests/ci/test_wave8_repository_intelligence_ci_integration.py \
  tests/ci/test_wave8_repository_intelligence_workflow_contract.py \
  tests/docs/test_wave8_repository_intelligence_docs.py \
  tests/interface/test_cli.py \
  -q
```
Compile-check source, tests, and scripts:
```
python -m compileall -q src tests scripts
```
Run repository scan:
```
blackfox repository scan --root . --json
```
Run impact analysis:
```
blackfox repository impact \
  --root . \
  --changed src/ix_blackfox/repository/report.py \
  --json
```
Generate Wave 8 CI evidence:
```
python scripts/run_wave8_repository_intelligence_ci.py --head-sha local
```
Default Wave 8 outputs:
```
.blackfox-artifacts/wave8/wave8-repository-intelligence-ci-report.json
.blackfox-artifacts/wave8/wave8-repository-intelligence-evidence.json
```
What this project does not claim

IX-BlackFox does not claim:

production readiness
safety certification
security certification
compliance certification
official defense affiliation
government approval
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
