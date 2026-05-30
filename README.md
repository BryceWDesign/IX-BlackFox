<p align="center">
  <img src="IX-BlackFox-Logo.png" alt="IX-BlackFox Logo">
</p>

# IX-BlackFox

**AI proposes. Humans decide. Evidence decides trust.**

IX-BlackFox is a source-available AI engineering control plane for governing AI-assisted code-change workflows. It treats model output as untrusted input and wraps proposed software changes in policy gates, isolated workspaces, receipts, evidence bundles, replay checks, human authority, audit-ready reports, and reviewable operating evidence.

Wave 10 extends IX-BlackFox from a repo-level governed repair/control plane into a broader **AI engineering operating-system layer**: multi-repo, multi-team, policy-governed, measurable, replayable, reviewable, and evidence-bound.

This repository is built for serious review by DevSecOps, platform engineering, security engineering, AI governance, software assurance, cloud-security, and defense-adjacent technical audiences that need proof around AI-in-the-code-change-loop workflows.

It does **not** claim certification, compliance approval, production readiness, DoD approval, AWS approval, FedRAMP authorization, cATO authorization, Security Hub integration, or autonomous authority.

---

## What problem IX-BlackFox is built to address

AI coding agents create a new trust boundary.

The hard question is not only:

> Can the model write code?

The harder engineering question is:

> When something breaks, can you reconstruct what the model proposed, what policy allowed it, what evidence was produced, what CI or replay validation checked, what a human actually approved, and why the final state was considered acceptable?

IX-BlackFox is built around that boundary.

It is designed to make AI-assisted engineering workflows:

- inspectable,
- policy-governed,
- evidence-bound,
- replayable,
- human-authorized,
- measurable,
- falsifiable,
- and reviewable.

---

## Core doctrine

IX-BlackFox follows one operating rule:

> **AI proposes. Humans decide. Evidence decides trust.**

That means:

- Model output is treated as untrusted input.
- Policy gates decide whether a proposed action can proceed.
- Evidence bundles record what happened.
- Human authority remains separate from model output.
- Self-approval, model approval, and system approval are not accepted as final human authority.
- Readiness claims must be bounded to the evidence actually present.
- Missing evidence fails closed.
- Replay gaps, traceability gaps, trust gaps, policy failures, and unresolved blockers prevent readiness.

---

## Wave 10 target

The locked Wave 10 roadmap target for IX-BlackFox is:

> **Full AI engineering operating system: multi-repo, multi-team, policy-governed, measurable, replayable, and reviewable.**

Wave 10 does not mean “autonomous AI can approve itself.”

Wave 10 means the repository now contains operating-system primitives for assembling, evaluating, exporting, and reviewing evidence across a governed AI-assisted engineering workflow.

---

## What Wave 10 adds

Wave 10 adds an operating layer under:

```
src/ix_blackfox/operating/
```
The Wave 10 layer includes:

operating models,
managed repository registry,
work packages,
campaign graph validation,
team authority and separation of duties,
Wave 5–9 evidence aggregation,
replay manifests and replay validation,
deterministic review bundles,
assurance traceability maps,
policy packs and operating gates,
sustainment blockers and readiness gates,
evidence trust scoring,
negative controls and kill criteria,
measurable operating scorecards,
standards crosswalk reports,
local AWS/cloud-security finding exports,
final operating report/dossier assembly,
local export-pack manifests,
and an end-to-end assembly smoke path.

Wave 10 module map
| Module                    | Purpose                                                                                                                                                                                    |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `operating.models`        | Core Wave 10 enums, artifact references, envelopes, findings, dispositions, digest helpers, and normalization.                                                                             |
| `operating.registry`      | Multi-repo registry, repository dependencies, risk surfaces, policy bindings, evidence posture, and governance scope.                                                                      |
| `operating.work_packages` | Reviewable work packages, dependencies, validations, evidence requirements, rollback requirements, and forbidden actions.                                                                  |
| `operating.campaign`      | Multi-phase operating campaign graph, dependency validation, blocked phase detection, and campaign-level evidence envelope.                                                                |
| `operating.authority`     | Teams, reviewer roles, approval quorum, separation-of-duties rules, and human-authority enforcement.                                                                                       |
| `operating.evidence`      | Normalizes Wave 5–9 evidence into Wave 10 operating evidence inventories.                                                                                                                  |
| `operating.replay`        | Replay environments, replay commands, replay steps, replay manifests, and replay validation results.                                                                                       |
| `operating.review_bundle` | Deterministic human-review bundle sections, artifacts, validation, and digest-bound review export.                                                                                         |
| `operating.traceability`  | Assurance traceability graph connecting mission needs, requirements, scenarios, hazards, controls, evidence, human review, and bounded claims.                                             |
| `operating.policy`        | Operating policy contexts, controls, policy packs, policy evaluations, and fail-closed gate decisions.                                                                                     |
| `operating.sustainment`   | Sustainment blockers, readiness transitions, readiness states, and readiness gates.                                                                                                        |
| `operating.trust`         | Evidence freshness, integrity, schema validity, producer trust, human-review binding, trust scores, and trust transitions.                                                                 |
| `operating.falsification` | Negative controls, kill criteria, falsification gates, and “prove it blocks bad states” evidence.                                                                                          |
| `operating.scorecard`     | Buyer-readable metrics for coverage, risk, review, replay, policy, and evidence trust.                                                                                                     |
| `operating.standards`     | Mapping-ready crosswalks for SSDF, OSCAL-style assessment results, DoD cATO evidence categories, SLSA/provenance, SBOM, GitHub artifact attestations, and OpenSSF Scorecard-style signals. |
| `operating.cloud`         | Local ASFF-shaped cloud-security finding export for review. No AWS API calls. No credentials. No live Security Hub integration.                                                            |
| `operating.report`        | Final Wave 10 operating report/dossier assembler and report validation.                                                                                                                    |
| `operating.export`        | Local export-pack manifest and payload digest validation.                                                                                                                                  |
| `operating.assembly`      | End-to-end local Wave 10 assembly smoke path.                                                                                                                                              |
End-to-end Wave 10 smoke path

Wave 10 includes a compact local assembly path that proves the final layers can be joined together without granting execution authority.
```
from ix_blackfox.operating import build_minimal_wave10_operating_assembly

assembly = build_minimal_wave10_operating_assembly()

print(assembly.all_ready)
print(assembly.dispositions)
print(assembly.report.digest)
print(assembly.export_pack.manifest_digest)
```
The assembly path builds:

a compact final operating report,
report digest validation,
a review bundle,
a standards crosswalk,
a local ASFF-shaped cloud-security export,
a local export pack,
and export-pack validation.

This is a local deterministic smoke path. It does not call AWS, upload evidence, write files, grant approvals, or authorize execution.

What IX-BlackFox is not

IX-BlackFox is not:

a replacement for human review,
a production authorization system,
a certified compliance product,
a FedRAMP-authorized product,
a DoD-approved product,
an AWS-approved product,
a live AWS Security Hub integration,
an autonomous deployment authority,
a claim that AI code changes are safe by default,
or a guarantee that model-generated code is correct.

It is an evidence-bound control plane and research prototype for making AI-assisted engineering workflows more inspectable, reviewable, and governable.

Why this matters for DevSecOps and platform teams

Organizations adopting AI coding agents need more than faster code generation.

They need to answer questions like:

What did the model propose?
What repository or workspace did the action affect?
What policy gates were applied?
What evidence was produced?
What validations ran?
What failed?
What was replayable?
What was traceable?
Who reviewed it?
Was the reviewer allowed to approve it?
Was there separation of duties?
Was any evidence stale, missing, untrusted, or tampered with?
Were negative controls run?
Did kill criteria trigger?
What final claim is actually supported?

IX-BlackFox is built to make those questions explicit.

Why this matters for defense-adjacent software assurance

Defense, autonomy, T&E, DevSecOps, and assurance workflows often require evidence chains, bounded claims, human authority, reproducibility, and auditability.

IX-BlackFox is designed to support that style of review by producing structured evidence around:

telemetry-like operating findings,
policy decisions,
human authority gates,
reviewer separation,
replay manifests,
evidence digests,
traceability maps,
negative controls,
scorecards,
standards crosswalks,
and final operating reports.

This repository does not claim official defense adoption, approval, certification, or accreditation.

It is intended to be technically reviewable by people who care about those evidence requirements.

Why this matters for AWS and cloud-security audiences

Wave 10 includes a local cloud-security export layer that emits ASFF-shaped JSON for review by cloud-security teams.

That layer is intentionally local-only.

It does not:

call AWS APIs,
upload findings,
handle credentials,
configure Security Hub,
require an AWS account,
claim AWS approval,
or claim live AWS Security Hub integration.

It gives cloud-security reviewers a familiar finding shape they can inspect, transform, or route through their own approved pipeline.

Evidence-first design

IX-BlackFox prioritizes evidence over assertion.

A Wave 10 operating report can include:

artifact IDs,
SHA-256 digests,
envelope digests,
section dispositions,
blocked/warning/ready states,
required evidence,
missing evidence,
policy findings,
replay validation findings,
trust findings,
scorecard findings,
standards crosswalk findings,
cloud-export findings,
and final report validation.

The goal is not to say “trust the model.”

The goal is to say:

Here is the evidence. Here is what passed. Here is what failed. Here is what is missing. Here is what a human still must review.

Fail-closed behavior

Wave 10 is intentionally conservative.

Readiness is blocked when critical evidence is missing or invalid, including:

missing required repository scope,
missing required evidence artifacts,
missing human review,
self-approval attempts,
model approval attempts,
unresolved high/critical blockers,
replay mismatches,
nondeterministic replay steps,
network-dependent replay steps,
unsupported assurance claims,
missing traceability,
stale or untrusted evidence,
failed policy controls,
missing negative-control results,
triggered kill criteria,
prohibited overclaim language,
digest mismatches,
or missing export payloads.

Warnings are preserved when evidence exists but still needs reviewer attention.

Human authority

Wave 10 separates human authority from model output.

The authority layer supports:

reviewer roles,
team definitions,
quorum requirements,
separated author/reviewer authority,
self-approval blocking,
model-approval blocking,
system-approval blocking,
and team review decisions.

The design assumption is simple:

A model can propose. A system can record. A human authority must decide.

Replayability

The replay layer supports:

deterministic replay environments,
argv-based replay commands,
dependency lock references,
expected artifacts,
evidence artifacts,
replay step dependencies,
cycle detection,
digest checks,
missing artifact detection,
unexpected artifact detection,
required-step execution checks,
and replay validation envelopes.

Replay evidence is not treated as decorative. It can block readiness.

Traceability

The traceability layer maps:

mission needs,
requirements,
scenarios,
hazards,
controls,
evidence,
human reviews,
assurance claims,
operating decisions,
repositories,
and work packages.

It is designed to prevent unsupported claims from passing through as “ready.”

A bounded claim must be supported by traceable evidence and human review.

Falsification and negative controls

Wave 10 includes negative controls because a serious governance system must prove that it blocks bad states.

Negative-control families include:

missing evidence,
tampered artifacts,
self approval,
model approval,
system approval,
policy bypass,
replay mismatch,
untrusted evidence,
traceability gaps,
claim overreach,
and unresolved blockers.

Kill criteria can block final readiness when severe failure conditions are triggered or not evaluated.

Standards crosswalk

Wave 10 includes mapping-ready evidence for review against several standards and evidence ecosystems:

NIST SSDF-style secure software development evidence,
OSCAL-style assessment-results evidence,
DoD cATO evidence categories,
SLSA/provenance evidence,
SBOM evidence,
GitHub artifact-attestation references,
and OpenSSF Scorecard-style signals.

This is mapping-ready evidence only.

It does not claim:

formal compliance,
certification,
accreditation,
authorization,
government approval,
vendor approval,
or production readiness.
Local export pack

Wave 10 can assemble a local export pack containing:

the final operating report,
report validation,
review bundle,
standards crosswalk,
cloud-security export index,
ASFF-shaped cloud-security finding JSON,
payload digests,
manifest digest,
required payload IDs,
optional payload IDs,
and export-pack validation results.

The export pack is local-only.

It does not write files by itself, upload to cloud services, or grant execution authority.

Repository structure

Typical structure:
```
src/
  ix_blackfox/
    operating/
      assembly.py
      authority.py
      campaign.py
      cloud.py
      evidence.py
      export.py
      falsification.py
      models.py
      policy.py
      registry.py
      replay.py
      report.py
      review_bundle.py
      scorecard.py
      standards.py
      sustainment.py
      traceability.py
      trust.py
      work_packages.py
tests/
  operating/
```
Running tests

From the repository root:
```
PYTHONPATH=src python -m pytest
```
For the Wave 10 operating package specifically:
```
PYTHONPATH=src python -m pytest tests/operating -q
```
For syntax compilation:
```
PYTHONPATH=src python -m compileall -q src tests
```
If your environment includes Ruff and Mypy, run:
```
ruff check .
mypy src
```
Do not treat this README as a claim that those checks passed in your local environment. Run the checks in your own clone or GitHub Actions environment and trust the actual output.

Example: build a local Wave 10 assembly
```
from ix_blackfox.operating import build_minimal_wave10_operating_assembly

assembly = build_minimal_wave10_operating_assembly(
    assembly_id="wave10-demo",
    registry_id="wave10-registry",
    campaign_id="wave10-campaign",
    repository_ids=("ix-blackfox",),
)

assert assembly.all_ready is True

report = assembly.report
export_pack = assembly.export_pack

print(report.disposition.value)
print(report.digest)
print(export_pack.manifest_digest)
```
Example: inspect final report findings
```
from ix_blackfox.operating import build_minimal_wave10_operating_assembly

assembly = build_minimal_wave10_operating_assembly()
report = assembly.report

for finding in report.findings:
    print(finding.code, finding.severity.value, finding.blocking)
```
A clean minimal assembly should produce a ready report. A real workflow should expect findings when evidence is missing, stale, untrusted, incomplete, or not reviewed.

Example: export local ASFF-shaped cloud-security findings
```
from ix_blackfox.operating import build_minimal_wave10_operating_assembly

assembly = build_minimal_wave10_operating_assembly()
asff_json = assembly.cloud_security_export.export_asff_json()

print(asff_json)
```
This produces local ASFF-shaped JSON.

It does not send anything to AWS.

Example: validate export pack payload digests
```
from ix_blackfox.operating import build_minimal_wave10_operating_assembly

assembly = build_minimal_wave10_operating_assembly()
validation = assembly.export_pack_validation

assert validation.passed is True
assert validation.manifest_digest_matches is True
```
Security posture

IX-BlackFox assumes model output is untrusted.

The repository is designed around:

deny-by-default thinking,
bounded evidence,
digest checks,
explicit review,
human authority,
policy gates,
local deterministic artifacts,
negative controls,
and fail-closed readiness.

Do not wire this directly into production deployment authority without a complete security review, environment-specific integration work, threat modeling, independent testing, and human governance.

Commercial and evaluation posture

IX-BlackFox is source-available for technical evaluation under the repository license.

Unless a separate written commercial license says otherwise, do not treat public visibility as permission for commercial use, production use, hosted service use, contractor use, funded operational use, derivative operational use, procurement use, or resale.

See the repository LICENSE for the exact legal terms.

Authorship

IX-BlackFox was originated and created by Bryce Lovell.

The IX-BlackFox project is part of the IX research ecosystem focused on governed, evidence-bound, human-reviewable technical systems.

Status

IX-BlackFox Wave 10 implements the repository’s operating-system layer as source code, tests, models, and local evidence assembly primitives.

It should be reviewed as a serious technical prototype and evidence architecture.

It should not be represented as certified, officially adopted, accredited, production-authorized, government-approved, vendor-approved, or autonomous.

Short positioning statement

IX-BlackFox is a source-available AI engineering control plane for governing AI-assisted code change: policy gates, evidence bundles, replay checks, human authority, traceability, scorecards, standards crosswalks, local cloud-security finding exports, and final operating reports.

AI proposes. Humans decide. Evidence decides trust.
