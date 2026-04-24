<p align="center">
  <img src="IX-BlackFox-Logo.png" alt="IX-BlackFox Logo">
</p>

# IX-BlackFox

Apache-2.0 licensed, governed AI runtime for auditable multi-brain execution.

IX-BlackFox is not framed as “just another agent.”
It is a controlled runtime that routes work, runs deterministic governance before execution, records chained receipts, supports optional multimodal inspection, supports advisory policy reasoning beside execution reasoning, and can escalate to a deeper reasoning lane when the run actually justifies it.

The architectural thesis is simple:

**intelligence should behave like a controlled operating runtime, not like a floating text box.**

---

## What IX-BlackFox is

IX-BlackFox is a measurement-first, governance-first AI operating runtime that currently implements:

- deterministic task intake and routing
- pack-based execution for architecture and programming work
- primary execution reasoning
- advisory policy reasoning beside hard governance
- semantic safeguard review
- optional vision review for screenshots and UI evidence
- optional escalated deep reasoning for hard cases
- runtime readiness inspection across all major brain lanes
- chained governance receipts
- replay detection
- artifact materialization and report persistence
- verification and sentinel checks around execution

In practical terms, BlackFox is built to answer a harder question than “did the model generate text?”

It is built to answer:

- what lane executed
- why that lane executed
- what governance decided before execution
- what receipts prove it
- what artifacts were produced
- whether the run contradicted its own controls
- whether the runtime itself was actually ready when the run happened

---

## What IX-BlackFox is not

IX-BlackFox is **not**:

- an unconstrained autonomous agent
- a production safety guarantee
- a claim of secure-by-default deployment
- a claim that advisory reasoning overrides deterministic governance
- a finished enterprise orchestration platform
- a substitute for human review in high-risk workflows

This repo is a governed runtime proof-of-concept with explicit control surfaces, explicit receipts, and explicit degraded-mode behavior.

---

## Highest-form direction this repo is pursuing

The intended direction is for BlackFox to function as an auditable AI operating system that can:

- route work to the right brain
- escalate only when the run actually justifies escalation
- inspect screenshots and UI evidence
- run policy reasoning beside execution reasoning
- keep deterministic control over all of it
- tell you whether the runtime itself was ready before you trust the result

That is the point of the current architecture wave.

---

## Current implemented wave

The current codebase already contains the core execution spine for that direction.

### Runtime execution spine

The runtime orchestrator now fuses:

- routing
- governance preflight
- approval resolution
- primary brain execution
- policy reasoning lane
- safeguard lane
- vision lane
- deep reasoning escalation lane
- sentinel evaluation
- verification
- receipt persistence
- artifact persistence
- run report persistence

### Brain lanes

BlackFox currently expects these default lanes:

- **primary** → default execution lane
- **policy** → advisory policy interpretation lane
- **safeguard** → semantic safety lane
- **vision** → screenshot / UI inspection lane
- **reasoning** → escalated deep-reasoning lane

### Default provider expectations

The default manifests currently assume:

- **ollama** for primary / policy / safeguard
- **vllm** for vision
- **openai-compatible** for escalated deep reasoning

These are runtime expectations, not guarantees.  
The doctor and readiness inspector make the current state explicit.

---

## Core repo concepts

## 1. Deterministic governance stays sovereign

Policy reasoning and safeguard reasoning are advisory lanes.

Deterministic governance still owns:

- allow / review / block semantics
- approval requirements
- approval satisfaction state
- receipt chain integrity

That split is deliberate.
Reasoning can explain, classify, and surface nuance.
Governance still controls execution.

## 2. Receipts are first-class

Each run can persist:

- governance receipts
- brain invocation receipts
- runtime reports
- produced artifacts

This pushes the repo away from “trust the model” and toward “inspect the chain.”

## 3. Readiness is explicit

The repo now includes runtime readiness inspection so the runtime can state whether it is:

- **ready**
- **degraded**
- **unavailable**

That matters because a multi-brain runtime should not quietly pretend full capability when whole lanes are missing.

## 4. Escalation is bounded

Deep reasoning is not always-on.
It is triggered by explicit signals such as:

- explicit deep-reasoning request
- contradiction signals
- failed verification
- repeated failures
- low-confidence conditions that cross the escalation policy threshold

That keeps the runtime controlled instead of permanently over-spending reasoning budget.

---

## Implemented architecture at a glance

```text
Task Intake
   ↓
Deterministic Classification
   ↓
Capability Routing
   ↓
Runtime Readiness Inspection
   ↓
Optional Vision Lane
   ↓
Policy Reasoning Lane
   ↓
Safeguard Lane
   ↓
Governance Preflight + Approval Resolution
   ↓
Primary Brain + Pack Execution
   ↓
Sentinel Checks + Verification
   ↓
Optional Escalated Reasoning Lane
   ↓
Governance Receipts + Run Report + Artifacts

Major implemented components
Runtime
ix_blackfox.runtime.orchestrator
ix_blackfox.runtime.governance
ix_blackfox.runtime.approval
ix_blackfox.runtime.replay
ix_blackfox.runtime.receipts
ix_blackfox.runtime.readiness
ix_blackfox.runtime.doctor
Cognitive lanes
ix_blackfox.runtime.inference
ix_blackfox.runtime.policy_reasoning
ix_blackfox.runtime.safeguard
ix_blackfox.runtime.vision
ix_blackfox.runtime.reasoning
Brain contracts and catalogs
ix_blackfox.brains.catalog
ix_blackfox.brains.receipts
ix_blackfox.brains.providers
ix_blackfox.brains.router
ix_blackfox.brains.renderers
Governance
ix_blackfox.governance.policy
ix_blackfox.governance.approval
ix_blackfox.governance.receipt
ix_blackfox.governance.advisory
Readiness model

BlackFox now has an explicit readiness model.

READY

All expected lanes are configured and healthy.

DEGRADED

Primary execution is available, but one or more non-critical lanes are missing or unhealthy.

Example:

no vision provider
no escalated reasoning provider
UNAVAILABLE

A critical lane is missing or unhealthy.

Right now the primary lane is treated as critical.

This is important because it prevents the repo from pretending it is fully operational when the runtime graph is only partially present.

Doctor mode

The runtime doctor inspects the currently configured runtime and emits a diagnostics report without requiring a task run.

What it reports
configured providers
runtime paths
lane-by-lane readiness
issue codes
recommended corrective actions

CLI entrypoint
```bash
python -m ix_blackfox.runtime.doctor
```
Write a JSON doctor report
```bash
python -m ix_blackfox.runtime.doctor --output artifacts/doctor-report.json
```
Exit codes

0 → ready
1 → degraded
2 → unavailable

That makes it useful for local validation, CI gating, or deployment checks.
Example runtime use
```python
from ix_blackfox.kernel import TaskKind
from ix_blackfox.runtime import BlackFoxRuntime
runtime = BlackFoxRuntime.create_default()
report = runtime.run_prompt(
prompt="Inspect the architecture and summarize the subsystem boundaries.",
kind=TaskKind.ARCHITECTURE,
labels=("architecture",),
)
print(report.status.value)
print(report.report_path)

```
Example doctor use from Python
```python
from ix_blackfox.runtime import RuntimeDoctor
report = RuntimeDoctor.inspect_default()
print(report.readiness_report.status.value)
print(report.to_json())
```
Artifact behavior
A successful run can write structured outputs such as:

artifacts/reports/<task_id>.json
artifacts/governance/<task_id>/blackfox-governance-receipts.json
artifacts/<task_id>/<artifact_name>.json

Those persisted artifacts are part of the repo's main value proposition: BlackFox tries to leave behind an inspectable trail, not just an answer.
Testing
The current wave includes tests around:

provider factory construction
vision planning and invocation
policy reasoning planning and invocation
deep reasoning planning and invocation
runtime readiness inspection
doctor diagnostics
runtime integration of vision, policy, reasoning, and readiness serialization

Run the suite with:
```bash
python -m pytest
```
Provider notes
BlackFox does not fabricate provider availability. If a provider is missing:

that lane is marked missing
readiness reflects it
doctor mode reflects it
receipt chains reflect what actually ran
the runtime degrades instead of pretending full capability

That is intentional.
Current strengths
What this repo now does well:

makes runtime control explicit
makes degraded state explicit
separates policy reasoning from policy authority
records why escalation happened
supports multimodal inspection without making it mandatory
keeps artifacts and receipts inspectable
supports architecture and programming pack execution under the same runtime spine

Current limitations
What still remains true:

there is no claim of production hardening
provider wiring is runtime-environment dependent
readiness is health-oriented, not full deployment validation
packs are still bounded, not universal
advisory lanes do not yet represent a full enterprise policy language
this repo is still a disciplined proof-of-concept, not a finished control plane product

Why this repo matters
A lot of "agent" projects still behave like this:

prompt in
text out
maybe tools
maybe logs
very little proof

BlackFox is trying to move the conversation toward:

explicit routing
explicit governance
explicit readiness
explicit receipts
explicit escalation
explicit post-run verification

That is a more serious direction for AI runtime engineering.
Recommended next step after this wave
The next sensible engineering step is to add a forward-facing operator surface on top of the runtime you now have:

one operator-grade CLI entrypoint for task submission and report inspection
one structured configuration document for providers and lane policy
one end-to-end demo flow showing degraded vs ready vs escalated runs
one concise system diagram image in the repo
one benchmark / validation section showing how the runtime behaves under missing-provider and contradiction scenarios

That would make BlackFox much easier for serious reviewers to assess quickly.

License
Apache License 2.0.
See LICENSE.

Final framing

IX-BlackFox should be evaluated as:
a governed, auditable AI runtime scaffold designed to make multi-brain execution inspectable, controllable, and reviewable — not mystical, not autonomous-by-default, and not trust-me software.
