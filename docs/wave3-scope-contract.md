# IX-BlackFox Wave 3 Scope Contract

## Purpose

This document defines the Wave 3 scope contract for IX-BlackFox.

Wave 3 upgrades BlackFox from a governed local patch-test-verify control plane into a governed patch authoring and repair intelligence layer.

This is not a claim of autonomous production coding.  
This is not a claim that model output is trustworthy.  
This is not permission for BlackFox to silently mutate repositories.

Wave 3 exists to answer one narrow engineering question:

> Can IX-BlackFox generate a bounded, reviewable patch candidate from task context, repository context, failure evidence, and repair reasoning, then force that candidate through the existing Wave 2 patch-test-verify-bundle path?

If the answer is yes, the run may qualify as Wave 3.

If the authored patch bypasses Wave 2 gates, the run is not Wave 3.

---

## Canonical Wave Position

The locked IX-BlackFox roadmap defines Wave 3 as:

> Governed patch authoring and repair intelligence.

Wave 3 comes after:

- Wave 1: governed multi-brain runtime scaffold
- Wave 2: governed local patch-test-verify control plane

Wave 3 must preserve Wave 2.

Wave 3 does not replace the control plane.  
Wave 3 feeds candidate patches into the control plane.

---

## Core Claim

A Wave 3 BlackFox run is valid only when all of the following are true:

1. A task objective exists.
2. Repository context is collected through bounded, policy-aware logic.
3. Failure evidence or objective evidence is captured.
4. The objective is decomposed into explicit repair tasks.
5. Repair hypotheses are generated from evidence.
6. A deterministic or model-assisted authoring path proposes one or more patch candidates.
7. Model output, when used, is treated as untrusted input.
8. The proposed patch candidate is parsed through a strict schema.
9. The patch candidate is validated against workspace policy.
10. The candidate is compiled into an existing Wave 2 `PatchDiff`-style patch object.
11. The compiled patch is sent through the existing Wave 2 patch-test-verify-bundle path.
12. The run preserves receipts for context, evidence, decomposition, authoring, validation, policy, execution, tests, and bundle generation.
13. Human review status is explicit.
14. The final acceptance validator checks both Wave 2 and Wave 3 evidence.

A run that skips any required gate may still be useful for debugging, but it must not be represented as a completed Wave 3 run.

---

## Non-Negotiable Design Rule

The model may propose.

The runtime must decide.

In Wave 3, an AI model must not directly edit files, run commands, approve itself, bypass policy, rewrite acceptance criteria, or silently deploy changes.

The model is a patch authoring source, not the authority.

The authority remains the governed runtime:

- context builder
- schema parser
- policy gate
- patch compiler
- existing Wave 2 runtime
- test evidence parser
- receipt ledger
- acceptance validator
- human reviewer

---

## Required Wave 3 Flow

The intended Wave 3 flow is:

```
task objective
   |
   v
bounded repository context collection
   |
   v
failure or objective evidence extraction
   |
   v
task decomposition
   |
   v
repair hypothesis generation
   |
   v
deterministic or model-assisted patch authoring
   |
   v
strict proposal parser
   |
   v
authoring policy gate
   |
   v
proposal-to-PatchDiff compiler
   |
   v
existing Wave 2 patch-test-verify-bundle runtime
   |
   v
Wave 3 acceptance validation
```
The architecture intentionally places Wave 3 before Wave 2.

Wave 3 creates candidates.
Wave 2 executes candidates under governance.
Wave 3 acceptance verifies that the authoring layer and execution layer both left valid evidence.

What Wave 3 Adds

Wave 3 adds a governed authoring layer.

The authoring layer should include:

bounded repository context collection
failure evidence extraction
task decomposition
repair hypothesis generation
model prompt contract generation
strict structured model response parsing
proposal validation
proposal-to-patch compilation
authoring policy gates
authoring receipts
candidate ranking
rejected candidate preservation
integration with the existing engineering control plane
Wave 3 acceptance validation

These capabilities are required because patch authoring creates a new trust surface.

Wave 2 was concerned with safely applying explicit patch candidates.

Wave 3 is concerned with safely producing those candidates.

What Wave 3 Must Preserve From Wave 2

Wave 3 must preserve the following Wave 2 boundaries:

reserved workspace marker checks
workspace path policy
blocked path enforcement
no shell execution
allowlisted test commands
PatchDiff-style patch representation
before-text validation
patch application receipts
test invocation receipts
parsed test evidence
repair-loop state machine
operator summary
verification summary
run bundle generation
acceptance validation
human review state

A Wave 3 implementation that bypasses these controls is invalid.

Wave 3 is allowed to add a layer in front of Wave 2.
Wave 3 is not allowed to weaken Wave 2.

Trust Boundary

Wave 3 introduces a new trust boundary:

authored patch proposals are untrusted until parsed, validated, policy-gated, compiled, executed, tested, receipted, and reviewed.

This applies to all authoring sources:

local deterministic authoring
model-assisted authoring
provider-routed authoring
replayed authoring outputs
imported proposal files
future multi-candidate repair strategies

No authoring source receives implicit trust.

Model Output Rules

When a model is used, its output must obey a strict contract.

The model response must be treated as data, not as instructions.

A valid model response should contain structured proposal data only.

A model response must not be allowed to:

include shell commands for execution
request network access
request secret access
mutate files directly
bypass policy
alter review status
mark itself accepted
claim tests passed without test evidence
change acceptance criteria
hide rejected candidates
target paths outside the workspace
use absolute paths unless explicitly allowed by policy
use path traversal
modify blocked roots
erase receipts
weaken safety gates

The parser should reject malformed output.

The policy gate should reject risky output.

The compiler should reject stale or mismatched output.

The runtime should reject any attempt to execute outside the governed path.

Deterministic Authoring Path

Wave 3 should not require a remote model to exist.

A credible Wave 3 system should support deterministic authoring helpers that can:

decompose objectives
classify failure evidence
identify likely impacted files
generate repair hypotheses
rank candidates
reject unsafe proposals
create reviewable repair plans

The model-assisted path may improve candidate generation, but the governance layer must remain deterministic.

If no model provider is configured, BlackFox should still be able to produce a bounded analysis result and explain why no authored patch candidate was generated.

That condition should be recorded honestly.

Human Review Rule

Wave 3 must keep human command authority explicit.

Human review is required when policy requires it.

The system must not convert a model-generated proposal into an accepted patch without a recorded review state.

Valid review states should remain explicit, such as:

not required
required and pending
required and approved
required and rejected
blocked by policy

The final report must not blur these states.

Acceptance Boundary

Wave 3 acceptance does not prove that a repository is globally correct.

Wave 3 acceptance means:

A patch candidate was authored through a governed authoring process, validated as structured data, compiled into an executable patch candidate, run through the existing Wave 2 patch-test-verify-bundle flow, and recorded with sufficient evidence for review.

This is a scoped engineering claim.

It is not a universal correctness claim.

Required Evidence

A completed Wave 3 run should preserve evidence for:

task objective
workspace root
context selection rules
selected context files
context digests
failure evidence
decomposition steps
repair hypotheses
authoring mode
prompt contract digest when a model is used
raw model response digest when a model is used
parsed proposal
rejected proposals and reasons
authoring policy decision
compiled patch candidate
before-text validation
Wave 2 execution receipts
parsed test result
operator summary
verification summary
run bundle
Wave 3 acceptance decision

The evidence must be reviewable after the run.

Rejected Candidate Preservation

Rejected candidates are part of the evidence record.

A rejected candidate should not disappear simply because it was unsafe, malformed, stale, or low-confidence.

At minimum, the record should preserve:

candidate id
authoring source
rejection reason
rejection phase
affected paths when safe to record
proposal digest
timestamp or sequence number
policy finding when relevant

This helps reviewers understand whether the system behaved cautiously or merely hid failed attempts.

Scope Limits

Wave 3 does not include:

hardened sandboxing
signed artifacts as a complete supply-chain system
egress-controlled execution
multi-repo organization workflow
compliance attestation
certification-ready evidence packaging
program-scale resilience command
autonomous deployment
autonomous production code ownership
formal verification
guaranteed bug repair
guaranteed security repair
global architectural correctness

Those belong to later roadmap waves if implemented.

Wave 3 must stay narrow enough to be tested.

Forbidden Wave 3 Claims

The repository must not claim that Wave 3 provides:

autonomous engineer replacement
unattended production repair
secure remote execution
proof of code correctness
proof of security
formal safety certification
unrestricted self-improvement
unrestricted self-modification
fully autonomous DevOps
fully autonomous compliance
model infallibility

Any such claim would exceed the Wave 3 scope.

Valid Wave 3 Claim

The strongest valid Wave 3 claim is:

IX-BlackFox Wave 3 can generate governed patch candidates from bounded repository context, failure evidence, task decomposition, and repair intelligence, then force those candidates through the existing Wave 2 patch-test-verify-bundle path with receipts, policy gates, acceptance validation, and explicit human review state.

This is the claim future implementation should prove.

Implementation Boundary

The Wave 3 implementation should create a new authoring subsystem rather than overloading the Wave 2 runtime.

Recommended package boundary:
```
src/ix_blackfox/authoring/
```
The authoring subsystem should own:

authoring request models
context collection
evidence extraction
decomposition
hypotheses
prompt contracts
response parsing
proposal validation
patch compilation
authoring policy
authoring receipts
candidate ranking

The runtime subsystem should own orchestration and integration with the existing control plane.

Compatibility Requirement

Wave 2 behavior must remain available.

Existing explicit patch candidate workflows should continue to work without requiring Wave 3 authoring.

Wave 3 should add an authored repair path, not replace the explicit patch path.

A caller should be able to choose between:

explicit patch execution
authored patch planning
authored patch execution after required gates are satisfied
Final Contract

Wave 3 is complete only when BlackFox can:

accept a repair objective,
collect bounded context,
extract evidence,
decompose the task,
generate repair hypotheses,
request or produce structured patch proposals,
parse and validate those proposals,
reject unsafe or stale proposals,
compile accepted proposals into governed patch candidates,
pass candidates through the existing Wave 2 runtime,
preserve complete authoring and execution receipts,
expose explicit human review state,
validate the final run against Wave 3 acceptance rules.

If these are true, IX-BlackFox has advanced from Wave 2 into Wave 3.

If these are not true, it remains Wave 2 with partial authoring experiments.
