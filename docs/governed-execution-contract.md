# IX-BlackFox Governed Execution Contract

## Purpose

This document defines the runtime contract for governed execution in IX-BlackFox.

It is not a marketing file.  
It is the technical boundary that explains:

- what governed execution means in this repository
- what runtime phases are allowed
- what evidence must exist at each phase
- what approval means
- what receipts mean
- what verification must prove before a run is trusted

This contract exists so BlackFox does not quietly slide from
“structured runtime” into “unbounded automation.”

---

## Core Claim

A BlackFox run is only considered governed when it satisfies all of the following:

1. the request is normalized into a typed task
2. a runtime route is selected explicitly
3. governance preflight produces a normalized action intent
4. risk is classified
5. policy decides allow, require review, or block
6. approval is resolved when required
7. receipts record the governance path
8. execution only happens when governance allows it
9. verification checks both output quality and governance integrity
10. the final report persists the evidence chain

If one or more of these do not happen, the run may still exist, but it is not a fully governed execution.

---

## Governed Runtime Phases

The runtime phase order is intentionally strict.

### Phase 1 — Intake
The request enters through an interface surface and becomes a typed task request.

Required outputs:
- task id
- prompt
- task kind or inferred kind
- labels
- optional metadata
- optional attachments

Required evidence:
- intake trace

Failure condition:
- malformed task construction

---

### Phase 2 — Routing
The switchboard selects a capability route.

Required outputs:
- route capability name
- route reason
- route confidence
- matched labels

Required evidence:
- routing trace
- route evidence record in final run

Failure condition:
- no route selected

---

### Phase 3 — Governance Preflight
The runtime creates the first governed action model for pack dispatch.

Required outputs:
- action intent
- risk profile
- policy decision
- forge-style execution ticket

Required evidence:
- governance trace
- governance evidence record
- first receipt entry in the receipt chain

Allowed decisions:
- `allow`
- `require_review`
- `block`

Failure condition:
- missing or invalid governance model
- blocked path that proceeds anyway

---

### Phase 4 — Approval Resolution
If the governance decision requires review, runtime approval artifacts are normalized and resolved.

Required outputs when review is required:
- approval resolution object
- approval ids
- satisfied or unsatisfied review state
- any parsing or validation issues

Required evidence:
- approval trace when review is required
- approval evidence record when approval is required
- approval receipt when approval is satisfied or explicitly rejected

Failure condition:
- review required but execution proceeds without satisfied approval

---

### Phase 5 — Controlled Execution
Only after governance allows execution may the selected pack run.

Required outputs:
- pack name
- pack summary
- pack artifacts
- pack metrics

Required evidence:
- execution started receipt
- execution completed or failed receipt
- pack trace

Failure condition:
- blocked action executes
- review-gated action executes without satisfied approval
- pack execution throws and failure is not captured

---

### Phase 6 — Sentinel Review
Sentinel inspects runtime behavior for contradictions, loop conditions, policy problems, and governance inconsistencies.

Required outputs:
- sentinel report
- zero or more sentinel issues

Required evidence:
- sentinel evidence record

Failure condition:
- sentinel detects blocking governance inconsistency
- sentinel detects critical contradiction or policy failure

---

### Phase 7 — Evaluation
Evaluation scores the run quality using explicit rules.

Required outputs:
- evaluation result
- score
- findings

Required evidence:
- evaluation evidence record

Failure condition:
- error-grade evaluation finding
- zero-evaluation situation where the repo contract required one

---

### Phase 8 — Verification
Verification determines whether the run is trustworthy enough to pass, requires review, or fails.

Required inputs:
- evaluation result
- expected artifacts
- produced artifacts
- governance signal state
- approval state
- governance chain integrity result

Required outputs:
- verification status
- verification issues

Allowed verification statuses:
- `passed`
- `needs_review`
- `failed`

Failure condition:
- missing required governance signal
- invalid governance receipt chain
- missing expected artifact
- failed evaluation
- failed regression signal
- blocking verification issue

---

### Phase 9 — Persistence
The runtime persists the run report, governance receipts artifact, state capsule, evidence records, provenance, traces, and artifact memory references.

Required outputs:
- persisted run report
- persisted governance receipt artifact when governance ran
- provenance entries
- artifact memory updates
- state capsule update

Failure condition:
- run finishes but cannot be reconstructed from persisted records

---

## Governed Decisions

BlackFox uses three canonical runtime governance decisions.

## `allow`
The runtime may proceed without explicit approval.

Interpretation:
- action is within current policy tolerance
- no approval gate blocks execution

Expected receipt event:
- `policy_allowed`

---

## `require_review`
The runtime may not proceed until approval is satisfied.

Interpretation:
- action is not forbidden
- but it crosses a review boundary

Expected receipt event:
- `policy_review_required`

Expected approval state:
- `required = true`

Expected runtime behavior:
- pause if approval is missing
- continue only when approval is satisfied

---

## `block`
The runtime must not execute the action.

Interpretation:
- action is outside current allowed boundary

Expected receipt event:
- `policy_blocked`

Expected runtime behavior:
- no pack execution
- no forge mutation
- final run should fail verification or final status accordingly

---

## Approval Contract

Approval is not a vague human concept in BlackFox.  
It is a normalized runtime object.

### An approval path is considered valid only when:
- an approval resolution exists
- approval is marked as required
- at least one approval state targets the same governed intent
- at least one approval state is terminally `approved`

### Approval does not count when:
- the artifact exists but does not normalize
- the status is missing or invalid
- the approval targets the wrong intent
- the status is only pending
- the approval says approved but the runtime never recorded it

### Approval statuses
- `pending`
- `approved`
- `rejected`
- `canceled`

### Approval invariants
- a blocked action cannot be rescued by approval
- approval only matters on review-gated actions
- satisfied approval must be recorded before governed execution proceeds

---

## Receipt Contract

Receipts are the runtime’s auditable action chain.

They are not generic logs.  
They are tamper-evident execution-state records linked by chain digest.

### Minimum receipt expectations by path

## Allowed run
Expected event order:
1. `policy_allowed`
2. `execution_started`
3. `execution_completed`
4. `verification_passed` or `verification_failed`

## Review-gated run with no approval
Expected event order:
1. `policy_review_required`

No execution events should exist.

## Review-gated run with satisfied approval
Expected event order:
1. `policy_review_required`
2. `approval_recorded`
3. `execution_started`
4. `execution_completed`
5. `verification_passed` or `verification_failed`

## Blocked run
Expected event order:
1. `policy_blocked`
2. `verification_failed`

No execution events should exist.

---

### Receipt invariants
For a governed receipt chain to be valid:

- every record must belong to the same intent id
- each record must point to the previous receipt id correctly
- each record must point to the previous chain digest correctly
- each record’s chain digest must recompute cleanly
- the event order must match the executed path

If any of these break, governance chain verification must fail.

---

## Verification Signal Contract

Verification must inspect governance signals, not only artifacts.

### Required signals when governance ran
- `governance_preflight`
- `governance_receipts`

### Additional required signal when approval was required
- `approval_resolution`

### Governance verification rules
Verification should fail or require review when:

- a required governance signal is missing
- governance receipt chain verification fails
- approval is required but not satisfied
- a run claims governance success but cannot provide receipts

This is essential.

BlackFox does not treat “I think the run was okay” as proof.  
Governance is part of the proof burden.

---

## Sentinel Governance Consistency Contract

Sentinel is expected to inspect governance consistency independently of verification.

### Sentinel must flag at least these cases:

#### Blocked execution
A governed action had decision `block` but still executed.

Expected severity:
- critical

#### Review gate bypass
A governed action had decision `require_review`, executed, and approval was not satisfied.

Expected severity:
- error

#### Review flag mismatch
A governed action says `require_review` but approval_required is false.

Expected severity:
- warning

#### Approval state inconsistency
A governed action says `allow` but is also marked approval_required.

Expected severity:
- warning

#### Unexpected satisfied approval
A governed action claims satisfied approval without actually requiring approval.

Expected severity:
- warning

These checks exist so governance state cannot quietly contradict execution state.

---

## Runtime Status Contract

The runtime exposes three final statuses.

## `passed`
Interpretation:
- no blocking verification issue
- no unresolved governance problem
- required approvals were satisfied
- governance receipt chain is valid when governance ran

## `needs_review`
Interpretation:
- the run is not trusted enough to pass
- but it is not a hard failure
- commonly caused by pending approval or warning-level review conditions

## `failed`
Interpretation:
- the run hit a blocking trust boundary
- examples:
  - no route
  - governance block
  - failed pack execution
  - verification failure
  - invalid governance signal state

### Important note
A run can end with no pack execution and still produce a valid governed audit trail.  
That is not pointless.  
That is the correct behavior for blocked or pending-review paths.

---

## Produced Artifacts Contract

When governance runs, the runtime is expected to produce a governance receipt artifact.

### Standard governance artifact
- `blackfox-governance-receipts.json`

### Standard run report artifact
- `blackfox-run-report.json`

### Artifact expectations by path

## Allowed or approved run
Expected:
- governance receipts artifact
- run report
- pack output artifacts

## Review-pending run
Expected:
- governance receipts artifact
- run report
- no pack output artifacts

## Blocked run
Expected:
- governance receipts artifact
- run report
- no pack output artifacts

This matters because a blocked or paused run still has audit value.

---

## What Governed Execution Does Not Mean

Governed execution in BlackFox does **not** currently mean:

- unrestricted autonomy
- privileged host control
- opaque self-modification
- hidden approval bypasses
- distributed execution mesh
- external trust delegation
- cryptographic nonrepudiation beyond the current internal receipt chain and provenance spine

The current contract is deliberately narrower:

- explicit internal action control
- approval-aware gating
- receipt-chain auditability
- verification-linked trust

That is enough to matter while staying honest.

---

## Current Boundaries

The current governed execution layer is strong, but bounded.

### Strong now
- explicit runtime preflight
- canonical governance models
- approval resolution
- chained receipts
- governance consistency checks
- governance-aware verification
- persisted governance artifacts

### Still ahead
- multi-step approval workflows
- role-scoped approval semantics
- delegated approvals
- stronger operator identity binding
- richer forge patch-application loops
- deeper campaign-level multi-repo governance
- stronger external receipt validation layers

This is intentional.  
The repo is aiming for honest, reviewable controlled execution, not bloated theater.

---

## Final Contract Statement

A BlackFox run should only be described as governed execution when:

- it passed through governance preflight
- approval requirements were resolved honestly
- execution obeyed policy
- receipts recorded the path
- verification checked governance integrity
- persistence preserved the evidence chain

That is the contract.

Anything less may still be useful runtime behavior, but it should not be described as governed execution in the full BlackFox sense.
