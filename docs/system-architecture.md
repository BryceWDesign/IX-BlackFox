# IX-BlackFox System Architecture

## Purpose

IX-BlackFox is a programming-first intelligence runtime built as one sovereign codebase.

Its goal is not to act like a loose swarm of endpoints or a generic chatbot.  
Its goal is to turn requests into explicit, auditable, tool-capable execution flows under governance.

The governing principles are:

- one kernel
- explicit task structures
- deterministic routing where possible
- tiered memory instead of one flat history blob
- controlled forge execution
- policy-gated runtime behavior
- approval-aware escalation paths
- chained receipts and provenance
- verification before trust

---

## Top-Level Shape

BlackFox is organized into the following core subsystems:

- `config/`
- `kernel/`
- `bus/`
- `switchboard/`
- `packs/`
- `memory/`
- `vault/`
- `sentinel/`
- `forge/`
- `eval/`
- `observability/`
- `runtime/`
- `interface/`

These are not cosmetic folders. Each exists to enforce a boundary.

---

## Runtime Flow

A governed runtime flow is intended to look like this:

1. **Interface intake**
   - CLI or future API surface receives a request.
   - Optional governance approval artifacts may be attached.

2. **Kernel normalization**
   - Request becomes a typed task.
   - Shared runtime state is prepared.
   - Lifecycle and execution status become explicit.

3. **Task inference**
   - If kind is unknown, deterministic inference attempts to classify the task.

4. **Switchboard routing**
   - Internal capability routes are scored.
   - The best pack is selected using task kind, labels, and fallback rules.

5. **Governance preflight**
   - A normalized action intent is created for runtime pack dispatch.
   - Risk is classified.
   - Policy decides whether work is allowed, review-required, or blocked.
   - A governed execution ticket is created.

6. **Approval resolution**
   - If the action requires review, approval artifacts are normalized and checked.
   - Runtime either proceeds, pauses pending approval, or remains blocked.

7. **Receipt capture**
   - Governance receipts record preflight, approval outcome, execution start, execution result, and verification result.
   - Chains are verified before trust is finalized.

8. **Pack execution**
   - The selected pack creates a deterministic plan or structured action output.
   - Pack events are published to the bus.
   - Shared state is updated.

9. **Sentinel evaluation**
   - Runtime safety checks inspect contradictions, repeated failures, guardrail problems, and governance consistency.

10. **Evaluation and verification**
    - Findings, evidence, regression outcomes, governance signals, and artifact expectations are combined.
    - A final verification status is derived.

11. **Persistence and audit capture**
    - Run reports, governance receipt chains, artifacts, evidence, provenance, and sealed state are persisted.

12. **Observability and memory retention**
    - Logs, traces, episodic memory, semantic memory, artifact memory, and shared state remain available for audit and debugging.

---

## Subsystem Responsibilities

## 1. Configuration

### Module
- `config/`

### Responsibility
Configuration is centralized and typed.  
BlackFox does not scatter environment reads throughout the codebase.

### Current capabilities
- typed runtime config
- path normalization
- config file loading
- environment override handling
- deterministic runtime directory creation

### Why it exists
Configuration drift destroys reproducibility.  
The config layer exists so every subsystem runs from one normalized runtime model.

---

## 2. Kernel

### Module
- `kernel/`

### Responsibility
The kernel is the orchestration center of BlackFox.  
It owns lifecycle state, typed task intake, and shared coordination state.

### Current capabilities
- kernel lifecycle states
- task request and task record models
- shared state store
- immutable snapshots

### Design rule
The kernel must remain small, explicit, and stable.  
It should orchestrate work, not become a dumping ground for domain logic.

---

## 3. Internal Bus

### Module
- `bus/`

### Responsibility
The bus carries typed event envelopes between subsystems.

### Current capabilities
- typed topics
- immutable envelopes
- in-memory dispatch
- dispatch result tracking
- event history

### Design rule
Subsystems should communicate through stable message contracts when practical.  
This improves observability and reduces hidden cross-module coupling.

---

## 4. Switchboard

### Module
- `switchboard/`

### Responsibility
The switchboard decides which internal capability should receive a task.

### Current capabilities
- capability route definitions
- deterministic scoring
- fallback routes
- route snapshots

### Design rule
Routing must be inspectable.  
BlackFox does not hide routing behind vague magic.  
Task kind, labels, and declared capability support should explain why a route was selected.

---

## 5. Packs

### Module
- `packs/`

### Responsibility
Packs are internal specialist units.  
They are not separate repositories and they are not fake “agents” talking over fragile local services.

### Current capabilities
- manifest model
- manifest registry
- pack loader
- base pack execution contract
- built-in programming pack
- built-in architecture pack

### Design rule
Specialization belongs inside one controlled runtime.  
Packs provide domain behavior without fracturing the system into repo sprawl.

---

## 6. Memory

### Module
- `memory/`

### Responsibility
Memory is tiered so the runtime can preserve context without collapsing every signal into one undifferentiated store.

### Current layers

#### Working memory
Short-horizon mutable execution context.

Used for:
- current plan fragments
- active coordination values
- in-progress assumptions

#### Episodic memory
Session-scoped recollection of prior events and outcomes.

Used for:
- task outcome summaries
- prior run records
- sequence reconstruction

#### Semantic memory
Distilled reusable facts, rules, and constraints.

Used for:
- remembered facts
- reusable constraints
- stable conceptual state

#### Artifact memory
Durable file and output tracking.

Used for:
- reports
- manifests
- patches
- produced artifacts

#### Trace memory
Execution trace records for runtime auditability.

Used for:
- stage tracking
- correlation-aware traces
- failure pattern inspection

### Design rule
Different memory classes solve different problems.  
Flattening them together makes retrieval sloppy and behavior hard to reason about.

---

## 7. Vault

### Module
- `vault/`

### Responsibility
Vault protects integrity, provenance, and structured persisted state.

### Current capabilities
- HMAC-sealed payloads
- content fingerprinting
- provenance hash chains
- disk-backed integrity-checked state
- logical redaction helper

### Design rule
The current vault layer is about integrity and provenance first.  
It does **not** overclaim full confidentiality where that has not been implemented.

---

## 8. Governance

### Modules
- `governance/`
- `runtime/governance.py`
- `runtime/approval.py`
- `runtime/receipts.py`

### Responsibility
Governance is the action-control layer that turns BlackFox from “auditable planning runtime” into “governed execution runtime.”

It makes runtime and forge actions explicit before execution, classifies their risk, applies policy, handles approval requirements, and records receipt chains.

### Current capabilities
- normalized action intents
- canonical action kinds
- risk-factor and risk-profile modeling
- deterministic policy decisions
- approval requests and approval decisions
- disk-backed approval state storage
- chained governance receipt ledgers
- runtime preflight governance
- runtime approval resolution from attached metadata
- persisted receipt artifacts per run

### Governance contract
Every meaningful governed action should have an answer to the following:

- what was proposed
- what risk was assigned
- what policy decided
- whether approval was required
- whether approval was satisfied
- whether execution happened
- what receipt chain proves it

### Design rule
BlackFox should not silently jump from planning to execution.  
Governance is the explicit trust boundary between intention and action.

---

## 9. Sentinel

### Module
- `sentinel/`

### Responsibility
Sentinel is the runtime conscience.  
It inspects behavior for contradictions, loops, policy boundary problems, and governance consistency failures.

### Current capabilities
- sentinel runtime
- check registration and snapshots
- contradiction detection
- repeated failure-loop detection
- policy guardrail checks
- governance consistency checks

### Governance consistency focus
Sentinel now explicitly checks for cases such as:
- blocked actions that still executed
- review-gated actions that executed without approval
- inconsistent approval state declarations
- governance observation payload errors

### Design rule
Safety signals should be explicit issues, not hidden side effects.  
A failing check should become an observable issue, not silent instability.

---

## 10. Forge

### Module
- `forge/`

### Responsibility
Forge is the programming workbench.

This is the subsystem that turns BlackFox from “something that talks about code”
into “something that can operate on code under control.”

### Current capabilities
- isolated workspace reservation
- file graph scanning
- static Python analysis
- patch plan generation
- governed patch-intent bridging
- forge execution tickets
- shell-free command execution
- governed command execution
- pytest test running
- regression collection from JUnit XML

### Governance-aware forge behavior
Forge no longer treats execution as an implicit step.

Instead it can:
- convert patch plans into governed action bundles
- classify command risk
- generate governed execution tickets
- require approvals before high-risk command execution
- emit governance receipts around command execution

### Design rule
All material code work should occur inside controlled workspaces.  
Execution needs boundaries, artifacts, and inspectable results.

---

## 11. Evaluation

### Module
- `eval/`

### Responsibility
Evaluation measures whether work is acceptable instead of assuming it is.

### Current capabilities
- deterministic evaluator model
- rule-based evaluators
- benchmark case and suite schemas
- evidence recording
- output verification
- regression-aware verification
- governance-signal verification
- approval-state-aware verification
- receipt-chain integrity checks in verification context

### Verification contract
A run is not trusted just because it produced output.

Verification now also checks:
- expected versus produced artifacts
- evaluation outcomes
- regression outcomes
- required governance signals
- governance receipt-chain integrity
- approval satisfaction when required

### Design rule
A result is not trusted just because it exists.  
BlackFox should grade its own work against explicit rules, evidence, outputs, and governance state.

---

## 12. Observability

### Module
- `observability/`

### Responsibility
Observability provides append-only structured logs.

### Current capabilities
- JSONL structured logger
- typed log levels
- log snapshots and filtering
- correlation-aware event logging

### Design rule
If behavior cannot be inspected, it cannot be trusted or debugged.  
Observability is not optional glue. It is part of the runtime contract.

---

## 13. Runtime

### Module
- `runtime/`

### Responsibility
Runtime is the fusion layer that turns the rest of the repository into one explicit execution spine.

It binds together:
- task inference
- route selection
- governance preflight
- approval resolution
- receipt capture
- pack dispatch
- sentinel checks
- evaluation
- verification
- artifact persistence
- provenance
- replay awareness
- memory updates

### Current capabilities
- default fully wired runtime composition
- deterministic prompt-to-task execution
- governance-aware pack dispatch
- approval-gated pause behavior
- persisted run reports
- persisted governance receipt reports
- explicit runtime status outcomes:
  - `passed`
  - `needs_review`
  - `failed`

### Runtime status semantics

#### `passed`
The run completed with no blocking verification issues.

#### `needs_review`
The run is not trusted yet, typically due to:
- approval still pending
- warning-grade evaluation or verification issues

#### `failed`
The run hit a blocking condition, such as:
- no valid route
- governance block
- execution failure
- verification failure

### Design rule
Runtime is where the repo’s thesis becomes real.  
It must remain explicit, inspectable, and bounded.

---

## 14. Interface

### Module
- `interface/`

### Responsibility
Provides operator-facing entrypoints.

### Current status
- CLI entrypoint exists
- JSON and human-readable summaries exist
- approval artifacts can be loaded from JSON files
- richer API and operator surfaces are intentionally deferred

### Design rule
Interface layers should stay thin.  
The real intelligence runtime belongs underneath them.

---

## 15. Assurance Evidence Packaging

### Module
- `assurance/`

### Responsibility
Wave 12 assembles real prior-wave and quality evidence into a deterministic,
content-addressed package for separate external assessment.

The serialized-package verifier recomputes the control crosswalk, review
qualification, readiness decision, bundle index, and in-toto statement from the
reopened archive. Local evidence is integrity verified, but only an externally
verified human-review artifact can satisfy the external-assessment authority
gate.

### Current capabilities
- revision-bound evidence collection
- stale-evidence rejection through JSON pointers
- symlink, traversal, secret, private-key, duplicate, and size rejection
- required and optional assurance-profile controls
- bounded NIST, OSCAL, SLSA, and in-toto mappings
- explicit asserted claims and non-claims
- separate human-authority review gate with external-verification requirement
- model, tool, CI, system, and self-approval blocking
- deterministic ZIP construction
- unsigned in-toto Statement v1 export
- independent archive safety and semantic-binding verification
- shell-free quality-gate evidence capture
- `blackfox assurance build`, `verify`, and `gate` commands

### Design rule
Packaging evidence must never silently convert evidence into authority.
`review_required` is the expected offline CI state. Only a separately
authenticated human approval can advance a coherent package to
`ready_for_external_assessment`, which still does not mean certification,
compliance, production readiness, or deployment approval.

---

## Built-In Packs

## Programming Pack

### Purpose
Handles programming-oriented tasks in a deterministic first-pass manner.

### Current behavior
- derives structured plan steps from prompt cues
- records state updates
- publishes pack events
- emits structured output data and metrics

### Important limitation
It does not pretend to autonomously repair code yet.  
It creates a stable action contract for forge-linked execution and governed runtime handling.

---

## Architecture Pack

### Purpose
Handles architecture-oriented tasks in a deterministic first-pass manner.

### Current behavior
- derives explicit architecture decisions from prompt cues
- records state updates
- publishes pack events
- emits structured design decisions and metrics

### Important limitation
It does not fabricate full system diagrams or implementation proof automatically.  
It creates explicit architecture recommendations for later planning and documentation layers.

---

## Governance and Trust Model

BlackFox now has a clearer trust model than a simple planner runtime.

### Current trust chain
1. request intake
2. typed task normalization
3. deterministic routing
4. governance preflight
5. approval resolution when required
6. receipt emission
7. pack execution
8. sentinel review
9. evaluation
10. verification
11. persistence and evidence recording

### What this changes
The runtime is no longer only asking:
- what should I do
- what route should I take
- what artifact did I produce

It is also asking:
- what action is actually being proposed
- should this be allowed
- do I need approval
- did I get approval
- what receipt chain proves what happened

That is the essential shift into governed execution.

---

## Safety Posture

BlackFox is designed to be strong, but not reckless.

### Current posture
- deterministic internal boundaries
- no default shell execution with `shell=True`
- workspace path containment
- policy observation checks
- governance preflight
- approval-gated review paths
- receipt-chain integrity
- provenance and integrity mechanisms
- regression and evaluation layers
- verification before trust

### Non-goals of the current implementation
- destructive host mutation by default
- autonomous privileged system behavior
- hidden routing
- unverifiable output claims
- theatrical security claims without implementation backing
- fake “self-improving” behavior that bypasses governance

---

## Why This Architecture Exists

The architecture exists to avoid common failure modes:

### Failure mode: “one giant blob”
Prevented by:
- clear subsystem boundaries
- typed models
- explicit contracts

### Failure mode: “microservice sprawl for no reason”
Prevented by:
- one sovereign codebase
- internal packs instead of repo fragmentation

### Failure mode: “memory as random leftovers”
Prevented by:
- tiered memory layers with distinct purposes

### Failure mode: “AI output with no proof”
Prevented by:
- evidence recording
- evaluation
- regression collection
- output verification

### Failure mode: “execution with no control boundary”
Prevented by:
- governance preflight
- action intents
- policy decisions
- approval resolution
- execution tickets
- receipt chains

### Failure mode: “safety through vibes”
Prevented by:
- sentinel checks
- policy observations
- governance consistency checks
- provenance
- structured logging

---

## Current Maturity

This repository is now best described as a **governed execution runtime foundation**, not merely a planning scaffold.

### What is already real
- runtime structure
- subsystem boundaries
- typed contracts
- deterministic routing
- tiered memory
- vault integrity base
- governance package and policy layer
- approval modeling
- receipt-chain capture
- sentinel governance consistency checks
- forge workspace and execution tools
- governed command execution
- evaluation and verification scaffolding
- built-in specialist packs
- CLI execution path
- smoke-path and matrix-path validation

### What is intentionally still ahead
- deeper kernel scheduling
- richer pack orchestration
- promotion flows across memory tiers
- stronger forge patch application loops
- broader benchmark coverage
- multi-step approval strategies
- richer operator interfaces
- advanced semantic routing
- local model integration layers

---

## Architectural Thesis

The core architectural thesis of BlackFox is:

> intelligence should behave like a controlled operating runtime, not like a floating text box.

For BlackFox, that now means:
- explicit tasks
- explicit routing
- explicit governance
- explicit approval boundaries
- explicit execution tickets
- explicit receipt chains
- explicit evaluation
- explicit verification
- explicit audit trails

That is the footing this repository is built on.
