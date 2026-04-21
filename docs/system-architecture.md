# IX-BlackFox System Architecture

## Purpose

IX-BlackFox is a programming-first intelligence runtime built as one sovereign codebase.  
Its goal is not to act like a loose swarm of endpoints or a generic chatbot.  
Its goal is to turn requests into explicit, auditable, tool-capable execution flows.

The design principles are:

- one kernel
- explicit task structures
- deterministic routing where possible
- tiered memory instead of one flat history blob
- controlled forge execution
- auditable traces and evidence
- policy-aware runtime safety
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

A normal runtime flow is intended to look like this:

1. **Interface intake**
   - CLI or future API surface receives a request.

2. **Kernel normalization**
   - Request becomes a typed task.
   - Shared runtime state is prepared.
   - Lifecycle and execution status become explicit.

3. **Switchboard routing**
   - Internal capability routes are scored.
   - The best pack is selected using task kind, labels, and fallback rules.

4. **Pack execution**
   - The selected pack creates a deterministic plan or structured action output.
   - Pack events are published to the bus.
   - Shared state is updated.

5. **Runtime orchestration**
   - The runtime layer fuses task-kind inference, replay observation, routing, pack execution, sentinel checks, evaluation, verification, artifact persistence, provenance, and sealed state capture into one explicit execution spine.

6. **Forge execution**
   - When code or repository work is needed, the forge handles workspace isolation,
     file scanning, analysis, patch planning, command execution, testing, and regression collection.

7. **Sentinel evaluation**
   - Runtime safety checks inspect contradictions, repeated failures, and policy problems.

8. **Evaluation and verification**
   - Findings, evidence, regression outcomes, and artifact expectations are combined.
   - A final verification status is derived.

9. **Observability and trace retention**
   - Logs, traces, evidence, and memory records remain available for audit and debugging.

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

## 8. Sentinel

### Module
- `sentinel/`

### Responsibility
Sentinel is the runtime conscience.
It inspects behavior for contradictions, loops, and policy boundary problems.

### Current capabilities
- sentinel runtime
- check registration and snapshots
- contradiction detection
- repeated failure-loop detection
- policy guardrail checks

### Design rule
Safety signals should be explicit issues, not hidden side effects.
A failing check should become an observable issue, not silent instability.

---

## 9. Forge

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
- shell-free command execution
- pytest test running
- regression collection from JUnit XML

### Design rule
All material code work should occur inside controlled workspaces.
Execution needs boundaries, artifacts, and inspectable results.

---

## 10. Evaluation

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

### Design rule
A result is not trusted just because it exists.
BlackFox should grade its own work against explicit rules, evidence, and produced outputs.

---

## 11. Observability

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

## 12. Interface

### Module
- `interface/`

### Responsibility
Provides operator-facing entrypoints.

### Current status
- CLI placeholder exists
- richer API and operator surfaces are intentionally deferred

### Design rule
Interface layers should stay thin.
The real intelligence runtime belongs underneath them.

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
It creates a stable action contract for future forge-linked execution.

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

## Safety Posture

BlackFox is designed to be strong, but not reckless.

### Current posture
- deterministic internal boundaries
- no default shell execution with `shell=True`
- workspace path containment
- policy observation checks
- provenance and integrity mechanisms
- regression and evaluation layers

### Non-goals of the current implementation
- destructive host mutation by default
- autonomous privileged system behavior
- hidden routing
- unverifiable output claims
- theatrical security claims without implementation backing

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

### Failure mode: “safety through vibes”
Prevented by:
- sentinel checks
- policy observations
- provenance
- structured logging

---

## Current Maturity

This repository is a **foundation runtime**, not a finished full-stack autonomous programming system yet.

### What is already real
- runtime structure
- subsystem boundaries
- typed contracts
- deterministic routing
- tiered memory
- vault integrity base
- sentinel checks
- forge workspace and execution tools
- evaluation and verification scaffolding
- built-in specialist packs
- smoke-path validation

### What is intentionally still ahead
- deeper kernel scheduling
- richer pack orchestration
- promotion flows across memory tiers
- stronger forge patch execution loops
- broader benchmark coverage
- additional built-in packs
- richer operator interfaces
- advanced semantic routing
- local model integration layers

---

## Architectural Thesis

The core architectural thesis of BlackFox is:

> intelligence should behave like a controlled operating runtime, not like a floating text box.

That means:
- explicit tasks
- explicit memory
- explicit execution boundaries
- explicit evaluation
- explicit verification
- explicit audit trails

That is the footing this repository is built on.

---

## 11. Runtime Composition Layer

### Module
- `runtime/`

### Responsibility
The runtime package is the execution spine that turns BlackFox from a collection of good subsystems into a single auditable run path.

### Current capabilities
- deterministic task-kind inference for unknown intake
- replay-aware task fingerprint observation
- explicit route selection and pack loading
- end-to-end pack execution composition
- sentinel, evaluation, and verification wiring
- artifact materialization for pack outputs
- provenance-ledger append for run artifacts
- sealed vault persistence for run reports
- CLI-backed task execution surface

### Design rule
The runtime layer composes subsystems.
It should not erase their boundaries.
Its job is to wire explicit contracts together, preserve auditability, and keep execution explainable.
