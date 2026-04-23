<p align="center">
  <img src="IX-BlackFox-Logo.png" alt="IX-BlackFox Logo">
</p>

# IX-BlackFox

IX-BlackFox is a programming-first intelligence runtime built as **one sovereign codebase**.

Its design center is simple:

**intelligence should behave like a controlled operating runtime, not like a floating text box.**

That means BlackFox is built around:

- explicit task structures
- deterministic routing
- tiered memory
- governed execution
- approval-aware control paths
- chained receipts
- evaluation and verification before trust
- audit-ready persistence

---

## Status

This repository is now a **governed execution runtime foundation**.

It is no longer just a planning scaffold or routing shell.  
It now has a real internal trust boundary between **intention** and **execution**.

BlackFox currently contains working foundations for:

- kernel lifecycle and typed tasks
- deterministic task-kind inference for unknown intake
- internal event bus
- shared state
- deterministic capability routing
- manifest-driven pack loading
- end-to-end runtime orchestration
- replay-aware intake observation
- tiered memory
- vault integrity and provenance
- sentinel checks
- forge workspace, analysis, command, test, and regression tooling
- governed patch-intent modeling
- governed command execution
- runtime governance preflight
- approval resolution
- chained governance receipts
- evaluation, evidence, and verification layers
- materialized run artifacts and persisted run reports
- structured logging
- built-in programming and architecture packs
- CLI execution with optional approval artifacts
- smoke, contract, governance, and runtime matrix tests

It does **not** claim to be a finished autonomous programming system.

---

## What BlackFox Is

BlackFox is being built as:

- one kernel
- many internal specialist packs
- one controlled forge
- one explicit memory model
- one governance layer
- one verification path
- one audit surface

BlackFox is **not** being built as:

- a pile of loosely related repos
- a fake swarm of endpoints
- a generic chatbot with hidden behavior
- theatrical autonomy with no proof burden
- uncontrolled self-modification

---

## What Changed in This Evolved Form

Earlier BlackFox already had strong structure:

- typed tasks
- deterministic routing
- pack execution
- sentinel checks
- evaluation
- verification
- persisted reports

This evolved form adds the missing control boundary.

BlackFox now explicitly models:

- **what action is being proposed**
- **what risk that action has**
- **what policy decided**
- **whether review is required**
- **whether approval was satisfied**
- **whether execution happened**
- **what receipt chain proves the path**

That is the shift from:

**auditable planning runtime**

to:

**governed execution runtime**

---

## Core Runtime Contract

A BlackFox run is governed only when it satisfies the following chain:

1. request intake becomes a typed task
2. a route is selected explicitly
3. governance preflight creates an action intent
4. risk is classified
5. policy decides allow, require review, or block
6. approval is resolved when required
7. receipts record the governance path
8. execution only happens when governance allows it
9. verification checks both output quality and governance integrity
10. the run report and receipt artifact are persisted

If that chain is incomplete, the run may still exist, but it should not be described as full governed execution.

---

## Core Subsystems

### `config/`
Typed runtime configuration and path normalization.

### `kernel/`
Lifecycle control, typed tasks, and shared coordination state.

### `bus/`
Typed internal events for subsystem coordination.

### `switchboard/`
Deterministic capability routing.

### `packs/`
Internal specialist packs loaded through manifests and stable execution contracts.

### `memory/`
Tiered memory:

- working
- episodic
- semantic
- artifact
- trace

### `vault/`
Integrity sealing, provenance chains, and integrity-checked persisted state.

### `governance/`
Normalized action intents, risk models, policy decisions, approvals, and chained receipts.

### `sentinel/`
Runtime conscience for contradiction checks, failure-loop detection, policy guardrails, and governance consistency checks.

### `forge/`
Controlled programming workbench for:

- workspace isolation
- file graph scanning
- static Python analysis
- patch planning
- governed patch-intent bridging
- command execution
- governed command execution
- test running
- regression collection
- forge execution tickets

### `eval/`
Evaluation, evidence capture, regression-aware verification, governance-signal verification, and output verification.

### `observability/`
Append-only JSONL structured logging.

### `runtime/`
End-to-end execution spine that fuses inference, replay observation, routing, governance preflight, approval resolution, receipt capture, pack execution, sentinel checks, evaluation, verification, artifact persistence, provenance, and vault-backed run state.

### `interface/`
CLI entrypoint layer.

---

## Built-In Packs

### Programming Pack

Current behavior:

- inspects programming-oriented prompts
- produces deterministic action steps
- records pack execution state
- emits pack events
- returns structured planning output

Current scope is intentionally bounded.  
It does **not** pretend to autonomously repair arbitrary code without the forge path being invoked explicitly.

### Architecture Pack

Current behavior:

- inspects architecture-oriented prompts
- produces deterministic architecture decisions
- records pack execution state
- emits pack events
- returns structured design output

Current scope is intentionally bounded.  
It does **not** claim to generate full architecture proof or implementation automatically.

---

## Governance Model

BlackFox uses three canonical governance decisions.

### `allow`
The runtime may proceed without explicit approval.

### `require_review`
The runtime may not proceed until approval is satisfied.

### `block`
The runtime must not execute the action.

Governance currently operates across both runtime and forge-facing behavior through:

- action intent modeling
- risk classification
- deterministic policy decisions
- approval requests and decisions
- persisted approval state
- execution tickets
- chained receipts
- governance-aware verification

---

## Approval Model

When a run requires review, approval artifacts are normalized into explicit approval state.

BlackFox currently supports these approval outcomes:

- `pending`
- `approved`
- `rejected`
- `canceled`

A review-gated action is considered satisfied only when:

- approval is required
- the approval targets the governed intent
- at least one approval state is terminally `approved`

Approval does **not** rescue blocked actions.  
Approval only resolves review-gated paths.

---

## Receipt Chain Model

Receipts are not generic logs.

They are chained execution-state records that document:

- governance preflight result
- approval resolution result
- execution start
- execution completion or failure
- verification result

For governed runtime paths, BlackFox persists a standard governance receipt artifact:

- `blackfox-governance-receipts.json`

That artifact is chain-verified before trust is finalized.

---

## Runtime Statuses

BlackFox exposes three final runtime statuses.

### `passed`
The run completed without blocking verification issues.

### `needs_review`
The run is not trusted enough to pass yet.  
Typical reasons include pending approval or review-level issues.

### `failed`
The run hit a blocking trust boundary.  
Typical reasons include no route, governance block, execution failure, or verification failure.

---

## Current Safety Posture

BlackFox currently emphasizes:

- explicit boundaries
- deterministic internal contracts
- no shell-based command execution
- workspace path containment
- policy observation checks
- governance preflight before execution
- approval-aware review gates
- receipt-chain auditability
- provenance and integrity tracking
- evaluation and verification before trust

BlackFox currently does **not** claim:

- hidden autonomy
- destructive host mutation by default
- magical reasoning
- complete confidentiality guarantees in vault storage
- finished production readiness
- unrestricted self-improving behavior

---

## Quick Start

### Requirements

- Python **3.11+**

### Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run tests
```bash
pytest
```

Run one programming task through the runtime
```bash
blackfox run --prompt "Fix the failing tests and patch the code." --kind programming
```

Emit the full run report as JSON
```bash
blackfox run \
  --prompt "Fix the failing tests and patch the code." \
  --kind programming \
  --json
```

Run a review-gated task with an approval artifact
```bash
blackfox run \
  --prompt "Delete workspace traces and remove source file references after planning." \
  --kind programming \
  --label code \
  --label patching \
  --approval-file approvals.json
```

Example approval file shape:
```bash
[
  {
    "status": "approved",
    "requested_by": "maintainer.one",
    "decided_by": "maintainer.one",
    "note": "Approved controlled review-gated runtime execution.",
    "evidence_refs": ["tickets/BF-42", "reviews/BF-42.txt"]
  }
]
```

Example Governed Runtime Flow

The intended shape of a governed runtime flow is:

create or infer a typed task
observe replay status for the normalized task shape
route it through the switchboard
run governance preflight
resolve approval if review is required
emit governance receipts
load and execute the selected pack only if governance allows it
run sentinel checks over the resulting trace window and governance observations
evaluate and verify the run outcome
materialize artifacts, run report, governance receipt report, provenance, and sealed run state
write structured logs
Repository Layout

src/ix_blackfox/
├── bus/
├── config/
├── eval/
├── forge/
├── governance/
├── interface/
├── kernel/
├── memory/
├── observability/
├── packs/
│   ├── architecture/
│   └── programming/
├── runtime/
├── sentinel/
├── switchboard/
├── vault/
└── exceptions.py

tests/
docs/

Key Documents
docs/system-architecture.md — full system architecture and subsystem responsibilities
docs/governed-execution-contract.md — runtime contract for governed execution
docs/fusion-audit.md — architecture and subsystem fusion analysis
What Is Real Right Now

This repository already includes tested implementations for:

runtime config loading
kernel lifecycle
deterministic task classification for unknown intake
replay-aware task observation
task models
shared state
event envelopes and dispatch
capability manifests and routing
pack loading and execution contracts
end-to-end runtime orchestration
working / episodic / semantic / artifact / trace memory
persisted artifact and run-report materialization
governance preflight and approval resolution
governance receipt persistence and chain verification
sentinel governance consistency checks
provenance and sealed run-state persistence
CLI execution paths including approval-file input
governed execution matrix tests
What This Repo Is Trying to Prove

The architectural thesis of BlackFox is:

intelligence should behave like a controlled operating runtime, not like a floating text box.

In BlackFox, that means:

explicit tasks
explicit routing
explicit governance
explicit approval boundaries
explicit execution tickets
explicit receipt chains
explicit evaluation
explicit verification
explicit audit trails

That is the current form of the repo.

It is not finished.

But it is now materially stronger, more honest, and more useful than a planning-only runtime.
