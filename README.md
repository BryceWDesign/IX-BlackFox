<p align="center">
  <img src="IX-BlackFox-Logo.png" alt="IX-BlackFox Logo">
</p>

# IX-BlackFox

IX-BlackFox is a programming-first intelligence runtime built as **one sovereign codebase**.

It is designed around a simple idea:

**intelligence should behave like a controlled operating runtime, not like a floating text box.**

That means BlackFox is being built around:

- explicit task structures
- deterministic internal routing
- tiered memory
- controlled forge execution
- structured evaluation
- auditable traces, evidence, and logs
- policy-aware runtime safety

## Status

This repository is currently a **foundation runtime**.

It already contains working core scaffolding for:

- kernel lifecycle and typed tasks
- deterministic task-kind inference for unknown intake
- internal event bus
- shared state
- capability routing
- manifest-driven pack loading
- end-to-end runtime orchestration
- replay-aware intake observation
- tiered memory
- vault integrity and provenance
- sentinel checks
- forge workspace, analysis, command, test, and regression tooling
- evaluation, evidence, and verification layers
- materialized run artifacts and persisted run reports
- structured logging
- built-in programming and architecture packs
- smoke and contract tests

It does **not** yet claim to be a finished autonomous programming system.

## Design Intent

BlackFox is not being built as:

- a pile of loosely related repos
- a fake swarm of endpoints
- a keyword-router demo
- a generic chatbot with hidden behavior

BlackFox is being built as:

- one kernel
- many internal specialist packs
- one controlled forge
- one explicit memory model
- one verification path
- one audit surface

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

### `sentinel/`
Runtime conscience for contradiction checks, failure-loop detection, and policy guardrails.

### `forge/`
Controlled programming workbench for:

- workspace isolation
- file graph scanning
- static Python analysis
- patch planning
- command execution
- test running
- regression collection

### `eval/`
Evaluation, benchmark schemas, evidence capture, and output verification.

### `observability/`
Append-only JSONL structured logging.

### `runtime/`
End-to-end execution spine that fuses inference, replay observation, routing, pack execution, sentinel checks, evaluation, verification, artifact persistence, provenance, and vault-backed run state.

### `interface/`
CLI entrypoint layer.

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

## Current Safety Posture

BlackFox currently emphasizes:

- explicit boundaries
- deterministic internal contracts
- no shell-based command execution
- workspace path containment
- policy observation checks
- provenance and integrity tracking
- evaluation before trust

BlackFox currently does **not** claim:

- hidden autonomy
- destructive host mutation by default
- magical reasoning
- complete confidentiality guarantees in vault storage
- finished production readiness

## Quick Start

### Requirements

- Python **3.11+**

### Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Run tests

```bash
pytest
```

### Run one programming task through the real runtime

```bash
blackfox run --prompt "Fix the failing tests and patch the code." --kind programming
```

### Emit the full run report as JSON

```bash
blackfox run \
  --prompt "Fix the failing tests and patch the code." \
  --kind programming \
  --json
```

## Example Runtime Flow

The current intended shape of a normal programming-oriented flow is:

1. create or infer a typed task
2. observe replay status for the normalized task shape
3. route it through the switchboard
4. load the selected pack
5. execute the pack under pack context
6. run sentinel checks over the resulting trace window
7. evaluate and verify the run outcome
8. materialize artifacts, report, provenance, and sealed run state
9. write structured logs

## Repository Layout

```text
src/ix_blackfox/
├── bus/
├── config/
├── eval/
├── forge/
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
```

## What Is Real Right Now

This repository already includes real tested implementations for:

- runtime config loading
- kernel lifecycle
- deterministic task classification for unknown intake
- replay-aware task observation
- task models
- shared state
- event envelopes and dispatch
- capability manifests and routing
- pack loading and execution contracts
- end-to-end runtime orchestration
- working / episodic / semantic / artifact / trace memory
- persisted artifact and run-report materialization
- provenance and sealed run-state persistence
- CLI execution through the actual runtime
- integrity sealing
- provenance chain verification
- disk-backed integrity-checked state
- contradiction / failure-loop / policy sentinel checks
- forge workspace isolation
- file graph scanning
- static Python AST analysis
- patch-plan generation
- command execution
- pytest-based test running
- JUnit regression collection
- rule-based evaluation
- benchmark suite models
- evidence recording
- output verification
- structured JSONL logging

## What Still Comes Next

The current foundation leaves room for later work such as:

- deeper kernel scheduling
- richer pack orchestration
- stronger memory promotion rules
- patch execution loops
- more built-in packs
- richer benchmark suites
- broader language support in forge analysis
- stronger operator interfaces
- model-backed semantic routing layers

## Philosophy

BlackFox is measurement-first and structure-first.

The standard is:

- explicit contracts over vague behavior
- verification over assumption
- auditability over mystery
- bounded claims over inflated claims

## License

Apache 2.0
