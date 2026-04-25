<p align="center">
  <img src="IX-BlackFox-Logo.png" alt="IX-BlackFox Logo">
</p>

# IX-BlackFox

**IX-BlackFox is a governed AI engineering control plane proof-of-concept.**

It is not a chatbot wrapper.  
It is not an autonomous swarm.  
It is not a claim of magic AI coding.

BlackFox is built around one hard rule:

> AI-generated engineering work should not be trusted until it can be routed, gated, executed, tested, verified, receipted, packaged, and reviewed.

Wave 2 upgrades BlackFox from a governed multi-brain runtime scaffold into a controlled local engineering runtime that can apply explicit patch candidates, run allowlisted tests, parse test evidence, produce receipt chains, generate operator summaries, produce verification summaries, and package reviewable run bundles.

---

## What BlackFox Does

BlackFox provides a controlled runtime path for engineering work:

1. Receive an explicit task objective.
2. Accept one or more explicit `PatchDiff` candidates.
3. Apply patches only inside a reserved workspace.
4. Enforce workspace path policy.
5. Run allowlisted local test commands.
6. Parse pytest output into structured evidence.
7. Record tool invocation receipts.
8. Record repair-loop decision receipts.
9. Generate an operator-readable summary.
10. Generate a machine-readable verification summary.
11. Package the run into a reviewable artifact bundle.
12. Validate the bundle against Wave 2 acceptance criteria.

The core idea is simple:

> Intelligence should behave like a controlled operating runtime, not like a floating text box.

---

## What BlackFox Is Not

BlackFox does **not** currently claim:

- autonomous patch generation
- autonomous repo refactoring without explicit patch candidates
- production sandbox isolation
- remote execution security
- cloud orchestration
- formal verification
- global code correctness
- permission to mutate arbitrary directories
- permission to access secrets
- permission to access networks by default
- flight, medical, financial, legal, or safety-critical readiness

The Wave 2 runtime verifies only the captured objective, patch candidates, workspace state, policy configuration, test command, receipts, and artifacts for a specific run.

---

## Wave 2 Architecture

Wave 2 adds a governed engineering control plane around the original runtime.

Major components:

- `PatchDiff` and `PatchFileChange`
- `PatchApplyTool`
- `WorkspaceFileReadTool`
- `WorkspaceDirectoryListTool`
- `TestRunnerTool`
- `PytestTextResultParser`
- `RepairLoopState`
- `ProgrammingRepairRuntime`
- `RepairLoopReceiptLedger`
- `ToolInvocationReceiptLedger`
- `RunBundleWriter`
- `RunBundleExporter`
- `OperatorSummaryRenderer`
- `VerificationSummaryRenderer`
- `EngineeringControlPlane`
- `Wave2AcceptanceValidator`

Together, these form the control path:

```
explicit patch candidate
        |
        v
governed patch tool
        |
        v
allowlisted test runner
        |
        v
pytest result parser
        |
        v
repair-loop state machine
        |
        v
tool receipts + repair receipts
        |
        v
operator summary + verification summary
        |
        v
run bundle
        |
        v
Wave 2 acceptance validation
```

---

## Repository Safety Model

BlackFox uses several local safety boundaries.

### Reserved Workspace Marker

Patch and test execution require a reserved workspace marker by default:

```
.blackfox-workspace
```

This prevents the control plane from silently mutating an arbitrary folder passed by mistake.

### Path Policy

Workspace tools reject:

- absolute paths unless explicitly allowed
- path traversal outside the workspace
- blocked roots such as `.git`, `.env`, `.ssh`, `secrets`, and `credentials`
- paths outside configured allowed roots

Default policy lives in:

```
blackfox.policy.toml
```

### No Shell Execution

The test runner uses argv-style subprocess execution with `shell=False`.

Commands must be passed as lists, not shell strings.

Example:

```
python -m pytest -q
```

Not:

```
python -m pytest -q && rm -rf something
```

### Approval-Oriented Policy

The policy file distinguishes between:

- allowed execution
- blocked execution
- review-required execution

Workspace writes and process execution are review-sensitive by default.

---

## Policy File

Default policy file:

```
blackfox.policy.toml
```

Example policy shape:

```toml
[execution]
allow_file_read = true
allow_file_write = true
allow_process_execution = true
allow_network = false
allow_system_mutation = false
allow_absolute_paths = false
max_repair_attempts = 3
max_tool_timeout_seconds = 900

[approval]
require_for_delete = true
require_for_network = true
require_for_secret_access = true
require_for_workspace_write = true
require_for_process_execution = true
review_high_risk = true
block_critical_risk = true

[paths]
allowed_roots = [
  "src",
  "tests",
  "docs",
  "scripts",
  "examples",
  "artifacts",
]
blocked_roots = [
  ".git",
  ".env",
  ".ssh",
  "secrets",
  "credentials",
  "__pycache__",
  ".pytest_cache",
  ".mypy_cache",
  ".ruff_cache",
  "dist",
  "build",
]
allow_absolute_paths = false
```

---

## Core Runtime Modules

### Tools

```
src/ix_blackfox/tools/
```

Important modules:

```
contracts.py
manifest.py
policy.py
policy_file.py
gateway.py
risk.py
receipts.py
artifacts.py
workspace.py
patch.py
patch_apply.py
test_runner.py
test_results.py
```

### Runtime

```
src/ix_blackfox/runtime/
```

Important Wave 2 modules:

```
repair_loop.py
programming_repair.py
repair_receipts.py
run_bundle.py
run_bundle_export.py
operator_summary.py
verification_summary.py
control_plane.py
control_plane_cli.py
acceptance.py
```

---

## Basic Verification

From the repository root, run:

```bash
python -m pytest -q
```

For stricter local checking, run the full test directory:

```bash
python -m pytest tests -q
```

I cannot honestly claim your local checkout is green until you run the tests in your environment after uploading every commit. The expected verification path is the pytest suite included in the repo.

---

## Running the Engineering Control Plane from Python

A minimal local example looks like this:

```python
from pathlib import Path

from ix_blackfox.runtime import EngineeringControlPlane
from ix_blackfox.tools import PatchDiff, PatchFileChange

workspace = Path(".").resolve()

patch = PatchDiff.create(
    summary="Repair a failing smoke test.",
    file_changes=(
        PatchFileChange.modify(
            path="tests/test_smoke.py",
            before_text="def test_smoke() -> None:\n    assert False\n",
            after_text="def test_smoke() -> None:\n    assert True\n",
        ),
    ),
    created_by="operator",
)

control_plane = EngineeringControlPlane.from_workspace(
    workspace_root=workspace,
    artifact_root=workspace,
    policy_path=workspace / "blackfox.policy.toml",
    test_command=("python", "-m", "pytest", "tests/test_smoke.py", "-q"),
)

report = control_plane.run_programming_repair(
    task_id="task-demo",
    run_id="run-demo",
    objective="Repair the failing smoke test and capture evidence.",
    candidate_patches=(patch,),
)

print(report.succeeded)
print(report.verification_status)
print(report.bundle_root)
```

The run writes a bundle under:

```
artifacts/runs/<run_id>/
```

---

## Running the Engineering Control Plane from CLI

The CLI adapter accepts explicit `PatchDiff` JSON files.

Example:

```bash
python -m ix_blackfox.runtime.control_plane_cli \
  --workspace-root . \
  --artifact-root . \
  --policy blackfox.policy.toml \
  --task-id task-demo \
  --run-id run-demo \
  --objective "Repair failing tests and capture evidence." \
  --patch patch.json \
  --test-command python -m pytest -q \
  --allowed-executable python \
  --output-json artifacts/run-demo-result.json
```

Optional bundle export:

```bash
python -m ix_blackfox.runtime.control_plane_cli \
  --workspace-root . \
  --artifact-root . \
  --policy blackfox.policy.toml \
  --task-id task-demo \
  --run-id run-demo \
  --objective "Repair failing tests and capture evidence." \
  --patch patch.json \
  --test-command python -m pytest -q \
  --allowed-executable python \
  --export \
  --export-dir exports \
  --export-name run-demo-review-pack
```

This produces a ZIP export such as:

```
exports/run-demo-review-pack.zip
```

---

## PatchDiff JSON Shape

Patch candidates are explicit before/after models.

Example JSON shape:

```json
{
  "patch_id": "patch-example",
  "summary": "Repair failing smoke test.",
  "created_by": "operator",
  "file_changes": [
    {
      "path": "tests/test_smoke.py",
      "change_kind": "modify",
      "before_text": "def test_smoke() -> None:\n    assert False\n",
      "after_text": "def test_smoke() -> None:\n    assert True\n",
      "metadata": {}
    }
  ],
  "metadata": {}
}
```

Patch operations support:

```
add
modify
delete
```

Deletes are flagged as review-sensitive.

---

## Run Bundle Layout

Each control-plane run writes a reviewable bundle:

```
artifacts/runs/<run_id>/
  manifest.json
  reports/
    programming-repair-report.json
    operator-summary.md
  verification/
    verification-summary.json
  receipts/
    tool-receipts.json
    repair-receipts.json
  traces/
    control-plane-trace.json
```

The manifest records artifact metadata:

- artifact kind
- relative path
- media type
- SHA-256 digest
- byte size
- creation timestamp
- metadata

The manifest itself has a digest binding the artifact inventory.

---

## Operator Summary

The operator summary is markdown intended for human review.

It answers:

- What was requested?
- What did BlackFox do?
- What changed?
- What evidence exists?
- What still needs human review?

Output path:

```
artifacts/runs/<run_id>/reports/operator-summary.md
```

---

## Verification Summary

The verification summary is JSON intended for machine review.

It records:

- verification status
- objective
- conclusion
- evidence items
- findings
- summary digest

Output path:

```
artifacts/runs/<run_id>/verification/verification-summary.json
```

Possible verification statuses:

```
verified
partial
failed
blocked
inconclusive
```

A run is marked `verified` only when the captured repair report reached a successful terminal state and the latest parsed test run passed.

---

## Acceptance Validation

Wave 2 includes an acceptance validator:

```python
from ix_blackfox.runtime import Wave2AcceptanceValidator

acceptance = Wave2AcceptanceValidator().validate_control_plane_report(
    report,
    check_filesystem=True,
)

print(acceptance.status)
print(acceptance.conclusion)
```

Acceptance checks include:

- successful repair loop
- verified status
- passing latest parsed test run
- minimum tool receipt count
- minimum repair receipt count
- required run-bundle artifact kinds
- unique artifact paths
- persisted artifact digests when filesystem checking is enabled

Acceptance statuses:

```
accepted
rejected
inconclusive
```

---

## Receipt Model

BlackFox records two kinds of receipts.

### Tool Receipts

Tool receipts record:

- policy evaluation
- invocation start
- invocation result
- emitted artifacts

These answer:

```
What tool was invoked, under what policy decision, with what result?
```

### Repair-Loop Receipts

Repair-loop receipts record:

- loop start
- attempt start
- patch result
- test result
- loop termination
- failure events

These answer:

```
Why did the repair loop continue, stop, pass, fail, or block?
```

Both receipt ledgers use chained digests for tamper-evident sequencing.

---

## Serious Use Boundaries

BlackFox is designed for local governed engineering experiments and audit-friendly AI-runtime research.

It is appropriate for:

- controlled proof-of-concept demos
- local patch/test experimentation
- AI governance runtime design
- receipt-chain and evidence-package research
- operator review workflows
- deterministic tool-policy testing

It is not appropriate for:

- unreviewed production mutation
- secret-bearing repositories without additional sandboxing
- arbitrary shell execution
- remote code execution
- sensitive infrastructure
- safety-critical deployment
- autonomous unattended repair of real systems

---

## Development Workflow

Recommended local loop:

```bash
python -m pytest tests/tools -q
python -m pytest tests/runtime -q
python -m pytest -q
```

Suggested manual review checklist:

```
1. Confirm .blackfox-workspace exists.
2. Confirm blackfox.policy.toml is present.
3. Confirm allowed_roots include only intended workspace areas.
4. Confirm blocked_roots include secrets and repository-control folders.
5. Confirm test command is argv-style and allowlisted.
6. Confirm patch candidates contain exact before_text and after_text.
7. Run pytest.
8. Inspect artifacts/runs/<run_id>/manifest.json.
9. Inspect operator-summary.md.
10. Inspect verification-summary.json.
11. Inspect tool and repair receipts.
12. Run Wave2AcceptanceValidator for final acceptance.
```

---

## Design Principle

BlackFox exists because AI engineering systems need more than fluent output.

They need:

- typed inputs
- explicit routing
- bounded tools
- policy gates
- approval points
- test evidence
- receipts
- traceable artifacts
- failure states
- reviewable summaries
- exportable evidence packs

The goal is not to make AI look autonomous.

The goal is to make AI engineering work inspectable enough that a serious reviewer can decide whether to trust, reject, or rerun it.

---

## License

Apache License 2.0.

See:

```
LICENSE
```

---

## Final Wave 2 State

Wave 2 turns IX-BlackFox into a governed AI engineering control plane proof-of-concept.

The important claim is narrow and defensible:

> BlackFox can coordinate explicit patch candidates through a bounded local patch-test-verify-package loop under policy, receipts, and operator review artifacts.

That is the line.

Anything beyond that needs more testing, stronger sandboxing, deeper policy enforcement, real model-side patch planning, and external security review before it should be trusted.
