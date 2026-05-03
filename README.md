<p align="center">
  <img src="IX-BlackFox-Logo.png" alt="IX-BlackFox Logo">
</p>

# IX-BlackFox

IX-BlackFox is a governed AI engineering control-plane project.

The goal is not to build an uncontrolled “AI writes code and deploys itself” system. The goal is a bounded, auditable engineering runtime that can propose repairs, compile them into governed patch candidates, route them through policy gates, execute them through a controlled patch-test-verify loop, preserve receipts, and make the result reviewable.

Wave 3 adds governed patch authoring and repair intelligence on top of the existing Wave 2 patch-test-verify control plane.

## Current position

IX-BlackFox is now structured around three implemented layers:

| Wave | Meaning | Current role |
|---|---|---|
| Wave 1 | Governed multi-brain runtime scaffold | Base runtime, reasoning lanes, governance preflight, readiness, replay, and operator-facing structure |
| Wave 2 | Governed local patch-test-verify control plane | Controlled patch application, test execution, receipts, verification summaries, and run bundles |
| Wave 3 | Governed patch authoring and repair intelligence | Structured repair proposal generation, parsing, compilation, policy gating, ranking, Wave 2 handoff, acceptance validation, CLI, and evidence packaging |

Wave 3 does not replace Wave 2. Wave 3 creates selected `PatchDiff` candidates. Wave 2 remains the execution authority.

## What Wave 3 adds

Wave 3 introduces the authored-repair path:

1. Build bounded repository context.
2. Extract or normalize failure evidence.
3. Decompose the repair objective into bounded subtasks.
4. Generate deterministic repair hypotheses.
5. Render a strict model-side patch-authoring prompt contract.
6. Accept raw proposal JSON from a provider or manual import.
7. Parse the proposal as hostile input.
8. Reject malformed, unsafe, command-like, or path-escaping responses.
9. Compile valid proposal mutations into governed `PatchDiff` candidates.
10. Run authoring policy gates before execution.
11. Rank candidate patches deterministically.
12. Select at most one candidate for Wave 2.
13. Preserve authoring receipts.
14. Execute selected candidates only through Wave 2.
15. Validate Wave 3 acceptance after Wave 2 execution.
16. Package Wave 3 evidence for review.

## What Wave 3 does not do

IX-BlackFox Wave 3 does not:

- silently edit files outside the governed patch path
- run tests from the authoring layer
- approve its own review
- bypass policy
- weaken tests to force success
- claim deployment readiness
- claim that a repair is proven without Wave 2 evidence
- call a remote model by default
- remove human authority from high-consequence engineering decisions

The current Wave 3 implementation supports manual/static proposal import and provider-interface wiring. A production model provider can be added later, but the trust boundary is already explicit: model output is untrusted input.

## Core trust boundary

The most important design rule is:

> Wave 3 may propose. Wave 2 must execute. Acceptance must verify. Humans retain authority.

That means an authored repair is not accepted merely because a model produced JSON. It must survive parsing, compilation, policy, candidate selection, Wave 2 execution, and Wave 3 acceptance validation.

## Repository layout

Important runtime and authoring modules include:

| Path | Purpose |
|---|---|
| `src/ix_blackfox/authoring/models.py` | Core authoring models: requests, objectives, evidence, context, findings, subtasks |
| `src/ix_blackfox/authoring/context.py` | Bounded repository context collection |
| `src/ix_blackfox/authoring/failure_evidence.py` | Failure evidence extraction from pytest output or objective-only reports |
| `src/ix_blackfox/authoring/decomposition.py` | Deterministic task decomposition |
| `src/ix_blackfox/authoring/hypotheses.py` | Repair hypothesis generation |
| `src/ix_blackfox/authoring/prompt_contract.py` | Strict model-side patch-authoring contract |
| `src/ix_blackfox/authoring/response_parser.py` | Strict parser for untrusted model proposal JSON |
| `src/ix_blackfox/authoring/patch_compiler.py` | Proposal-to-`PatchDiff` compiler |
| `src/ix_blackfox/authoring/policy.py` | Authoring policy gate |
| `src/ix_blackfox/authoring/receipts.py` | Wave 3 authoring receipt ledger |
| `src/ix_blackfox/authoring/candidates.py` | Candidate scoring, ranking, and selection |
| `src/ix_blackfox/runtime/authoring_repair.py` | Wave 3 authored repair runtime |
| `src/ix_blackfox/runtime/control_plane.py` | Wave 2 control plane plus Wave 3 handoff integration |
| `src/ix_blackfox/runtime/wave3_acceptance.py` | Wave 3 acceptance validator |
| `src/ix_blackfox/runtime/wave3_cli.py` | Manual Wave 3 CLI entrypoint |
| `src/ix_blackfox/runtime/wave3_bundle.py` | Wave 3 evidence package writer |

## Wave 3 proposal schema

Wave 3 proposals are JSON only. Markdown-wrapped JSON is rejected by default.

A proposal must include:

- `schema_version`
- `proposal_id`
- `objective_summary`
- `reasoning_summary`
- `confidence`
- `assumptions`
- `risk_notes`
- `expected_tests`
- `mutations`

Supported mutation types:

| Mutation type | Meaning |
|---|---|
| `replace_text` | Replace exact text in an existing file |
| `create_file` | Create a new file with supplied text |

Example proposal:

~~~
{
  "schema_version": "wave3.patch_authoring_response.v1",
  "proposal_id": "proposal-1",
  "objective_summary": "Repair the failing addition behavior.",
  "reasoning_summary": "The proposed source change aligns with the failing assertion evidence.",
  "confidence": 0.72,
  "assumptions": [
    "The compiler must verify before_text against the current workspace."
  ],
  "risk_notes": [
    "The patch must still pass policy and Wave 2 execution."
  ],
  "expected_tests": [
    "The targeted behavior test should pass after governed execution."
  ],
  "mutations": [
    {
      "mutation_id": "mutation-1",
      "mutation_type": "replace_text",
      "path": "src/example.py",
      "before_text": "return a - b",
      "after_text": "return a + b",
      "rationale": "The failing assertion expects addition behavior."
    }
  ]
}
~~~

## Parser restrictions

The parser treats model output as hostile input.

It rejects:

- empty responses
- malformed JSON
- markdown-wrapped JSON
- unknown top-level fields
- unknown mutation fields
- unsafe paths
- absolute paths
- drive-prefixed paths
- path traversal
- hidden root paths such as `.env`
- shell-command-like text
- network/download instructions
- success claims such as “all tests passed”
- no-op replacements
- duplicate mutation IDs
- duplicate create-file paths
- invalid confidence values

## Compiler behavior

The compiler converts a validated `PatchAuthoringProposal` into a Wave 2 `PatchDiff`.

For `replace_text`, it:

1. Resolves the target path through the workspace path policy.
2. Reads the current workspace file.
3. Verifies that `before_text` is present.
4. Rejects stale `before_text`.
5. Rejects ambiguous replacements by default.
6. Expands the mutation into a whole-file `PatchFileChange`.
7. Validates the resulting patch diff.

For `create_file`, it:

1. Resolves the target path through policy.
2. Rejects overwrite attempts.
3. Rejects empty file content.
4. Compiles the mutation into a `PatchFileChange.add`.

## Authoring policy gate

The policy gate can allow, require review, or block a proposal.

It blocks high-risk cases such as:

- secret-like paths
- blocked roots
- path traversal
- unsafe command or dynamic-execution content
- delete-like mutation language

It requires review for cases such as:

- test mutation
- possible test weakening
- governance-sensitive paths
- acceptance logic
- receipt logic
- dependency or build configuration
- CI workflow files
- executable scripts
- create-file mutations
- weak or missing evidence
- low-confidence proposals
- large patches

Low-risk source patches with direct evidence can be allowed.

## Candidate ranking

Wave 3 ranks compiled candidates using deterministic scoring.

Scoring considers:

- proposal confidence
- policy decision
- evidence strength
- path risk
- patch size
- selected hypothesis alignment
- review penalties
- blocked penalties
- duplicate patch digests

Only one candidate can be selected. Lower-ranked available candidates are preserved as not selected.

## Authoring receipts

Wave 3 records an authoring receipt chain for review.

Receipt events include:

- context collected
- evidence extracted
- decomposition created
- hypotheses generated
- prompt contract rendered
- model response received
- response parsed
- proposal validated
- patch compiled
- policy decided
- candidate selected
- candidate rejected
- authoring failed

Each receipt includes a payload digest and chain digest. The chain is intended to make the authoring path reviewable and tamper-evident enough for local engineering workflow evidence. It is not a replacement for external signing infrastructure.

## Wave 3 acceptance

Wave 3 acceptance validates that the authored repair path and Wave 2 execution path line up.

Acceptance checks include:

- authored repair report exists
- receipt chain is valid
- required authoring events are present
- selected candidate exists
- selected patch exists
- selection report exists
- selected candidate has an allow policy report
- Wave 2 report exists
- Wave 2 executed
- Wave 2 succeeded
- Wave 2 metadata references the selected Wave 3 patch
- Wave 2 metadata references the authoring chain digest
- Wave 2 metadata references the authoring receipt count

Acceptance statuses:

| Status | Meaning |
|---|---|
| `passed` | Authoring, policy, receipts, selected patch, and Wave 2 success aligned |
| `failed` | Required evidence or alignment failed |
| `blocked` | Authoring was blocked |
| `requires_review` | Authoring requires review |
| `not_executed` | No selected candidate reached Wave 2 execution |

## Wave 3 evidence package

The Wave 3 evidence package writer persists:

- authored engineering report
- authoring receipts
- Wave 3 acceptance report
- Wave 2 engineering report, when present
- Wave 3 evidence index
- Wave 3 evidence package manifest

This package is separate from the Wave 2 run bundle. It exists so the authored layer can be reviewed alongside the execution layer.

## Manual CLI usage

The Wave 3 CLI is intended for manual proposal import and controlled local runs.

Example:

~~~
python -m ix_blackfox.runtime.wave3_cli \
  --workspace-root . \
  --artifact-root . \
  --task-id task-add \
  --run-id run-add \
  --objective "Repair addition behavior." \
  --include-path src \
  --include-path tests \
  --proposal-file proposal.json \
  --raw-test-output-file pytest-output.txt \
  --test-command python -m pytest -q tests
~~~

Exit codes:

| Exit code | Meaning |
|---:|---|
| `0` | Wave 3 acceptance passed |
| `1` | Wave 3 acceptance failed |
| `2` | CLI input error |
| `10` | Review required |
| `20` | Blocked |

## Programmatic usage

Example manual/static Wave 3 run through the control plane:

~~~
from pathlib import Path

from ix_blackfox.runtime.control_plane import EngineeringControlPlane
from ix_blackfox.runtime.authoring_repair import StaticPatchProposalProvider
from ix_blackfox.runtime.wave3_acceptance import Wave3AcceptanceValidator

proposal_json = """
{
  "schema_version": "wave3.patch_authoring_response.v1",
  "proposal_id": "proposal-1",
  "objective_summary": "Repair file content.",
  "reasoning_summary": "The proposed source change aligns with the failure evidence.",
  "confidence": 0.72,
  "assumptions": ["The compiler must verify before_text."],
  "risk_notes": ["The patch must still pass policy and Wave 2 execution."],
  "expected_tests": ["The targeted behavior test should pass after governed execution."],
  "mutations": [
    {
      "mutation_id": "mutation-1",
      "mutation_type": "replace_text",
      "path": "src/example.py",
      "before_text": "before",
      "after_text": "after\\n",
      "rationale": "Repair source behavior."
    }
  ]
}
"""

control_plane = EngineeringControlPlane.from_workspace(
    workspace_root=Path("."),
    artifact_root=Path("."),
    test_command=("python", "-m", "pytest", "-q", "tests"),
)

report = control_plane.run_authored_programming_repair(
    task_id="task-example",
    run_id="run-example",
    objective="Repair file content.",
    include_paths=("src", "tests"),
    proposal_provider=StaticPatchProposalProvider(responses=(proposal_json,)),
    raw_test_output="FAILED tests/test_example.py::test_example",
    authoring_test_return_code=1,
)

acceptance = Wave3AcceptanceValidator().validate(report)
print(acceptance.status.value)
~~~

## Workspace requirements

By default, the control plane requires a workspace marker:

~~~
.blackfox-workspace
~~~

This is intentional. IX-BlackFox is designed to run in an explicitly reserved workspace, not in arbitrary directories by accident.

## Policy file

If present, the control plane loads:

~~~
blackfox.policy.toml
~~~

The policy document controls path boundaries and repair-loop behavior. If no policy file is present, the system falls back to the default policy document.

## Testing

From the repository root:

~~~
python -m pytest
~~~

To run only Wave 3 related tests:

~~~
python -m pytest tests/authoring tests/runtime/test_authoring_repair.py tests/runtime/test_control_plane_wave3.py tests/runtime/test_wave3_acceptance.py tests/runtime/test_wave3_cli.py tests/runtime/test_wave3_bundle.py
~~~

## Current Wave 3 limitations

Wave 3 is now structurally present, but it is not the final form of IX-BlackFox.

Known boundaries:

- No production remote model provider is committed by default.
- The CLI uses manual/static proposal JSON import.
- The policy gate is intentionally conservative.
- Acceptance validates local evidence, not external certification.
- Receipt chaining is local evidence integrity, not cryptographic signing infrastructure.
- Human review is still required for governance-sensitive or high-risk mutations.
- Generated proposals are not trusted until they pass parsing, policy, compilation, ranking, Wave 2, and acceptance.

## Canonical roadmap

The locked IX-BlackFox roadmap is:

| Wave | Locked meaning |
|---:|---|
| 1 | Governed multi-brain runtime scaffold |
| 2 | Governed local patch-test-verify control plane |
| 3 | Governed patch authoring and repair intelligence |
| 4 | Reliability lab with scenario suites, adversarial tests, and repair metrics |
| 5 | Organization-grade workflow with PR evidence packs, approvals, and CI integration |
| 6 | Hardened sandbox execution layer with isolated workspaces, signed artifacts, and egress controls |
| 7 | Model-agnostic repair intelligence with model comparison, routing, budget controls, and provider abstraction |
| 8 | Repository intelligence layer with code graph, dependency mapping, impact analysis, and architectural memory |
| 9 | Compliance/audit attestation layer with policy packs, evidence standards, reviewer signoff, and governance reports |
| 10 | Full AI engineering operating system: multi-repo, multi-team, policy-governed, measurable, replayable, and reviewable |

Future extensions may continue beyond Wave 10 only if they add testable, useful, bounded, auditable capability.

A clean extended direction is:

| Wave | Possible extension |
|---:|---|
| 11 | Cross-program learning without data leakage |
| 12 | Certification-ready evidence packaging |
| 13 | Human-machine review board |
| 14 | Constraint-aware mission/factory optimizer |
| 15 | Governed engineering autonomy layer |
| 16 | Digital engineering mesh |
| 17 | Assurance-grade model governance |
| 18 | Program-scale resilience command layer |
| 19 | Closed-loop verification ecosystem |
| 20 | High-consequence engineering intelligence fabric |

Wave 20 is not “AI takes over engineering.” The correct endpoint is a governed, auditable, multi-domain engineering intelligence fabric that proposes, tests, compares, documents, routes, reviews, learns, and recommends while preserving human command authority.

## Engineering principle

IX-BlackFox evolves through controlled engineering optimization, not uncontrolled mutation.

Every serious capability should be:

- bounded
- testable
- auditable
- reversible
- policy-gated
- evidence-producing
- human-reviewable
- honest about uncertainty

That is the spine of the project.

## License

Apache License 2.0.

See `LICENSE` for the full license text.
