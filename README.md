<p align="center">
  <img src="IX-BlackFox-Logo.png" alt="IX-BlackFox Logo">
</p>

# IX-BlackFox

**AI proposes. Humans decide. Evidence decides trust.**

IX-BlackFox is a source-available AI engineering control plane for governing
AI-assisted software-change workflows. It treats model output as untrusted input
and puts proposed actions behind scoped capabilities, policy gates, sandbox
boundaries, repository-impact analysis, content-addressed evidence, provenance,
independent verification, and separate human authority.

## Wave 14: Live Authority Gateway

Wave 14 puts BlackFox in the live request path between an AI agent and an
external tool. Configured MCP and HTTP API tool calls are intercepted **before**
the upstream receives them. Agent identity/scope authorization is combined with
cryptographically verified, repository/revision-bound evidence. Consequential
requests that require human review remain non-executable until a trusted,
policy-shaped human approval is present and, when configured, bound to the exact
action subject.

The Wave 14 rule is intentionally simple:

> **Capability is not authority. No configured consequential tool action reaches
> its upstream unless identity, scope, evidence, and required human authority
> agree.**

Wave 14 adds:

- a real network gateway at `/mcp` and `/v1/invoke`
- current MCP `2026-07-28` protocol/method/name and configured parameter-header
  body consistency checks, including exact protocol-version metadata binding
- agent-authenticated MCP pass-through plus fail-closed `Origin` validation when
  browser-originated MCP requests include an `Origin` header
- real pre-tool enforcement; denied calls are never forwarded upstream
- environment-backed per-agent ingress credentials, constant-time verified before
  an agent id can exercise its registered authority
- reuse of the Wave 11 registered-agent capability/scope engine
- per-route repository, path, risk, and evidence policies
- HMAC-SHA256 authenticated evidence from configured trusted issuers
- repository/revision evidence binding and freshness checks
- exact action-subject binding for non-replayable approval evidence
- a route-level human-approval condition that remains mandatory when configured
  and can satisfy an existing review gate without giving machines voting authority
- fixed-upstream HTTP forwarding only after the final authority decision is
  `allow`
- fixed-length request framing and bounded evidence-reference input before
  authority evaluation, reducing ambiguous framing and unbounded reference abuse
- SQLite-backed, transactionally hash-chained authority receipts
- live health/readiness plus operator-authenticated detailed status, receipt
  lookup, and receipt-chain verification endpoints
- a real local network integration proof that demonstrates unauthenticated,
  out-of-scope, and evidence-deficient calls produce zero upstream executions,
  then demonstrates approved MCP and API calls causing real upstream file writes

The complete Wave 14 contract and operator instructions are in
[`docs/wave14-live-authority-gateway.md`](docs/wave14-live-authority-gateway.md).

Run the end-to-end Wave 14 proof:

```bash
PYTHONPATH=src python scripts/run_wave14_live_gateway_ci.py --root .
```

Run a configured gateway:

```bash
blackfox gateway serve \
  --config examples/wave14/blackfox.gateway.toml \
  --print-status
```

The server entry point fails closed and will not bind a listener unless configured
credentials/evidence keys are loaded strongly enough and the receipt chain verifies.

Wave 14 includes a bounded static ingress-credential binding so a network caller
cannot simply self-assert another registered agent id. It deliberately does
**not** claim enterprise identity federation, OIDC/OAuth/IAM integration, HSM/KMS
signing, an external transparency log, production HA, compliance certification,
or deployment authorization. Those are separate boundaries rather than claims
hidden behind the word "gateway."

## Wave 13 foundation: Human-Machine Review Board

When an AI coding agent changes a real repository, can you prove what it was
allowed to touch, what changed, what evidence belongs to that exact revision,
what independent verification found, which specialists reviewed it, and whether
a human quorum actually authorized the next gate?

Wave 13 turns that question into an executable review-board contract above the
Wave 12 certification-ready evidence package. Machine analysis is visible, but
it has zero voting authority. Human approval is role-specific, revision-bound,
policy-bound, externally verified out of band, and independently rechecked from
the serialized package.

The locked default board requires seven distinct human roles:

- security
- QA
- systems
- safety
- operations
- manufacturing
- maintainer

Wave 13 adds:

- independent admission of a verified Wave 12 evidence package
- embedding of the exact Wave 12 ZIP inside the Wave 13 package
- nested Wave 12 reverification during independent Wave 13 verification
- non-authoritative machine advisories with `authoritative: false` and
  `vote_weight: 0`
- human reviews bound to the exact subject and board-policy digests
- separate identity and role-authority evidence references
- trusted out-of-band verification bound to the exact human-review digest
- distinct-human quorum and complete role-coverage enforcement
- subject-producer self-approval prevention
- conflict disclosure and recusal enforcement
- fail-closed reject and request-changes handling
- evidence challenges with blocking open state
- deterministic board evaluation, package construction, and bundle index
- a package-internal hash-chained review ledger
- independent semantic recomputation instead of trust in refreshed hashes
- `blackfox review-board build`, `verify`, and `gate` operator commands
- a dedicated offline Wave 13 CI evidence workflow

The full Wave 13 contract is documented in
[`docs/wave13-human-machine-review-board.md`](docs/wave13-human-machine-review-board.md).

## Wave 13 decision states

| State | Meaning |
| --- | --- |
| `blocked` | A binding, verification, policy, dissent, conflict, challenge, or integrity rule failed. |
| `human_review_required` | The machine/evidence path is coherent, but the required trusted human authority is incomplete. This is the expected offline CI state. |
| `approved_for_next_gate` | The configured human quorum, role coverage, and trusted review-verification rules are satisfied for the exact evidence package. This is not deployment, production, certification, or operational authorization. |

A serialized review cannot promote itself by claiming `externally_verified`.
IX-BlackFox is not an identity provider. Trusted verification must arrive through
an integration boundary and bind the reviewer identity, role, identity-evidence
digest, role-authority-evidence digest, and exact human-review digest. Changing
the decision or its bound content after verification invalidates that binding.

## What the Wave 13 verifier proves

The verifier reopens the package and checks:

- safe, unique ZIP paths and bounded expansion
- the exact embedded Wave 12 archive digest
- independent verification of the embedded Wave 12 archive
- reconstruction of the Wave 13 subject from that verified upstream package
- canonical review-case, advisory, review, challenge, evaluation, ledger, and
  bundle-index representations
- exact content digests for package entries
- machine zero-authority invariants
- human review subject and policy bindings
- external-verification context bindings to exact review digests
- role coverage, distinct-human quorum, conflict, recusal, and self-approval rules
- blocking reject, request-changes, and unresolved evidence-challenge states
- recomputed review-board disposition
- recomputed hash-chained ledger and package index
- rejection of unexpected package payloads

It does not trust self-consistent hashes alone. Corrupting the nested Wave 12
archive or changing a board disposition and refreshing outer hashes still fails
independent or semantic verification.

## Main Wave 13 modules

| Module | Responsibility |
| --- | --- |
| `review_board.models` | Review roles, subjects, policies, advisories, human reviews, external verification records, challenges, findings, and dispositions |
| `review_board.admission` | Independent Wave 12 verification and exact Wave 13 subject construction |
| `review_board.policy` | Zero-authority machine analysis and fail-closed human quorum evaluation |
| `review_board.package` | Deterministic case, ledger, index, embedded upstream archive, and ZIP construction |
| `review_board.parsing` | Strict reconstruction and canonicalization of serialized Wave 13 documents |
| `review_board.verify` | ZIP safety, nested Wave 12 verification, trust-context binding, ledger checks, and semantic recomputation |
| `review_board.cli` | Build, verify, and gate operator commands |

## Wave 13 package layout

A Wave 13 review-board package contains the bounded review surface plus the exact
upstream evidence archive:

```text
review-case.json
machine-advisories.json
human-reviews.json
evidence-challenges.json
board-evaluation.json
review-ledger.json
bundle-index.json
upstream/wave12-certification-ready-evidence.zip
```

The package builder uses canonical JSON, deterministic entry ordering, fixed ZIP
metadata, explicit content hashes, and a deterministic ledger.

## Wave 12 foundation

Wave 12 remains the evidence foundation directly beneath Wave 13. It collects
real prior-wave and quality evidence, maps it to a bounded assurance profile,
constructs a deterministic certification-ready evidence package, and reopens
that archive through an independent semantic verifier.

Here, **certification-ready** is deliberately narrow. It means the evidence is
scoped, revision bound, content addressed, mapped, checked for completeness,
packaged deterministically, and independently reverified. It does not mean the
repository, workflow, model, organization, or package is certified.

See
[`docs/wave12-certification-ready-evidence.md`](docs/wave12-certification-ready-evidence.md)
for the complete Wave 12 contract.

## Framework boundaries

The Wave 12 evidence profile includes bounded conceptual mappings to:

- NIST SP 800-218 SSDF 1.1
- NIST AI RMF 1.0
- NIST OSCAL Assessment Results
- SLSA 1.2
- in-toto Statement v1

These are mappings only. IX-BlackFox does not claim certification, a SLSA level,
conformant OSCAL output, accreditation, an ATO or cATO, or external endorsement.

## Install and test

IX-BlackFox requires Python 3.11 or newer. The primary CI matrix runs Python
3.11, 3.12, and 3.13.

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

Run the complete local quality suite:

```bash
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy src
.venv/bin/python -m pytest -q
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall -q src scripts tests
```

Run the focused Wave 13 campaign:

```bash
.venv/bin/python -m pytest \
  tests/review_board \
  tests/ci/test_wave13_review_board_runner.py \
  tests/ci/test_wave13_review_board_workflow_contract.py \
  tests/docs/test_wave13_review_board_docs.py \
  -q
```

Trust current local or GitHub Actions output, not a static README claim, as proof
that checks passed.

## Generate the offline Wave 13 evidence package

Wave 13 consumes a real Wave 12 package. Generate the upstream package first:

```bash
PYTHONPATH=src python scripts/run_wave12_assurance_ci.py \
  --root . \
  --head-sha 0123456789abcdef0123456789abcdef01234567 \
  --expected-status review_required
```

Then build and independently verify the Wave 13 board package:

```bash
PYTHONPATH=src python scripts/run_wave13_review_board_ci.py \
  --root . \
  --head-sha 0123456789abcdef0123456789abcdef01234567 \
  --expected-status human_review_required
```

The offline Wave 13 runner intentionally supplies zero human reviews and zero
trusted external-verification records. Its correct passing state is
`human_review_required`. CI proves that machine analysis cannot silently become
human authority; it does not manufacture an approval. Wave 14 then provides the
live enforcement layer that can consume separately trusted evidence before a
configured external action is allowed to execute.

The Wave 13 workflow is
`.github/workflows/wave13-human-machine-review-board.yml`.

## Operator CLI

Build a review-board package from an explicit Wave 12 package:

```bash
blackfox review-board build \
  --wave12-package .blackfox-artifacts/wave12/wave12-certification-ready-evidence.zip \
  --output .blackfox-artifacts/wave13/wave13-human-machine-review-board.zip
```

Independently verify a serialized Wave 13 package:

```bash
blackfox review-board verify \
  --package .blackfox-artifacts/wave13/wave13-human-machine-review-board.zip
```

Require the board to have reached the next human-authorized gate:

```bash
blackfox review-board gate \
  --package .blackfox-artifacts/wave13/wave13-human-machine-review-board.zip
```

The `review` command is an alias for `review-board`.

## What IX-BlackFox is not

IX-BlackFox is not:

- a replacement for human review or an external assessor
- an enterprise identity provider or OIDC/OAuth/IAM federation service
- a production high-availability MCP reverse proxy for every MCP method/stream
- a human identity-proofing service
- a qualified digital-signature service
- a production authorization or deployment authority
- a certified compliance product
- FedRAMP authorized
- an ATO or cATO issuer
- DoD approved or endorsed
- AWS approved or endorsed
- a transparency log
- a claim of formal verification or guaranteed software correctness
- an autonomous human-equivalent approval system

It is a platform-neutral, evidence-bound control plane and research prototype
for making AI-assisted engineering workflows more inspectable, reviewable,
identity bound, and governable. Wave 14 also provides a functioning live
MCP/HTTP pre-tool enforcement surface. Its evidence packages and authority
receipts can be consumed by CI, artifact storage, assessment, or cloud
integration layers without granting those layers implied approval.

## License and use

IX-BlackFox is source-available for technical evaluation under the repository
license.

Unless a separate written commercial license says otherwise, public visibility
does not grant permission for commercial use, production use, hosted service
use, contractor use, funded operational use, derivative operational use,
procurement use, or resale.

See [`LICENSE`](LICENSE) for the exact terms.

## Authorship

IX-BlackFox was originated and created by Bryce Lovell.

**AI proposes. Humans decide. Evidence decides trust.**
