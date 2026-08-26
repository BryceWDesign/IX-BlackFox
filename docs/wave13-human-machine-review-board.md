# Wave 13: Human-Machine Review Board

## Purpose

Wave 13 adds the next layer above Wave 12 certification-ready evidence packaging.
It consumes a Wave 12 ZIP that has already passed the independent Wave 12
verifier and turns that exact evidence package into a role-based review case.

The locked Wave 13 review roles are:

- security
- QA
- systems
- safety
- operations
- manufacturing
- maintainer

The default policy requires one qualifying approval for every role, seven
qualifying human approvals in total, and seven distinct human reviewer
identities. The policy object is serialized and digest-bound so a review cannot
silently move to a weaker policy after it is recorded.

Wave 13 does not replace Wave 12. The exact Wave 12 ZIP is embedded beneath
`upstream/` in the Wave 13 package and is independently verified again whenever
the Wave 13 package is verified.

## Governing rule

**Machine analysis is advisory. Human authority remains separate.**

A `MachineAdvisory` is serialized with:

- `authoritative: false`
- `vote_weight: 0`

The policy engine never includes machine advisories in human approval counts,
role coverage, or quorum. A package containing only machine advisories remains
`human_review_required`.

The built-in CI advisory is rule-based. It reports the actual result of the
independent Wave 12 package verification and the actual Wave 12 readiness state.
It does not call a model and it does not manufacture a human decision.

## Default board policy

`default_wave13_review_policy()` exposes the full-board default:

| Rule | Default |
| --- | --- |
| Supported roles | security, QA, systems, safety, operations, manufacturing, maintainer |
| Required roles | all seven |
| Minimum qualifying approvals | 7 |
| Distinct reviewers required | yes |
| External identity verification required | yes |
| Authenticated rejection blocks | yes |
| Authenticated request-changes blocks | yes |
| Open evidence challenge blocks | yes |
| Subject producer self-approval blocked | yes |
| Machine vote weight | 0 |

The implementation supports explicit `ReviewBoardPolicy` objects so future
integrations can define a narrower board when a governed policy actually calls
for one. The shipped default deliberately exercises the complete locked Wave 13
role set.

## Human review qualification

A human review can count toward role coverage and quorum only when all of these
conditions hold:

1. the review binds to the exact Wave 13 subject digest;
2. the review binds to the exact Wave 13 policy digest;
3. the reviewer is not the admitted Wave 12 subject producer;
4. the reviewer has not declared a conflict without recusing;
5. the reviewer is not recused;
6. the serialized identity state is `externally_verified`;
7. the review records both identity-verification and role-authority references and SHA-256 digests;
8. a separately trusted `ExternalHumanReviewVerification` is supplied out of band;
9. that trusted context matches the reviewer, role, identity digest, role-authority digest, and the **exact human-review digest**;
10. the decision is `approve`;
11. the role is required by the active policy.

The serialized `externally_verified` value is only a recorded claim. It **cannot self-authorize a review**.
IX-BlackFox is **not an identity provider** and does
not infer trusted authority from fields inside its own package. A caller that
integrates an identity and authorization system must authenticate that external
source and then supply matching `ExternalHumanReviewVerification` context through
the programmatic build and verification APIs. The external context binds the
exact review digest, so confirming that a person exists or holds a role is not
enough to confirm a different decision.

The trusted external-verification context is deliberately not embedded in the
package as its own authority source. The board evaluation records only its count
and a deterministic context digest. An `approved_for_next_gate` package must be
reverified with the same trusted out-of-band context. Verification without that
context, or with mismatching context, fails closed.

A merely `recorded` identity does not count toward quorum. Seven serialized
reviews that claim `externally_verified` also do not count when trusted external
context is absent. Test fixtures use deterministic synthetic verification records
only to exercise this integration boundary. The Wave 13 CI campaign supplies
zero human reviews and zero external-verification records, so it cannot produce
an approval by construction.

## Dissent, conflict, and recusal

Wave 13 preserves negative human evidence rather than reducing review to a
single approval counter.

A trusted-context-confirmed `reject` fails closed under the default policy. A
trusted-context-confirmed `request_changes` also fails closed. An open `EvidenceChallenge` blocks
the board until it is resolved or withdrawn under a
policy that permits that state.

A reviewer can declare a conflict. A conflicted reviewer must recuse before the record can stop being a blocking conflict. A recused review contributes no approval authority. The model prevents a recused record from claiming an
`approve` decision.

## Board states

Wave 13 has exactly three top-level dispositions:

| State | Meaning |
| --- | --- |
| `blocked` | A fail-closed condition exists, such as stale binding, self-approval, authenticated rejection, request-changes, unresolved blocking challenge, or conflict without recusal. |
| `human_review_required` | The package is coherent, but the configured qualifying human role coverage or quorum is incomplete. This is the expected offline CI state. |
| `approved_for_next_gate` | The configured human role coverage, trusted external verification context, distinct-reviewer rule, quorum, and challenge rules are satisfied. This is not deployment authority. |

`approved_for_next_gate` intentionally stops at the next governed boundary. It
does not mean production approved, deploy approved, certified, compliant,
procurement approved, ATO/cATO granted, or operationally authorized.

## Wave 12 admission

`review_board.admission.admit_wave12_package()` does not trust a path name or an
outer digest. It executes the Wave 12 independent verifier and then parses the
canonical Wave 12 manifest.

The resulting Wave 13 subject binds:

- repository
- revision
- Wave 12 subject producer
- exact Wave 12 archive SHA-256
- Wave 12 manifest digest
- Wave 12 profile digest
- Wave 12 readiness state
- Wave 12 bundle-index digest
- Wave 12 subject digest

The Wave 13 package builder repeats admission before writing the package. The
Wave 13 verifier extracts the embedded Wave 12 ZIP and repeats the same admission
again. A corrupted nested Wave 12 package therefore cannot be rescued by
refreshing only the outer Wave 13 hashes.

## Package layout

A Wave 13 package contains:

```text
review-case.json
machine-advisories.json
human-reviews.json
evidence-challenges.json
board-evaluation.json
review-ledger.json
upstream/wave12-certification-ready-evidence.zip
bundle-index.json
```

The ZIP is deterministic for identical inputs. Entry names are sorted, ZIP
timestamps are fixed, file modes are fixed, JSON is canonicalized, and
compression settings are fixed.

## Independent verifier

`verify_review_board_package()` checks:

- safe relative ZIP paths;
- duplicate entries;
- directory and symlink rejection;
- per-entry, total-size, and compression-ratio limits;
- required package entries;
- UTF-8 JSON object roots;
- canonical subject and policy parsing;
- canonical machine-advisory, human-review, and evidence-challenge sets;
- exact embedded Wave 12 SHA-256 binding;
- independent Wave 12 package verification;
- exact reconstruction of the Wave 13 subject from the embedded Wave 12 package;
- independent board-policy recomputation;
- trusted external human-review context count and digest binding;
- exact human-review digest confirmation before any approval can count;
- deterministic review-ledger reconstruction;
- deterministic bundle-index reconstruction from the actual package bytes.

The verifier does not trust a self-consistent `approved_for_next_gate` string.
If an attacker edits the board disposition and refreshes outer hashes, the
independent policy recomputation still detects the semantic mismatch. If a
serialized package was legitimately built with trusted external review context,
the verifier requires matching out-of-band context again. Package fields cannot
reconstruct or promote that authority by themselves.

## Review ledger

`review-ledger.json` is a deterministic package-internal hash chain over:

1. subject admission;
2. policy binding;
3. machine advisories;
4. human reviews;
5. evidence challenges;
6. the board evaluation.

Every event includes the previous event hash and the digest of the represented
object. Reordering or mutating the serialized review sequence changes the
recomputed chain.

This ledger is not an external transparency log, trusted timestamp, blockchain,
or signature service.

## Schemas

Wave 13 ships JSON Schemas for the public serialized surfaces:

- `schemas/wave13-review-case.schema.json`
- `schemas/wave13-machine-advisories.schema.json`
- `schemas/wave13-human-reviews.schema.json`
- `schemas/wave13-evidence-challenges.schema.json`
- `schemas/wave13-board-evaluation.schema.json`
- `schemas/wave13-package-verification.schema.json`
- `schemas/wave13-review-board-ci-summary.schema.json`

The runtime parser remains authoritative for canonical semantic reconstruction;
the schemas document and constrain the interoperable JSON shapes.

## Operator CLI

Build a Wave 13 package over an explicit Wave 12 package:

```bash
blackfox review-board build \
  --wave12-package .blackfox-artifacts/wave12/wave12-certification-ready-evidence.zip \
  --output .blackfox-artifacts/wave13/wave13-human-machine-review-board.zip
```

Without a machine-advisory input file, the command creates a deterministic
rule-based advisory from the actual Wave 12 verification state. Without human
review input, the board remains `human_review_required`. The CLI intentionally
does not provide an option that converts serialized external-verification claims
into trusted context. Authoritative external identity, role, and exact-decision
verification belongs at a separately trusted integration boundary.

Verify the serialized package independently:

```bash
blackfox review-board verify \
  --package .blackfox-artifacts/wave13/wave13-human-machine-review-board.zip
```

Require completed human board approval:

```bash
blackfox review-board gate \
  --package .blackfox-artifacts/wave13/wave13-human-machine-review-board.zip
```

For offline CI, explicitly allow the expected open human gate:

```bash
blackfox review-board gate \
  --package .blackfox-artifacts/wave13/wave13-human-machine-review-board.zip \
  --allow-human-review-required
```

## CI campaign

The dedicated workflow is:

`.github/workflows/wave13-human-machine-review-board.yml`

It:

1. installs the declared development tooling;
2. runs the Wave 13 adversarial and contract tests;
3. compiles the Wave 13 implementation;
4. executes `scripts/run_wave12_assurance_ci.py` to regenerate the real upstream evidence package;
5. executes `scripts/run_wave13_review_board_ci.py` over that exact Wave 12 package;
6. expects `human_review_required`;
7. uploads the Wave 13 package and verification surface.

The Wave 13 CI runner intentionally provides `human_reviews=()` and no trusted
external-verification context. It asserts:

- `human_review_supplied: false`
- `external_verification_supplied: false`
- `external_verification_count: 0`
- `qualifying_human_approval_count: 0`
- `machine_vote_weight: 0`

A green CI result means the implementation and evidence chain worked and the
human gate remained unsatisfied. It does not mean a human board approved the
revision.

## Main modules

| Module | Responsibility |
| --- | --- |
| `review_board.models` | Roles, policies, machine advisories, human reviews, challenges, findings, and dispositions |
| `review_board.admission` | Independent Wave 12 verification and exact subject construction |
| `review_board.policy` | Full-board default policy and fail-closed deterministic evaluation |
| `review_board.package` | Deterministic package, advisory/review/challenge sets, ledger, and bundle index |
| `review_board.parsing` | Strict reconstruction of serialized Wave 13 documents |
| `review_board.verify` | ZIP safety, nested Wave 12 verification, semantic recomputation, ledger and index verification |
| `review_board.cli` | Build, verify, and gate operator commands |
| `scripts/run_wave13_review_board_ci.py` | Offline CI campaign with intentionally absent human approvals |

## Threat boundary and non-claims

Wave 13 does not claim to provide:

- identity proofing or identity-provider validation;
- automatic role authorization from package data;
- proof that a human made a decision unless trusted out-of-band review verification is supplied;
- qualified digital signatures;
- external trusted timestamps;
- a transparency log;
- certification or accreditation;
- compliance approval;
- ATO or cATO authority;
- procurement approval;
- deployment or production authorization;
- operational command authority;
- correctness, safety, or security guarantees;
- autonomous human-equivalent approval.

It provides a bounded, testable, auditable, policy-gated, evidence-producing,
human-reviewable mechanism for proving **which evidence was reviewed, which
roles were required, what machine analysis said, what humans decided, whether
the decisions bind to the exact subject and policy, and whether the configured
review gate is actually satisfied**.
