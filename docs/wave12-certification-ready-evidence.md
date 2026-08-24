# Wave 12 Certification-Ready Evidence Packaging

## Purpose

Wave 12 turns prior IX-BlackFox evidence into a deterministic package that can
be inspected by a separate assessor.

The phrase certification-ready has a narrow meaning here. It means the package
has explicit scope, content-addressed artifacts, control mappings, actor and
revision bindings, human-authority state, claim boundaries, and an independent
byte-level verifier.

It does not mean that IX-BlackFox, a repository, an AI model, a workflow, or an
organization has been certified.

The governing rule remains:

```text
AI proposes. Humans decide. Evidence decides trust.
```

## Problem Wave 12 addresses

Earlier waves produced policy decisions, sandbox receipts, repository-impact
reports, audit records, operating envelopes, agent identities, capability
decisions, and provenance chains.

Those artifacts are useful individually, but an external reviewer still needs
answers to a larger set of questions:

1. Which repository revision does this evidence describe?
2. Which files are part of the review record?
3. Are the files complete and unchanged?
4. Which required evidence categories are present or missing?
5. Which external framework concepts are being mapped?
6. Is a mapping being misrepresented as certification?
7. Who produced the package?
8. Has a separate authenticated human authority approved external assessment?
9. Can a second implementation reopen the archive and verify every binding?

Wave 12 answers those questions without granting authority to the package
builder, a model, a tool, a CI runner, or the verifier.

## Implemented capability

Wave 12 adds `src/ix_blackfox/assurance/` with these boundaries:

| Module | Responsibility |
| --- | --- |
| `models` | Subjects, evidence descriptors, controls, profiles, claims, reviews, and manifests |
| `profiles` | Default Wave 12 evidence profile and bounded external-framework mappings |
| `evidence` | Local evidence collection, path containment, size limits, JSON validation, and revision binding |
| `crosswalk` | Control-to-evidence matching and mandatory coverage evaluation |
| `report` | Claim enforcement, human-authority checks, and readiness disposition |
| `quality` | Shell-free capture of pytest, Ruff, mypy, and compileall outcomes |
| `package` | Deterministic ZIP creation, bundle index, and unsigned in-toto Statement |
| `verify` | Independent ZIP safety, digest, inventory, and semantic-binding verification |
| `cli` | `blackfox assurance build`, `verify`, and `gate` commands |

## Quality evidence

The Wave 12 CI runner executes and captures these commands as real JSON
evidence:

```text
python -m pytest -q
python -m ruff check .
python -m mypy src
python -m compileall -q src scripts tests
```

Each record includes the bound revision, the exact argument vector, exit code,
standard output, standard error, timeout state, and a deterministic payload
digest.

Commands are executed with `shell=False`. A failed or timed-out command remains
recorded and blocks the Wave 12 CI campaign.

## Policy evidence

Wave 12 regenerates the Wave 9 compliance and audit report. The Wave 9 report is
expected to remain blocked in offline CI because CI is not a human authority.

That blocked disposition is valid evidence. It proves the earlier audit gate
still refuses to convert generated evidence into compliance approval.

Wave 12 requires the policy evidence to be valid JSON, integrity verified, and
bound to the same revision as the package subject.

## Sandbox evidence

Wave 12 regenerates the Wave 6 sandbox CI evidence and binds it to the package
revision.

The package records that the Wave 6 sandbox checks ran. It does not reinterpret
local sandbox evidence as formal isolation certification.

## Repository evidence

Wave 12 regenerates Wave 8 repository-intelligence evidence for the Wave 12
implementation paths.

This ensures the package includes an inspectable repository-impact surface
rather than relying on a prose description of what changed.

## Authority evidence

Wave 12 packages two separate Wave 11 artifacts:

1. Agent identity engine evidence, classified as agent-identity evidence.
2. Agent readiness evidence, classified as provenance evidence.

Both must be bound to the same revision as the Wave 12 subject.

The Wave 12 package producer is an explicit agent id. That producer cannot
approve its own package.

## Evidence collection boundary

Wave 12 does not blindly copy files into an archive.

Collection rejects:

- absolute paths
- parent traversal
- files outside the repository root
- symlink files
- symlink path components
- directories and other non-regular files
- duplicate artifact ids
- duplicate package paths
- individual files above the configured size limit
- total evidence above the configured size limit
- invalid UTF-8 JSON when JSON is declared
- JSON evidence bound to a different revision
- VCS, virtual-environment, cache, and dependency-tree paths
- common credential and private-key filenames
- PEM private-key markers inside otherwise permitted files

Every collected file is hashed with SHA-256 after it passes the collection
boundary.

## Revision binding

Structured evidence can declare an RFC 6901-style JSON pointer that identifies
its revision field.

Examples used by Wave 12 include:

```text
/head_sha
/subject/head_sha
/metadata/head_sha
```

If the pointer does not resolve or its value differs from the package revision,
collection stops. Stale evidence is not silently relabeled.

## Assurance profile

The default profile requires these evidence categories:

- tests
- static analysis
- strict type checking
- policy evaluation
- sandbox evaluation
- repository intelligence
- agent identity
- provenance

It also requires a separate human review before the package can advance from
`review_required` to `ready_for_external_assessment`.

Optional mappings exist for richer risk-assessment and externally verified
supply-chain evidence. Missing optional evidence is exposed but does not block
the core package.

## External-framework mappings

The profile includes bounded mappings to:

- NIST SP 800-218 SSDF 1.1 provenance concepts
- NIST AI RMF 1.0 governance and measurement concepts
- NIST OSCAL Assessment Results concepts
- SLSA 1.2 provenance and verification-summary concepts
- in-toto Statement v1 subject and predicate structure

These are mappings only.

Wave 12 does not emit a conformant OSCAL Assessment Results document because a
real OSCAL result must be connected to a real assessment plan and system scope.
Wave 12 does not claim a SLSA level because local content hashes do not prove a
trusted build platform or externally authenticated provenance.

The package contains an unsigned in-toto Statement v1. It identifies every
subject file by digest and carries a versioned BlackFox predicate. It is not a
signed attestation. Authentication belongs to an external signer or
attestation service and is deliberately not fabricated by the offline runner.

Primary specification references:

- NIST SSDF 1.1: <https://csrc.nist.gov/pubs/sp/800/218/final>
- NIST AI RMF: <https://airc.nist.gov/airmf-resources/airmf/>
- NIST OSCAL Assessment Results: <https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/>
- SLSA 1.2: <https://slsa.dev/spec/v1.2/>
- in-toto specifications: <https://in-toto.io/docs/specs/>

## Readiness states

Wave 12 has three states:

### `blocked`

The package has a mandatory evidence gap, invalid claim, invalid review,
unverified required artifact, self-approval attempt, non-human approval
attempt, review rejection, or broken binding.

### `review_required`

Mandatory evidence is complete and internally coherent, but a separately
authenticated human approval has not been supplied.

This is the expected offline CI state.

### `ready_for_external_assessment`

Mandatory evidence is complete, package and profile bindings are coherent, and
a separately authenticated human authority has approved the manifest for
external assessment.

This state still does not mean certified, compliant, production ready, or
approved for deployment.

## Human-authority boundary

An authoritative review must be:

- performed by an actor classified as a human operator
- bound to the exact manifest digest
- bound to the exact profile digest
- performed by an actor other than the package producer
- recorded as approval for external assessment only
- authenticated by evidence classified as human-review evidence
- backed by human-review evidence whose verification state is
  `externally_verified`

Model, tool, CI runner, and system-service approval attempts block readiness.

A recorded but unauthenticated human decision remains non-authoritative.

The local evidence collector deliberately emits only `integrity_verified`
artifacts. Consequently, a review JSON file and a locally collected human-review
file cannot move the CLI to `ready_for_external_assessment`. An external identity
or signature verifier must validate the reviewer binding and supply an
`externally_verified` evidence descriptor through an integration boundary.
Wave 12 does not fake that verifier.

## Claim boundary

Wave 12 separates asserted claims from explicit non-claims.

Asserted claims may state that:

- listed files are content-addressed
- the archive can be independently reverified
- missing evidence and review state are exposed
- unsupported assurance claims are blocked

Asserted claims may not declare certification, formal compliance, ATO, cATO,
government approval, production approval, or autonomous approval authority.

Explicit non-claims may name those terms because their purpose is to deny the
claim rather than assert it.

## Deterministic package

The package writer uses:

- sorted entry names
- fixed ZIP timestamps
- fixed regular-file permissions
- canonical JSON serialization
- SHA-256 content descriptors
- a non-self-referential bundle index
- no network calls
- no cloud credentials
- no signing keys

Given identical manifest data and identical evidence bytes, package output is
byte identical.

The package contains:

```text
manifest.json
crosswalk.json
readiness-report.json
authority-reviews.json
in-toto-statement.json
bundle-index.json
evidence/...
```

## Independent verification

The verifier reopens the serialized ZIP. It does not trust the in-memory build
objects.

It rejects:

- malformed ZIP files
- duplicate names
- unsafe paths
- directory entries
- symlink entries
- too many entries
- oversized entries
- oversized total expansion
- excessive compression ratios
- missing required documents
- invalid JSON documents
- index entries that do not match archive bytes
- manifest evidence that does not match archive bytes
- subject, profile, crosswalk, readiness, or review binding mismatches
- in-toto subjects that do not match archive bytes
- prohibited asserted claims

A passing verification proves archive integrity and internal semantic binding.
It does not authenticate a signer or organization.

The verifier does not trust self-consistent hashes alone. After reopening the
archive, it parses the canonical manifest and authority reviews, recomputes the
control crosswalk and readiness findings, rebuilds the review set, in-toto
statement, and bundle index, and compares those results with the serialized
documents. Rewriting a status and refreshing its digests does not produce a
passing package.

## CI campaign

The end-to-end runner is:

```text
scripts/run_wave12_assurance_ci.py
```

It performs this sequence:

1. Regenerate Wave 6 sandbox evidence.
2. Regenerate Wave 7 model-repair evidence.
3. Regenerate Wave 8 repository-intelligence evidence.
4. Regenerate Wave 11 agent-identity evidence.
5. Regenerate Wave 9 audit evidence after the earlier files exist.
6. Run the full pytest, Ruff, mypy, and compileall gates.
7. Create the revision-bound evidence input specification.
8. Collect and hash actual files.
9. Evaluate the default profile.
10. Build the readiness report.
11. Build the deterministic ZIP.
12. Reopen and independently verify the ZIP.
13. Require the expected `review_required` state.

Example:

```text
PYTHONPATH=src python scripts/run_wave12_assurance_ci.py \
  --root . \
  --head-sha 0123456789abcdef0123456789abcdef01234567 \
  --expected-status review_required
```

The dedicated workflow is:

```text
.github/workflows/wave12-assurance-evidence.yml
```

It uploads the package, manifest, crosswalk, readiness report, evidence spec,
verification report, and CI summary as one inspection surface.

The generated files are:

```text
.blackfox-artifacts/wave12/wave12-certification-ready-evidence.zip
.blackfox-artifacts/wave12/wave12-package-verification.json
.blackfox-artifacts/wave12/wave12-assurance-readiness-report.json
.blackfox-artifacts/wave12/wave12-assurance-crosswalk.json
.blackfox-artifacts/wave12/wave12-assurance-manifest.json
.blackfox-artifacts/wave12/wave12-evidence-spec.json
.blackfox-artifacts/wave12/wave12-assurance-ci-summary.json
```

## Operator CLI

Build from an explicit evidence spec:

```text
blackfox assurance build \
  --root . \
  --revision 0123456789abcdef0123456789abcdef01234567 \
  --evidence-spec evidence-spec.json
```

Verify a serialized package:

```text
blackfox assurance verify \
  --package .blackfox-artifacts/wave12/wave12-certification-ready-evidence.zip
```

Gate for a real external-assessment approval:

```text
blackfox assurance gate \
  --package .blackfox-artifacts/wave12/wave12-certification-ready-evidence.zip
```

Offline CI may explicitly allow the open review gate:

```text
blackfox assurance gate \
  --package .blackfox-artifacts/wave12/wave12-certification-ready-evidence.zip \
  --allow-review-required
```

That option does not satisfy human authority. It only permits CI to prove the
gate remains open.

## Acceptance rule

Wave 12 is complete only when all of these conditions hold:

- the untouched Wave 11 baseline is green before modification
- mandatory evidence is regenerated from the bound revision
- quality commands execute and their real results are captured
- stale, missing, sensitive, escaped, oversized, or symlinked evidence fails closed
- every package entry is content-addressed
- external-framework mappings remain mappings rather than certification claims
- model, tool, CI, and system self-approval attempts are blocked
- local review assertions cannot impersonate externally verified identity evidence
- separate human authority remains required
- deterministic builds are byte identical for identical inputs
- the independent verifier accepts the valid package
- the independent verifier rejects tampered and structurally hostile packages
- the full repository test, lint, type, and compile gates remain green
- documentation preserves the claim boundary

If any condition fails, Wave 12 is incomplete.

## Non-goals

Wave 12 is not:

- certification
- accreditation
- formal compliance determination
- FedRAMP authorization
- ATO or cATO
- DoD approval or endorsement
- AWS approval or endorsement
- procurement approval
- production authorization
- deployment authorization
- a qualified digital-signature service
- a built-in external reviewer-identity verifier
- a transparency log
- a replacement for an assessor
- a replacement for human review
- autonomous approval authority

## Strongest valid claim

The strongest valid Wave 12 claim is:

> IX-BlackFox Wave 12 can regenerate bounded prior-wave and quality evidence,
> bind it to a repository revision and assurance profile, package it
> deterministically, expose missing evidence and human-review state, and
> independently verify the serialized archive without converting that evidence
> into certification, compliance, deployment approval, or autonomous authority.
