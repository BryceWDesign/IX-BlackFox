<p align="center">
  <img src="IX-BlackFox-Logo.png" alt="IX-BlackFox Logo">
</p>

# IX-BlackFox

**AI proposes. Humans decide. Evidence decides trust.**

IX-BlackFox is a source-available AI engineering control plane for governing
AI-assisted software-change workflows.

It treats model output as untrusted input and puts proposed actions behind
scoped capabilities, policy gates, sandbox boundaries, repository-impact
analysis, content-addressed evidence, provenance, and separate human authority.

## Wave 12: Certification-Ready Evidence Packaging

Wave 12 turns real prior-wave and quality evidence into a deterministic archive
that a separate reviewer can inspect and independently reverify.

Here, **certification-ready** has a narrow meaning: evidence is explicitly
scoped, revision bound, content addressed, mapped to a versioned profile,
checked for completeness, packaged deterministically, and reopened by a
fail-closed verifier.

It does not mean that IX-BlackFox, a repository, a workflow, a model, or an
organization is certified or formally compliant.

Wave 12 adds:

- bounded local evidence collection with traversal, symlink, size, secret-key,
  duplicate, JSON, and stale-revision rejection
- real pytest, Ruff, strict mypy, and compileall result capture with
  `shell=False`
- regeneration of available Wave 6, 7, 8, 9, and 11 evidence
- a nine-control assurance profile with mandatory and optional mappings
- deterministic control-to-evidence crosswalks and readiness findings
- separate asserted claims and explicit non-claims
- deterministic ZIP construction with canonical JSON and SHA-256 inventories
- an unsigned in-toto Statement v1 with an explicitly unauthenticated predicate
- an independent archive verifier with ZIP safety limits and semantic
  recomputation
- a human-authority gate that local CI cannot silently satisfy
- `blackfox assurance build`, `verify`, and `gate` commands
- a dedicated offline evidence workflow and artifact surface

The full contract is documented in
[`docs/wave12-certification-ready-evidence.md`](docs/wave12-certification-ready-evidence.md).

## Readiness states

| State | Meaning |
| --- | --- |
| `blocked` | Mandatory evidence, integrity, claim, binding, or authority checks failed. |
| `review_required` | Mandatory evidence is coherent, but separate externally verified human authority is still absent. This is the expected offline CI result. |
| `ready_for_external_assessment` | The package is coherent and a separate human approval is bound through externally verified review evidence. This still is not certification or deployment approval. |

The local collector emits `integrity_verified` evidence only. A review JSON file
cannot promote itself to `ready_for_external_assessment`. External identity or
signature verification must happen at an integration boundary and supply an
`externally_verified` human-review artifact. IX-BlackFox does not fabricate that
verification.

## What the verifier proves

The verifier reopens the serialized archive and checks:

- safe, unique ZIP paths and bounded expansion
- required documents and valid UTF-8 JSON
- entry sizes and SHA-256 digests
- exact manifest-to-evidence inventory
- subject, profile, crosswalk, readiness, and review bindings
- canonical manifest and authority-review representations
- recomputed control coverage and readiness findings
- recomputed review set, bundle index, and in-toto statement
- prohibited asserted claims

It does not trust self-consistent hashes alone. Changing a readiness status and
refreshing the affected digests still fails semantic recomputation.

A passing verification proves archive integrity and internal coherence. The
package remains unsigned, and the verifier does not authenticate a person,
organization, or platform.

## Main Wave 12 modules

| Module | Responsibility |
| --- | --- |
| `assurance.models` | Subjects, evidence descriptors, controls, profiles, claims, reviews, and manifests |
| `assurance.profiles` | Default bounded evidence profile and mapping-only framework references |
| `assurance.evidence` | Contained evidence collection, validation, hashing, and revision binding |
| `assurance.crosswalk` | Deterministic control-to-evidence evaluation |
| `assurance.report` | Claim enforcement, external-review qualification, and readiness disposition |
| `assurance.quality` | Shell-free quality-command execution and evidence capture |
| `assurance.package` | Deterministic ZIP, bundle index, and unsigned in-toto Statement creation |
| `assurance.parsing` | Strict reconstruction of serialized manifests and authority reviews |
| `assurance.verify` | Archive safety, integrity, binding, and semantic recomputation |
| `assurance.cli` | Build, verify, and gate operator commands |

Wave 11 remains the identity and authority foundation beneath this layer. It
provides agent identities, scoped capability grants, self-approval prevention,
authorization records, and append-only provenance.

## Package layout

A Wave 12 assurance package contains:

```text
manifest.json
crosswalk.json
readiness-report.json
authority-reviews.json
in-toto-statement.json
bundle-index.json
evidence/...
```

Given identical manifest inputs and evidence bytes, the builder produces a
byte-identical archive using sorted names, fixed timestamps, fixed file modes,
canonical JSON, and deterministic compression settings.

## Framework boundaries

The default profile includes bounded conceptual mappings to:

- NIST SP 800-218 SSDF 1.1
- NIST AI RMF 1.0
- NIST OSCAL Assessment Results
- SLSA 1.2
- in-toto Statement v1

These are mappings only. Wave 12 does not emit a conformant OSCAL Assessment
Results document, claim a SLSA level, sign an attestation, or convert evidence
coverage into certification.

## Install and test

IX-BlackFox requires Python 3.11 or newer.

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

Run the complete local quality suite:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy src
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall -q src scripts tests
```

Run the focused Wave 12 campaign tests:

```bash
.venv/bin/python -m pytest \
  tests/assurance \
  tests/ci/test_wave12_assurance_runner_contract.py \
  tests/ci/test_wave12_assurance_workflow_contract.py \
  tests/docs/test_wave12_assurance_docs.py \
  -q
```

Trust current local or GitHub Actions output, not a static README claim, as proof
that checks passed.

## Generate the offline evidence package

The end-to-end runner always regenerates prerequisite evidence and runs the full
quality suite. It has no partial-campaign switch.

```bash
PYTHONPATH=src python scripts/run_wave12_assurance_ci.py \
  --root . \
  --head-sha 0123456789abcdef0123456789abcdef01234567 \
  --expected-status review_required
```

It writes:

```text
.blackfox-artifacts/wave12/wave12-certification-ready-evidence.zip
.blackfox-artifacts/wave12/wave12-package-verification.json
.blackfox-artifacts/wave12/wave12-assurance-readiness-report.json
.blackfox-artifacts/wave12/wave12-assurance-crosswalk.json
.blackfox-artifacts/wave12/wave12-assurance-manifest.json
.blackfox-artifacts/wave12/wave12-evidence-spec.json
.blackfox-artifacts/wave12/wave12-assurance-ci-summary.json
```

The GitHub Actions workflow is
`.github/workflows/wave12-assurance-evidence.yml`. It runs without model API
keys, AWS credentials, signing keys, or autonomous approval authority.

## Operator CLI

Build from an explicit evidence specification:

```bash
blackfox assurance build \
  --root . \
  --revision 0123456789abcdef0123456789abcdef01234567 \
  --evidence-spec evidence-spec.json
```

Independently verify a serialized package:

```bash
blackfox assurance verify \
  --package .blackfox-artifacts/wave12/wave12-certification-ready-evidence.zip
```

Require externally approved assessment readiness:

```bash
blackfox assurance gate \
  --package .blackfox-artifacts/wave12/wave12-certification-ready-evidence.zip
```

Offline CI can prove that the human gate remains open without pretending to
satisfy it:

```bash
blackfox assurance gate \
  --package .blackfox-artifacts/wave12/wave12-certification-ready-evidence.zip \
  --allow-review-required
```

## What IX-BlackFox is not

IX-BlackFox is not:

- a replacement for human review or an external assessor
- a production authorization or deployment authority
- a certified compliance product
- FedRAMP authorized
- an ATO or cATO issuer
- DoD approved or endorsed
- AWS approved or endorsed
- a qualified signature or reviewer-identity verification service
- a transparency log
- a claim of formal verification or guaranteed software correctness
- an autonomous agent approval system

It is a platform-neutral, evidence-bound control plane and research prototype
for making AI-assisted engineering workflows more inspectable, reviewable,
identity bound, and governable. Its evidence packages can be consumed by CI,
artifact storage, assessment, or cloud integration layers without granting
those layers implied approval.

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
