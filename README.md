<p align="center">
  <img src="IX-BlackFox-Logo.png" alt="IX-BlackFox Logo">
</p>

# IX-BlackFox

**Enforce authority before AI agents change code.**

**AI proposes. Humans decide. Evidence decides trust.**

IX-BlackFox is a source-available AI engineering control plane for governed software change.

It sits between AI agents and consequential tools, treating model output as untrusted input until identity, delegated authority, scope, evidence, revision state, policy, and required human approval agree.

BlackFox is designed around a simple rule:

> **Capability is not authority. An AI agent being able to perform an action does not mean it is authorized to perform it.**

Today, BlackFox provides a live MCP/API enforcement boundary with federated workload identity, delegated least privilege, revocation, evidence-conditioned authorization, human-gated execution, revision-bound verification, and cryptographically chained authority receipts.

---

## What BlackFox does

BlackFox governs AI-produced software changes **before consequential tool execution**.

Its current control surface includes:

* live pre-tool enforcement for configured MCP and HTTP API actions
* cryptographically verified short-lived workload identity
* configured issuer, audience, subject, token-time, key, and replay-related checks
* trusted external identity-to-agent binding
* bounded delegated authority
* delegation that may narrow authority but cannot expand its parent authority
* tool, repository, path, and expiration constraints
* durable token and delegation revocation
* registered agent capabilities and scopes
* repository and revision-bound evidence
* evidence freshness and provenance checks
* policy-shaped human approval where required
* exact action-subject binding
* sandbox and repository-impact controls
* deterministic evidence packaging
* independent verification
* machine advisories with no human voting authority
* transactionally hash-chained authority receipts
* receipt lookup and independent chain verification
* fail-closed behavior when required trust material is missing or invalid

The goal is not to make AI agents more autonomous.

The goal is to make increasingly capable agents **bounded, attributable, inspectable, revocable, and governable**.

---

## The enforcement path

```text
AI Agent
   |
   v
MCP / HTTP API request
   |
   v
Federated Workload Identity
   |
   v
Registered Agent Binding
   |
   v
Delegated Authority + Scope
   |
   v
Repository / Revision / Evidence Checks
   |
   v
Policy Evaluation
   |
   v
Human Authority When Required
   |
   v
ALLOW or DENY
   |
   +---- DENY ----> upstream is not executed
   |
   +---- ALLOW ---> configured upstream tool executes
                         |
                         v
                Hash-Chained Authority Receipt
```

BlackFox is intended to make the answer to these questions inspectable:

* Who is this workload?
* Which registered agent does that identity represent?
* Who delegated authority to it?
* What tool may it invoke?
* Which repository may it affect?
* Which paths may it touch?
* Which exact revision does the evidence describe?
* Is the evidence authentic and current?
* Is human approval required?
* Is that approval bound to this exact action?
* Has the identity or delegation been revoked?
* Did a denied request reach the upstream?
* What actually executed?
* Can the resulting authority record be independently checked?

---

## Show me it works

Wave 15 includes a live proof using:

* a real RS256 keypair
* a real JWKS trust document
* short-lived signed workload tokens
* real HTTP sockets
* bounded delegation
* a real upstream side effect
* persistent revocation
* hash-chained authority receipts

The proof exercises both allowed and denied paths.

Representative validated behavior:

```text
Static credential in federated-only mode   -> 401 DENIED
Wrong token audience                       -> 401 DENIED
Expired workload token                     -> 401 DENIED
Missing required delegation                -> 401 DENIED
Delegation scope escape                     -> 403 DENIED

Upstream executions after denied requests  -> 0

Valid identity + bounded delegation
+ required authority                       -> 200 ALLOWED

Upstream executions after allowed request  -> 1

Revoked workload token reuse               -> 401 DENIED

Upstream executions after revocation       -> still 1

Receipt-chain verification                 -> PASSED
Receipt-chain issues                       -> 0
```

The important property is not the HTTP status code itself.

It is that requests which fail the authority boundary **do not reach the configured upstream action**.

---

## Run the Wave 15 proof

IX-BlackFox requires Python 3.11 or newer.

Install the project and development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run the current enterprise-identity and delegated-authority proof:

```bash
python scripts/run_wave15_enterprise_identity_ci.py --root .
```

For the complete identity, delegation, revocation, threat, and claim boundaries, see:

[`docs/wave15-enterprise-identity-delegated-authority.md`](docs/wave15-enterprise-identity-delegated-authority.md)

---

## Why identity alone is not enough

Authenticating an AI agent answers only part of the problem.

BlackFox separates:

```text
IDENTITY
Who is making the request?

AUTHORITY
What is that identity allowed to do?

DELEGATION
Where did that authority come from?

SCOPE
Which tools, repositories, and paths are permitted?

EVIDENCE
What verified information supports the action?

HUMAN AUTHORITY
Does this action require an accountable human decision?

REVOCATION
Can previously granted authority be invalidated?

RECEIPTS
Can the resulting decision and execution history be checked later?
```

A valid identity does not automatically receive tool authority.

A valid delegation cannot expand beyond its parent authority.

Valid evidence does not automatically replace required human approval.

A capable model does not approve itself.

---

## Fail closed before execution

For configured consequential actions, BlackFox is designed to deny before forwarding when required conditions are not satisfied.

Examples include:

* missing or invalid workload identity
* untrusted issuer
* wrong audience
* expired or not-yet-valid token
* unrecognized identity binding
* revoked token
* missing delegation
* revoked delegation
* expired delegation
* delegation outside permitted scope
* unregistered capability
* repository mismatch
* path-scope violation
* missing required evidence
* invalid evidence authentication
* revision mismatch
* stale evidence
* missing required human approval
* approval bound to the wrong action subject
* receipt-chain integrity failure during required startup verification

Denied configured tool actions are not supposed to become upstream side effects.

---

## Human authority remains separate

BlackFox does not treat machine confidence, model output, or machine review as human authorization.

The review-board layer supports role-separated human review while preserving machine analysis as advisory.

Machine advisories are non-authoritative and carry zero voting authority.

Human review can be bound to:

* the exact evidence subject
* review policy
* reviewer identity evidence
* role-authority evidence
* the exact review decision
* conflict and recusal rules
* required quorum and role coverage

This preserves the project's governing principle:

> **AI proposes. Humans decide. Evidence decides trust.**

---

## Evidence is bound to what was actually reviewed

BlackFox uses content-addressed, revision-bound evidence rather than treating a passing test result as universally reusable approval.

The evidence architecture can bind assurance material to:

* repository
* revision
* policy
* action subject
* provenance
* verification result
* review state
* human authority
* chained execution receipts

Changing the governed subject can invalidate the authority derived from evidence for the previous subject.

---

## Independent verification

BlackFox does not rely solely on a producer saying its own package is valid.

The project includes independent verification paths that reopen serialized evidence and recompute important integrity and semantic properties.

Depending on the evidence layer, verification includes controls such as:

* canonical representations
* content digests
* deterministic packaging
* safe archive paths
* bounded archive expansion
* nested evidence verification
* revision binding
* policy binding
* review binding
* semantic recomputation
* ledger verification
* receipt-chain verification

Self-consistent hashes alone are not treated as sufficient proof when semantic verification is required.

---

## Current architecture

```text
                         IX-BlackFox

        +-------------------------------------------+
        |        Federated Workload Identity        |
        |  issuer / audience / subject / token      |
        +----------------------+--------------------+
                               |
                               v
        +-------------------------------------------+
        |        Registered Agent Authority          |
        | capabilities / repositories / path scope  |
        +----------------------+--------------------+
                               |
                               v
        +-------------------------------------------+
        |          Delegated Least Privilege         |
        | parent binding / narrowing / expiration   |
        |                 revocation                  |
        +----------------------+--------------------+
                               |
                               v
        +-------------------------------------------+
        |           Evidence + Policy Gates          |
        | provenance / revision / freshness / risk  |
        +----------------------+--------------------+
                               |
                               v
        +-------------------------------------------+
        |           Human Authority Boundary         |
        |       when policy requires approval        |
        +----------------------+--------------------+
                               |
                               v
                    +---------------------+
                    |    ALLOW / DENY     |
                    +----------+----------+
                               |
                +--------------+--------------+
                |                             |
              DENY                          ALLOW
                |                             |
        no upstream action             upstream executes
                                              |
                                              v
                                  +-----------------------+
                                  | Authority Receipt     |
                                  | hash-chained +        |
                                  | independently checked |
                                  +-----------------------+
```

---

## Primary components

### Live Authority Gateway

A live request-path enforcement surface for configured MCP and HTTP API tool calls.

It evaluates authority **before** forwarding to the configured upstream.

See:

[`docs/wave14-live-authority-gateway.md`](docs/wave14-live-authority-gateway.md)

### Enterprise Identity & Delegated Authority

Adds cryptographically verified workload identity, trusted agent binding, bounded delegation, expiration, narrowing, and revocation.

See:

[`docs/wave15-enterprise-identity-delegated-authority.md`](docs/wave15-enterprise-identity-delegated-authority.md)

### Human-Machine Review Board

Keeps machine analysis visible while reserving binding approval authority for configured human review roles.

See:

[`docs/wave13-human-machine-review-board.md`](docs/wave13-human-machine-review-board.md)

### Certification-Ready Evidence Packaging

Produces bounded, revision-bound, content-addressed, deterministic evidence packages with independent verification.

Here, **certification-ready** describes the structure and verification posture of the evidence package. It does not mean BlackFox or a consuming organization is certified.

See:

[`docs/wave12-certification-ready-evidence.md`](docs/wave12-certification-ready-evidence.md)

---

## Validation

The primary CI matrix covers:

* Python 3.11
* Python 3.12
* Python 3.13
* Ruff
* mypy
* pytest
* dedicated evidence and authority workflows for major BlackFox control layers

Wave 15 also has dedicated enterprise-identity and delegated-authority CI proofing across the supported Python matrix.

**Treat current GitHub Actions results and [`VALIDATION_REPORT.md`](VALIDATION_REPORT.md) as the source of truth for current validation status rather than relying on a static test-count claim in this README.**

---

## Local quality checks

Install development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run Ruff:

```bash
python -m ruff check .
```

Run mypy:

```bash
python -m mypy src
```

Run the complete test suite:

```bash
python -m pytest -q
```

---

## Development history

BlackFox was built incrementally, but the README describes the **current system**, not a chronological feature dump.

Major recent milestones:

| Generation | Capability                                |
| ---------- | ----------------------------------------- |
| Wave 15    | Enterprise Identity & Delegated Authority |
| Wave 14    | Live Authority Gateway                    |
| Wave 13    | Human-Machine Review Board                |
| Wave 12    | Certification-Ready Evidence Packaging    |

The individual architecture and validation documents retain the detailed contracts and boundaries for each layer.

---

## What IX-BlackFox is not

IX-BlackFox is not:

* a replacement for accountable human review
* an external assessor
* an enterprise identity provider
* a general OIDC/OAuth/IAM federation service
* a human identity-proofing service
* a qualified digital-signature service
* a production high-availability reverse proxy for every MCP method or transport
* a production authorization or deployment authority
* a certified compliance product
* FedRAMP authorized
* an ATO or cATO issuer
* DoD approved or endorsed
* AWS approved or endorsed
* an external transparency log
* a claim of formal verification
* a guarantee of software correctness
* an autonomous human-equivalent approval system

BlackFox is a platform-neutral, evidence-bound control plane and research implementation for making AI-assisted engineering actions more attributable, constrained, inspectable, reviewable, revocable, and governable.

Its evidence packages and authority receipts can be consumed by CI, artifact storage, assessment, cloud, and other integration layers without implying that those external systems have approved or certified BlackFox.

---

## Framework mappings

BlackFox evidence work includes bounded conceptual mappings to frameworks including:

* NIST SP 800-218 SSDF 1.1
* NIST AI RMF 1.0
* NIST OSCAL Assessment Results
* SLSA 1.2
* in-toto Statement v1

These are **mappings only**.

They do not constitute certification, accreditation, conformity, an ATO, a cATO, a SLSA level claim, government approval, or external endorsement.

---

## License and use

IX-BlackFox is source-available for technical evaluation under the repository license.

Unless a separate written commercial license says otherwise, public visibility does not grant permission for commercial use, production use, hosted-service use, contractor use, funded operational use, derivative operational use, procurement use, or resale.

See [`LICENSE`](LICENSE) for the controlling terms.

See [`COMMERCIAL.md`](COMMERCIAL.md) for commercial-use information.

---

## Documentation

Key documents:

* [`docs/wave15-enterprise-identity-delegated-authority.md`](docs/wave15-enterprise-identity-delegated-authority.md)
* [`docs/wave14-live-authority-gateway.md`](docs/wave14-live-authority-gateway.md)
* [`docs/wave13-human-machine-review-board.md`](docs/wave13-human-machine-review-board.md)
* [`docs/wave12-certification-ready-evidence.md`](docs/wave12-certification-ready-evidence.md)
* [`docs/system-architecture.md`](docs/system-architecture.md)
* [`VALIDATION_REPORT.md`](VALIDATION_REPORT.md)
* [`HANDOFF_MANIFEST.md`](HANDOFF_MANIFEST.md)

---

## Authorship

IX-BlackFox was originated and created by Bryce Lovell.

**AI proposes. Humans decide. Evidence decides trust.**
