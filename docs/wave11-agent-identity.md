# Wave 11 Agent Identity and Capability Registry

## Purpose

Wave 11 adds an agent identity and capability registry to IX-BlackFox.

The purpose is to make every actor explicit before it can participate in a
BlackFox-controlled action. A model, tool, CI runner, system service, repository
adapter, or human reviewer must be represented as a registered agent with a
bounded capability grant before an authorization decision can be trusted.

Wave 11 does not make BlackFox autonomous. It does not grant production authorization.
It does not certify a model, tool, workflow, or deployment.

The governing rule remains:

```
AI proposes. Humans decide.
```

## Problem Wave 11 addresses

Earlier BlackFox waves produced strong policy, evidence, sandbox, repository,
and compliance boundaries. Those waves proved that a proposed change can be
made inspectable before trust is granted.

Wave 11 closes a different gap:

```
Who is acting, what are they allowed to do, under what scope, and who can review
or approve the action?
```

Without that layer, a runtime can have good policy evidence while still treating
actors too generically. Wave 11 prevents that by binding authorization to named
agent identities and scoped capability grants.

## What Wave 11 implements

Wave 11 implements:

- agent identity records
- agent lifecycle states
- capability grant scopes
- capability posture validation
- an agent registry snapshot
- authorization requests
- authorization decisions
- human-authority validation
- self-approval prevention
- authorization provenance records
- a tamper-evident provenance ledger
- BrainManifest agent adapters
- ToolManifest agent adapters
- ReviewerAuthority and ReviewBoard adapters
- operating-envelope bridges
- agent-authorized tool gateway preflight
- an agent readiness report
- CI evidence generation for the Wave 11 layer

## Agent identity boundary

An agent identity is not just a label. It binds together:

- an agent id
- a display name
- an agent kind
- a trust tier
- a lifecycle state
- scoped capability grants
- issuer and subject metadata
- deterministic digest evidence

The important distinction is that a registered agent is still not trusted by default.
Registration only makes the actor visible and reviewable. Authorization remains
separate.

## Capability boundary

A capability grant answers four questions:

- What capability is being granted?
- What repository, domain, tool, pack, or path scope limits it?
- What risk tier is the maximum allowed for that grant?
- Does the grant require human review before use?

A grant with no practical boundary is rejected. A grant that attempts to give a
model, tool, CI runner, or system service human-only authority is blocked by
capability posture validation.

Human-only capabilities include release approval, security approval, compliance
approval, sandbox-egress approval, agent registration, capability delegation,
and agent revocation.

## Authorization boundary

Authorization is evaluated per request. A request binds:

- the requesting agent
- the requested action
- the requested capability
- the target scope
- risk tier
- evidence artifacts
- justification metadata

The evaluator returns one of three outcomes:

- allow
- require review
- block

An allow decision only means the request passed the Wave 11 identity and
capability preflight. It does not mean the final system action is globally safe,
production ready, or externally approved.

A review-required decision must name a human authority reviewer before it can be
accepted as authority-preserving evidence.

A block decision is expected behavior when the actor is unknown, revoked,
missing capability, out of scope, expired, or policy-invalid.

## Human authority boundary

Wave 11 keeps human authority separate from model output, tool execution, CI
status, and generated reports.

The human-authority evaluator checks whether:

- a review-required decision names a reviewer
- the reviewer is registered
- the reviewer is an active human authority agent
- the requester is not reviewing itself
- human-only capabilities are not being requested by non-human agents

A model may generate a patch proposal. A model may not approve its own release.
A tool may execute only after scoped authorization. A CI runner may produce
evidence, but the CI runner is not a human authority.

## Provenance boundary

Wave 11 authorization decisions can be recorded into an append-only provenance
ledger. Each record binds:

- the authorization decision id
- the decision digest
- the requesting agent
- evidence artifacts
- the previous chain digest
- the current record digest
- the resulting chain digest

This makes the authorization path replayable and tamper-evident. It does not
make the decision automatically correct.

## Adapter boundary

Wave 11 adapters convert existing BlackFox concepts into agent identities.

Brain manifests become governed model-brain agents. They can receive scoped
proposal, review, inspection, test-planning, and read-style participation
grants. They do not receive human approval authority.

Tool manifests become registered tool agents. Their declared capabilities and
side effects are mapped into scoped agent capability grants. Risky tool grants
remain visible so authorization and posture checks can block or require review.

Reviewer authority records become reviewer agents. Human reviewers can hold
human-authority trust. Model and system reviewers remain model or system agents,
so any attempted approval authority remains visible as blocking evidence.

## Tool gateway boundary

The Wave 11 tool gateway wrapper does not replace the existing governed tool
gateway. It adds an identity and capability preflight before the existing tool
policy and receipt flow can run.

If agent authorization blocks or requires review, the underlying tool gateway is
not executed.

## Readiness boundary

The readiness report checks whether the Wave 11 layer has enough coherent
evidence to be treated as ready for review.

It checks:

- registry posture
- active human authority presence
- authorization decision status
- authority evaluation coverage
- provenance coverage
- provenance chain validity

A warning can be a valid outcome. For example, a review-required decision is a
warning when authority is preserved and provenance exists. A warning proves a
gate exists; it is not the same as a failed system.

A blocked readiness report means the Wave 11 agent-governance evidence should
not be treated as complete.

## CI boundary

The Wave 11 CI runner is an offline diagnostic. It generates deterministic JSON
evidence for the agent identity, capability, authorization, human authority,
provenance, and readiness-report flow.

The CI runner intentionally does not contact model providers, cloud services, or
external approval systems. It does not use API keys. It does not issue production
authorization. It does not certify a system for deployment.

## Non-goals

Wave 11 is not:

- production authorization
- model safety certification
- ATO or cATO
- DoD endorsement
- procurement approval
- deployment approval
- autonomous agent approval
- a replacement for human review
- a replacement for security testing
- a claim that AI output is correct

## Acceptance rule

Wave 11 should only be treated as valid when the repository can prove all of the
following:

- every actor is represented as an explicit agent identity
- capability grants are scoped and digest-bound
- non-human actors cannot hold human-only authority
- review-required decisions require a separate human authority
- self-approval is blocked
- authorization decisions are provenance-recorded
- readiness reports expose warnings and blockers clearly
- CI evidence is generated without external model or secret access
- documentation preserves the claim boundary

If any of these fail, Wave 11 is incomplete.
