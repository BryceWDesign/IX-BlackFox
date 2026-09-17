# Wave 14: Live Authority Gateway

## Status

Wave 14 moves IX-BlackFox from an offline assurance/control engine into the live
request path between an AI agent and an external tool surface.

The Wave 14 contract is intentionally narrow:

> **No configured consequential tool action reaches its upstream unless agent
> identity/scope authorization and the configured evidence conditions both
> permit it.**

This is **evidence-conditioned authority**. A capability grant alone is not
enough when the route requires current evidence or trusted human approval.

## What is real in Wave 14

Wave 14 adds a functioning network service, not a mocked UI:

- a live HTTP gateway at `/mcp` for Model Context Protocol traffic
- support for the current stateless MCP `2026-07-28` request shape, including
  body/header protocol-version agreement plus `Mcp-Method`, `Mcp-Name`, and
  configured `Mcp-Param-*` mirror validation before governed `tools/call`
- authenticated pass-through for explicitly allowlisted non-tool MCP calls to a
  fixed configured upstream
- fail-closed browser `Origin` validation for MCP requests when an `Origin` header
  is present; the default empty allowlist rejects browser-originated MCP traffic
- fail-closed interception of MCP `tools/call` before the upstream receives the
  request
- a generic governed HTTP API at `/v1/invoke`
- exact action-subject construction at `/v1/subject` for approval binding
- environment-backed per-agent ingress credentials, verified in constant time
  before a caller can exercise a registered agent identity
- reuse of the Wave 11 agent registry and scoped-capability evaluator
- per-route capability, repository, path, risk, and evidence-policy binding
- HMAC-SHA256 authenticated evidence from explicitly trusted issuers
- repository/revision binding and evidence freshness enforcement
- optional exact-action binding through the Wave 14 subject digest
- a trusted human-approval evidence type that is an independent route-level
  execution condition when configured; it can satisfy an existing `REQUIRE_REVIEW`
  decision only when the approval is cryptographically valid, human-authored by
  policy shape, and bound to the exact subject
- real upstream invocation only after the final Wave 14 decision is `allow`
- fixed-length HTTP request framing only: `Transfer-Encoding`, ambiguous/multiple
  `Content-Length` fields, oversized bodies, and truncated bodies are rejected
  before JSON parsing or authority evaluation
- duplicate security-sensitive HTTP headers are rejected before request handling;
  authorization, origin, BlackFox identity/evidence headers, MCP authority headers,
  Host, and framing headers cannot acquire competing interpretations
- bounded evidence-reference input (maximum 64 unique references per action and
  128 characters per evidence id) before evidence loading or authority evaluation
- durable SQLite authority receipts with a transactionally maintained hash chain
- `/v1/receipts/<id>` lookup and `/v1/receipts/verify` chain verification
- health/readiness/status endpoints
- a local end-to-end integration proof that opens real network sockets, proves
  denied calls do not reach the upstream, then proves approved MCP and HTTP API
  calls do reach an upstream that performs a real upstream file write

## Enforcement flow

```text
Agent / MCP client
      |
      v
IX-BlackFox Live Authority Gateway
      |
      +--> protocol/header validation
      |
      +--> registered agent identity
      |
      +--> capability + repository + tool + path + risk scope
      |
      +--> evidence policy
      |      |
      |      +--> trusted issuer / key
      |      +--> canonical digest
      |      +--> HMAC signature
      |      +--> repository binding
      |      +--> revision binding
      |      +--> freshness
      |      +--> exact subject binding where required
      |      +--> trusted human approval where required
      |
      +--> BLOCK / REVIEW_REQUIRED / EVIDENCE_REQUIRED
      |        (upstream receives nothing)
      |
      `--> ALLOW
               |
               v
        configured MCP/API upstream
               |
               v
        durable authority receipt
```

## Current MCP profile

The gateway accepts MCP over HTTP and understands the current `2026-07-28`
stateless request profile for routing/enforcement. For modern `tools/call`
requests it checks that:

- `MCP-Protocol-Version` is supported and exactly matches
  `params._meta["io.modelcontextprotocol/protocolVersion"]`
- `Mcp-Method` agrees with the JSON-RPC method
- `Mcp-Name` agrees with the name-bearing JSON-RPC parameter; the exact MCP
  base64 sentinel form is decoded before comparison
- route-configured `Mcp-Param-*` mirrors agree with their bound primitive tool
  arguments before authority evaluation; configured mirrors are never trusted as
  a substitute for the JSON-RPC body
- unconfigured `Mcp-Param-*` headers are forwarded as intermediary metadata but
  are ignored for BlackFox authority decisions

For MCP `2026-07-28`, methods removed from that stateless profile such as
`initialize` are rejected rather than silently treated as modern requests. Earlier
streamable-HTTP protocol-version headers are accepted for explicitly configured
legacy pass-through compatibility. Every MCP connection, including pass-through
methods, requires a valid BlackFox agent ingress credential.
The gateway intentionally buffers bounded upstream responses rather than
implementing an unbounded long-lived subscription proxy. Wave 14 is focused on
consequential tool invocation, not acting as a general-purpose event-stream
relay. If an MCP request carries an `Origin` header, that origin must match
`server.allowed_origins`; an absent `Origin` is accepted for non-browser clients.

## Identity boundary

Wave 14 does **not** claim to be an enterprise identity provider, but it also
does not trust an unauthenticated caller-supplied agent id.

Every registered Wave 14 agent must have an `[[agent_credentials]]` binding in
the gateway config. The binding names an environment variable containing that
agent's ingress token. The token itself is never stored in TOML. Network calls
must provide it in `X-BlackFox-Agent-Token`; the gateway compares credential
bytes in constant time and maps the credential to exactly one registered agent.
Duplicate loaded token values make readiness fail and cannot authenticate a
request.

A caller may also state the expected agent id through:

- `X-BlackFox-Agent-Id`,
- MCP `_meta["io.ix-blackfox/agentId"]`, or
- the API request body.

When a stated id is present it must agree with the identity authenticated by the
ingress credential. An agent cannot obtain another registry entry's capability
grants simply by changing a header or request field.

This is intentionally a bounded Wave 14 network-authentication mechanism, not
enterprise federation. Deploy the plain HTTP listener only on a trusted network
or behind TLS termination. OIDC/OAuth, cloud workload identity, mTLS/SPIFFE,
Entra/Okta, IAM/STS, rotation services, and short-lived enterprise credentials
remain separate identity-integration work rather than claims hidden inside Wave
14.

Example configuration:

```toml
[[agent_credentials]]
agent_id = "coding-agent-07"
secret_env = "BLACKFOX_WAVE14_AGENT_TOKEN"
```

## Evidence-conditioned authority

Each route may reference an `EvidencePolicy`.

A policy can require evidence kinds such as:

- `test_result`
- `human_approval`
- other organization-defined kinds

Evidence is stored as canonical JSON under the configured evidence root. Every
signed artifact includes:

- evidence id and kind
- issuer and key id
- status
- repository id
- exact revision
- production time
- optional exact Wave 14 subject digest
- structured payload
- canonical SHA-256 digest
- HMAC-SHA256 signature

Secrets are **not** stored in the TOML config. A trusted issuer entry names the
environment variable from which its HMAC secret is loaded.

A target-bound approval cannot be replayed for a different action because its
`target_digest` must equal the digest of the exact agent/tool/repository/revision/
path/arguments/protocol subject.

## Human authority

Wave 11 already marks consequential capabilities such as workspace writes as
human-review gated for non-human actors. Wave 14 does not weaken that rule.

Instead, a route may name a `human_approval_kind`. That declaration is itself an
execution condition, even if the lower-level capability evaluator would otherwise
return `ALLOW`. A `REQUIRE_REVIEW` decision can become executable only when all
normal evidence conditions pass **and** a valid artifact of that kind:

- has status `approved`
- says `decision = "approve"`
- says `reviewer_kind = "human"`
- names a non-empty `reviewer_id`
- passes signature, issuer, repository, revision, freshness, and optional exact
  subject-binding checks

Machine evidence cannot satisfy this shape by silently claiming a vote.

## Receipts

Every governed tool decision is written to a SQLite receipt database. Receipts
record:

- the exact action subject
- the complete Wave 14 authority decision
- evidence references and verification results
- whether an upstream request was attempted
- upstream HTTP status
- a digest of any bounded upstream response body
- upstream transport errors
- an `execution_state` of `not_attempted`, `response_received`, or
  `outcome_unknown`
- a compatibility `executed` field meaning BlackFox received an upstream response
  after an allowed request, not proof of arbitrary upstream side effects
- the previous receipt digest and current receipt digest

Receipt insertion uses an immediate SQLite transaction so sequence and previous
hash are assigned atomically for one database. `blackfox gateway check` and
`GET /v1/receipts/verify` independently recompute the chain.

This chain detects local mutation/reordering. A single-use approval is atomically
reserved before upstream dispatch. If the process dies after reservation but before
a receipt is appended, the approval remains consumed and must be reissued; the
gateway chooses fail-safe replay prevention over automatic reuse. A transport error
after dispatch is recorded as `outcome_unknown` because BlackFox cannot prove whether
an arbitrary upstream completed a side effect.

The receipt chain is not a public transparency log, trusted timestamp, HSM-backed
non-repudiation system, or legal signature.

## Operator commands

Run the gateway after loading the example agent/evidence secrets from your
secret manager or shell environment:

```bash
export BLACKFOX_WAVE14_AGENT_TOKEN='replace-with-a-long-random-secret'
export BLACKFOX_WAVE14_CI_KEY='replace-with-a-ci-signing-secret'
export BLACKFOX_WAVE14_HUMAN_KEY='replace-with-a-human-review-signing-secret'
export BLACKFOX_WAVE14_OPERATOR_TOKEN='replace-with-a-separate-operator-secret'
blackfox gateway serve --config examples/wave14/blackfox.gateway.toml --print-status
```

`/readyz` returns only a minimal readiness result and remains non-ready if a
configured ingress credential, operator credential, or trusted evidence key is
missing or weak. The public `serve_gateway` entry point also refuses to bind the
listener when readiness fails, including receipt-chain verification failure.
Detailed `/v1/status` and receipt inspection endpoints require the operator
credential. Do not commit these secret values.

Check config/receipt state:

```bash
blackfox gateway check --config examples/wave14/blackfox.gateway.toml
```

Compute the exact subject digest for a pending action:

```bash
blackfox gateway subject \
  --config examples/wave14/blackfox.gateway.toml \
  --agent-id coding-agent-07 \
  --tool-name filesystem.write_file \
  --protocol mcp/2026-07-28 \
  --arguments-json '{"path":"docs/readme.md","revision":"abc123","content":"change"}'
```

Issue evidence with a configured trusted issuer after setting the issuer secret
environment variable:

```bash
blackfox gateway issue-evidence \
  --config examples/wave14/blackfox.gateway.toml \
  --evidence-id ci-tests-abc123 \
  --kind test_result \
  --issuer ci \
  --key-id ci-hmac-v1 \
  --status passed \
  --repository-id ix-blackfox \
  --revision abc123 \
  --payload-json '{"suite":"protected-branch","passed":true}'
```

Human approvals use the exact subject digest and a human-shaped payload:

```json
{
  "decision": "approve",
  "reviewer_kind": "human",
  "reviewer_id": "maintainer.one"
}
```

## Local integration proof

Run:

```bash
PYTHONPATH=src python scripts/run_wave14_live_gateway_ci.py --root .
```

The proof starts a real local upstream HTTP server and a real BlackFox gateway.
It then checks the critical live paths:

1. a request with no configured agent credential is rejected and upstream call
   count remains `0`
2. an MCP request with a hostile browser `Origin` is rejected before forwarding
   and upstream call count remains `0`
3. an authenticated out-of-scope `src/` write is blocked and upstream call count
   remains `0`
4. an authenticated in-scope `docs/` write without required evidence is blocked
   and upstream call count remains `0`
5. the same in-scope MCP write with valid CI evidence and exact target-bound,
   single-use human approval reaches the real upstream and produces a real file
   write
6. replaying that human approval is rejected with HTTP `409` and produces no new
   upstream invocation
7. an HTTP API invocation with its own exact target-bound approval reaches the
   same real upstream and produces another real file write
8. unauthenticated receipt inspection is rejected, operator-authenticated receipt
   verification succeeds, and the receipt chain is independently reverified

The CI proof is synthetic/local by design, but the enforcement, networking,
evidence verification, upstream side effect, and receipt persistence are real.

## Explicit limits

Wave 14 does not claim:

- production readiness or high availability
- OIDC/OAuth/IAM/Entra/Okta identity integration
- mTLS workload identity
- KMS/HSM/Sigstore signing
- an external transparency log or trusted timestamp
- unbounded SSE/subscription proxying
- deployment authorization, compliance certification, FedRAMP, ATO, or cATO
- AWS, DoD, or any other third-party approval or endorsement

Those boundaries are intentionally stated so the live enforcement claim remains
narrow, testable, and real.
