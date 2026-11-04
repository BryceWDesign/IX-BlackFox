# Wave 17: Enterprise Integration Mesh

Version 0.5.0 extends the signed authority gateway with named enterprise destinations and a durable audit relay. Consequential requests still require registered identity, delegated scope, revision-bound evidence and configured human approval before dispatch. The example policy requires both CI evidence and exact-subject single-use human approval for every command.

## Implemented interfaces

| Connector kind | Interface | Enforced binding |
| --- | --- | --- |
| `github_check` | GitHub REST Check Runs, `POST /repos/{owner}/{repo}/check-runs` | Fixed repository endpoint; `head_sha` must equal the authority revision; explicit API version |
| `jira_issue` | Jira Cloud REST v3, `POST /rest/api/3/issue` | Fixed tenant endpoint and exact configured project key; native issue fields |
| `json` | Fixed JSON HTTP endpoint using the route method | Fixed destination, literal path, method and exact native payload |
| `mcp` | Governed JSON-RPC `tools/call` over HTTP POST | Named fixed tool server; authenticated initialization/discovery/session routing; governed tool name and arguments; JSON response only |
| Audit sink | CloudEvents 1.0 structured JSON over HTTP POST | Signed receipt as `data`; stable receipt ID; durable per-sink cursor and outbox |

These are implemented request paths, not SDK stubs. `scripts/run_wave17_integration_mesh_ci.py` starts real local HTTP servers, observes public-key signed authorization from an independent database reader before writing provider records, exercises the four connector kinds, denies an unevidenced action, suppresses duplicate command execution, retries an audit outage and verifies the exported receipt bundle in another process.

The local providers implement the relevant wire contracts. No live GitHub App installation, Jira tenant, enterprise MCP server or hosted SIEM was accessed during release validation. Tenant permissions, custom fields, provider rate limits, certificate configuration, access policies and hosted interoperability require deployment qualification. BlackFox does not manufacture a successful CI result from model output or treat a submitted Check Run as verified evidence.

## Authority and dispatch

A route opts in with `connector_id`. Connector public configuration, including its URL, kind, credential environment-variable name, project and API version, is bound into `authority_context_digest` and signed subject metadata. The route already binds tool, method, literal path, repository and evidence policy. Changing these values invalidates previous target-bound approvals. Secret values are never placed in the subject or signed receipt. Credential rotation under the same configured identity does not change the public contract.

For HTTP connectors, arguments are:

```json
{
  "revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "payload": {"message": "approved native service payload"}
}
```

The gateway authorizes the entire arguments object. Only `payload` is sent as the HTTP JSON body. For a GitHub check, `payload` contains `name`, `head_sha` and the intended native check fields. For Jira, it contains `fields`, including `project: {"key": "ENG"}`, `summary` and `issuetype`. Jira description fields use the provider's Atlassian Document Format. Additional tenant-required fields belong in the exact approved payload.

`service_write` maps to the existing `access_network` agent capability with the `write` action. Grants must explicitly scope the repository and tool IDs. Workspace-write grants do not silently grant enterprise-service access. Mesh routes cannot use caller-selected repositories. The supplied policy requires human review; deployments remain responsible for selecting evidence requirements for their risk model.

Before a mesh command is dispatched:

1. Authenticate and evaluate the existing authority boundary, including current evidence and human approval.
2. Validate native connector constraints and isolated outbound credentials.
3. Atomically reserve the scoped request key in the mesh database.
4. Claim single-use evidence and commit signed authorization in the authority database.
5. Revalidate current identity, evidence and trust after signing.
6. Attempt the fixed destination once; commit a linked signed outcome observation.
7. Persist the response reference and original response bytes for verified duplicate retrieval.

Mesh mode requires signed receipts. Existing unsigned Wave 14/15 configurations remain available without opting into the mesh.

## Command idempotency and crash behavior

Every mesh command requires `X-BlackFox-Idempotency-Key`, 1–128 ASCII characters from letters, digits, `_`, `.`, `:`, `-`, starting with a letter or digit. The durable reservation key hashes the agent, connector ID, tool name and supplied key. It is bound to the exact authority subject. The hashed request ID is returned on completed requests and reservation conflicts.

| Condition | Behavior |
| --- | --- |
| First authorized request | Reserve durably and attempt dispatch once |
| Completed duplicate with current valid authority | Verify the retained upstream bytes against the signed outcome, then return the result; `X-BlackFox-Replayed: true` |
| Same key, changed subject | HTTP 409; no dispatch |
| Concurrent duplicate or unresolved reservation | HTTP 409 with `outcome_unknown`; no dispatch |
| Transport failure after attempting dispatch | Linked unknown-outcome receipt; HTTP 502; reservation retained |
| Receipt or cache persistence failure after dispatch | HTTP 503 with `retry_safe: false`; reservation retained |
| Returned upstream HTTP error | Signed observation is retained and cached; no automatic mutation retry |
| Process crash at any stage | Reservation remains; a restart does not automatically repeat the command |

This supplies at-most-one automatic attempt per retained scoped request key. It does not promise exactly-once execution by an arbitrary external system. No atomic transaction spans the mesh database, authority database and external service. A crash can leave a reservation without an authorization, or an authorization without an outcome. The conservative consequence is a request that remains blocked for reconciliation, including cases that never reached the provider.

Inspect the hashed request ID with:

```console
blackfox mesh inspect-request --config examples/wave17/blackfox.gateway.toml --request-id REQUEST_SHA256
```

Use its authorization ID to inspect the signed receipt stream and the provider's own record. A fresh request key requires fresh valid authority and, under the example policy, a new target-bound single-use approval. Do not create a new key until the original provider outcome has been reconciled. There is deliberately no command-reservation reset or automatic command-replay operation.

The mesh database and authority database are trusted durable operational state. Retain them together, restrict filesystem access and coordinate backups. Deleting the mesh database removes request-key memory; signed receipt verification does not recreate lost reservations. Completed caches retain original upstream response bodies and need the same confidentiality controls as the provider data. There is no automatic retention pruning in this release.

## Credentials and network boundary

Credentials come only from operator-configured environment-variable names. GitHub uses a provisioned GitHub App token with the required Checks write permission. Jira `Basic` material is the base64 encoding of the operator's approved account identifier and API token. Token issuance, refresh and provider account lifecycle remain external to BlackFox.

Ingress agent tokens, operator tokens, evidence keys and caller-supplied authorization headers are not forwarded. Reusing ingress/evidence secret bytes as an outbound credential is rejected. Mesh MCP envelopes omit BlackFox identity/evidence `_meta`; configured parameter mirrors and MCP protocol/session headers are the only caller transport metadata forwarded. Unrelated connector credential failures do not block an already running route that has valid credentials. Readiness checks all configured bindings before the server starts.

HTTPS is required. Tests may explicitly permit HTTP only to literal loopback IP addresses. Credentials, query strings, fragments, percent-encoded paths and ambiguous URL paths are rejected in connector URLs. Redirects are never followed. Request bytes and response bytes remain bounded by the gateway configuration; mesh network timeout is separately bounded to at most 300 seconds. Mesh command dispatch has no retry loop.

URL configuration is an operator trust boundary. This is not a general outbound firewall, DNS-pinning service, workload credential issuer or cross-tenant network isolation mechanism. Provider response bodies are returned to the authorized caller and retained for duplicate retrieval; provider responses must not echo secrets.

## Audit relay

The durable signed receipt database is the audit source. Relay synchronization reads bounded, verified stream pages, compares the retained sequence/digest cursor, then transactionally inserts events and advances that cursor in the mesh database. A crash before commit advances neither; after commit the event is durable. This avoids a best-effort network callback inside command execution.

```console
blackfox mesh status --config examples/wave17/blackfox.gateway.toml
blackfox mesh relay --config examples/wave17/blackfox.gateway.toml --limit 100
```

Run `relay` repeatedly using an operator-controlled scheduler or process supervisor. Each invocation synchronizes up to the limit and attempts up to that many deliveries per sink, without blocking sleeps. Exit code 1 identifies a dead event. Pending/backoff events are visible in the returned status; monitor those counts and cursors as well as the process exit code.

Delivery is ordered independently per sink. Workers claim bounded leases before networking. HTTP 2xx acknowledges receipt. Transport errors, 408, 429 and 5xx use bounded exponential backoff; numeric `Retry-After` can extend it to at most one hour. Other responses, including redirects, and exhausted attempt budgets become dead events. A dead event blocks subsequent events for that sink until the operator resolves it. HTTP-date `Retry-After` is not interpreted; exponential backoff still applies.

```console
blackfox mesh requeue-audit --config examples/wave17/blackfox.gateway.toml --sink-id security-events --sequence 1
```

This retries only audit delivery. It cannot re-execute a command. A lost acknowledgment or expired lease can produce duplicate audit deliveries. Receivers must deduplicate the CloudEvent `source` and `id`. Stable event IDs are also supplied as `Idempotency-Key`. The relay verifies stored event content against the signed receipt before delivery. Changing a retained sink URL, credential binding, retry policy or source stream requires a new sink ID; that new sink starts at the beginning of the retained stream.

Event data includes signed decisions, subject metadata, authenticated-principal metadata, evidence references and response digests. It omits raw command arguments and upstream response bodies. Public trust and independently retained checkpoints are still required for independent receipt verification. Receiving an HTTP 2xx does not prove long-term SIEM retention or independent anchoring. Receiver-side lifecycle, immutable storage and access controls remain deployment responsibilities.

Verified paging reuses the existing signed-store verification cache. Startup and independent receipt-writer commits can trigger full history replay; synchronization is not advertised as constant-time across independent writer processes. Slow audit delivery does not hold an authority-database write transaction or block dispatch.

## Named MCP endpoints and transport limits

Connect an MCP client to `/mcp/CONNECTOR_ID`, for example `/mcp/mcp-tools`. The gateway authenticates the client and forwards `initialize`, `notifications/initialized`, `ping` and `tools/list` to that configured MCP server using its separate service credential. Initialization responses preserve `Mcp-Session-Id`; subsequent calls carry that session header to the same server. Tool calls must belong to the selected connector and still pass the full signed authority path, including evidence and the request key. A client cannot select one named endpoint and dispatch a tool configured for another connector.

The existing `/mcp` default upstream retains its configured lifecycle/discovery methods. Mesh tool routes also remain callable there for stateless integrations. Named endpoints avoid sharing a default server's session with another server. Discovery is forwarded to the selected upstream; a tool appearing in its list does not grant invocation authority.

This release accepts JSON-RPC JSON responses over HTTP POST. It does not aggregate discovery across servers, implement SSE streaming or GET subscriptions, proxy DELETE session termination, translate tools into REST payloads, perform upstream OAuth token exchange or route arbitrary MCP methods. Upstream session expiry and identity-token lifecycle remain operator/provider responsibilities.

## Reproduction

```console
python -m pip install -e ".[dev,aws-kms]"
python -m ruff check .
python -m mypy src
python -m pytest -q
python scripts/run_wave17_integration_mesh_ci.py --root .
```

Use an isolated Python environment so sandboxed child test processes can import their test dependencies. The proof writes public receipt/trust/checkpoint artifacts and measured local latency to `.blackfox-artifacts/wave17`. Temporary private keys, tokens, provider records and runtime databases are deleted after the proof. Captured release results are under `validation/wave17`.

The latency measure includes client HTTP, authority/evidence evaluation, synchronous SQLite durability, local Ed25519 signing, provider HTTP and outcome persistence. Evidence issuance occurs outside the timed call. It is a small local experiment, not a production capacity estimate, cloud-signing benchmark, real-time deadline guarantee or HA qualification.

## Protocol references

- [GitHub Check Runs REST interface](https://docs.github.com/en/rest/checks/runs)
- [Jira Cloud REST v3 issues](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/)
- [CloudEvents 1.0.2 HTTP binding](https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/bindings/http-protocol-binding.md)
- [CloudEvents 1.0.2 JSON format](https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/formats/json-format.md)
