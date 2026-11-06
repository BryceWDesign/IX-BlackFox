# Wave 18 Governed Autonomy

Version 0.6.0 coordinates consequential engineering work as an operator-approved plan. A registered agent proposes the plan. Assigned agents request specific steps. An operator approves the current conditions and a human review issuer signs each exact action. The signed authority gateway enforces the operation contract immediately before sending a managed request. Downstream work requires separately issued evidence of what the provider actually did.

## Configure the gateway

Start with [the two-agent template](../examples/wave18/blackfox.gateway.toml). Provision the gateway's receipt signing key, separate operator and agent credentials, evidence issuer keys, and provider credential. Replace the sample provider URL and route contracts with provisioned endpoints. Use `blackfox gateway check --config FILE` and `blackfox gateway serve --config FILE`. The default listener is loopback. Put authenticated remote traffic behind a trusted TLS endpoint.

`[autonomy]` requires a dedicated SQLite database, an explicit list of managed tool names, an observation issuer and key ID, and a freshness bound in seconds. The observation key must be configured under `[[trusted_issuers]]` for `operation_observation` alone. Give it to a separate evidence producer that reads provider state with read-only credentials. Keep that key, the human review key, the operator credential, and agent credentials separate. An observer needs only its own signing secret and the target supplied by the operator. The gateway needs the corresponding verification material because these artifacts use the existing HMAC evidence format.

Managed tools are named Wave 17 REST mutation routes backed by signed receipts, revision-bound evidence, and exact-subject single-use human approval. Unmanaged routes preserve their previous behavior. The gateway rejects direct managed calls at `/v1/invoke` and `/mcp` and refuses exact destination aliases on unmanaged REST routes at configuration time. Restrict provider credentials and network paths so agents cannot reach the same mutation through a separate gateway, alternate DNS alias, MCP tool or provider endpoint. Wave 18 operation dispatch supports the JSON, GitHub Check Runs, and Jira REST connector contracts. Named MCP remains available through the Wave 17 interface for unmanaged work.

## Propose, review, and dispatch

All operation endpoints take a JSON object over HTTP POST under `/v1/operations/`. Use the configured agent identity (static token or federated bearer according to gateway configuration) for agent calls. Use `X-BlackFox-Operator-Token` for operator calls. Unknown request fields are rejected.

| Endpoint | Caller | Request fields |
| --- | --- | --- |
| `propose` | Registered agent | `operation_id`, `expires_at`, `max_attempts`, `max_cost`, `steps` |
| `inspect` | Operator | `operation_id` |
| `conditions` | Operator | `operation_id`, current `epoch`, complete `facts` object, `valid_until`, `reason` |
| `approve` | Operator | `operation_id`, exact current `snapshot_digest`, `reviewer` |
| `subject` | Assigned agent | `operation_id`, `step_id` |
| `dispatch` | Assigned agent | `operation_id`, `step_id`, `evidence_refs` |
| `observation-target` | Operator | `operation_id`, `step_id` |
| `observe` | Operator | `operation_id`, `step_id`, `evidence_ref` |
| `suspend`, `close` | Operator | `operation_id`, current `epoch`, `reason` |
| `events` | Operator | `operation_id`, `after` sequence (0 for first page, up to 50 results per call) |

A plan seals 1–32 unique steps and a dependency graph with no cycles. Each step contains `step_id`, `agent_id`, `tool_name`, exact Wave 17 `arguments`, a `depends_on` array, a `preconditions` object, an `expected_outcome` object, integer `cost`, and `recovery`. The recovery object holds the operator `instruction` and the `expected_outcome` to verify after remediation. Use a fresh offset-bearing expiry no more than 30 days out. Cost measures integer units assigned and reviewed in the plan. The gateway does not meter provider spend. A durable reservation charges both the attempt and cost budgets. Reservations that end in a known pre-transport denial remain charged.

1. Submit a proposed plan with the named agents and exact payloads. An operation ID permanently identifies that proposal in the retained database.
2. Inspect the sealed plan. Submit the current operator-observed facts and an expiry within the configured freshness window. Review the new snapshot and approve its digest.
3. Have the assigned agent fetch its step subject. Use the returned repository, revision, and digest to issue the configured evidence and single-use human approval. The existing `blackfox gateway issue-evidence` command accepts `--target-digest` and `--payload-file`. Obtain the subject from the operation endpoint so the approval binds the plan, epoch, attempt and dependency observations.
4. Dispatch the step with the evidence IDs. BlackFox takes the arguments and identity assignment from the sealed plan, derives the mesh request key, and stores the attempt before Wave 17 signs authorization. It rechecks identity and evidence, the operation snapshot, expiry, conditions, and current dependency observations just before sending. A 2xx upstream response records transport progress.
5. Obtain the observation target. Have the separate observer read the actual provider effect using the request ID and issue a `verified` evidence artifact of kind `operation_observation`, with the returned repository, revision and target digest. The artifact payload is `{"kind":"outcome","value":{...}}`. Submit its evidence ID to `observe`. The gateway requires a retained signed authorization for the observed attempt and compares the actual value against the exact expected JSON. A fresh matching observation can release eligible downstream steps.

The expected and observed objects are compared using BlackFox's canonical JSON bytes. Design these objects around values the observer can independently read. An HTTP acceptance body, an agent assertion, or a CI result alone cannot satisfy the observation gate. The observer is trusted to make accurate assertions about the provider. Replaying a proof for a different attempt, step, operation or epoch fails target verification.

## Suspension, reconciliation, and recovery

Every conditions update and suspension creates a new epoch. It clears plan approval and makes earlier observations unavailable to dispatch, while retaining their audit history. Supply fresh conditions, obtain a new plan approval, and collect new independent observations for retained effects before proceeding. Issue new step approval evidence for the new subject. The operator or a trusted controller must report external condition changes. The freshness limit fails closed when updates stop.

| State or event | Meaning |
| --- | --- |
| `approved` | The operator approved the current snapshot. Each dispatch still needs its own signed evidence and authorization. |
| `reserved` / `authorized` journal events | The durable budget reservation exists. The authorized event links the signed pre-dispatch receipt when available. Neither establishes provider effect. |
| `attempted` | The gateway crossed the transport boundary. Inspect `transport_state` for a response or unknown result. |
| `outcome_unknown` | A retained reservation may have crossed the transport boundary. The gateway will not redispatch the step automatically. |
| `verified` | A fresh observation matches the expected provider state for the current epoch. |
| `mismatch` | The observed state differs. New effects pause until reconciliation. |
| `recovered` | A separate observation confirms the recovery obligation. Steps depending on the original expected outcome remain blocked. |
| `observation_stale` | The epoch, evidence validity or freshness changed. Submit new evidence under a new epoch. |

If a request loses its response, retain the attempt and use the provider's own state to reconcile it. An unresolved reservation without a signed authorization cannot be reconciled through an observation target. An operator can close the operation after reviewing the retained state. Closing is irreversible for that operation ID and blocks future dispatch. Keep any necessary follow-up work in a separately approved plan after confirming provider state.

If the observed effect diverges, follow the recovery instruction through the deployment's authorized operator procedures. The observer then submits `{"kind":"recovery","value":{...}}` for the same attempt. BlackFox validates the recovery value against the plan. It does not run implicit compensation, replay a mutation, or mark a recovered step as a successful dependency. Recovery may be documented even when normal dispatch is suspended.

## Durability and deployment

Keep the operation, mesh, and signed authority databases together with the evidence directory. Restrict access and take coordinated backups. The operation journal is trusted local operational state. The gateway's signed authorization includes the operation context and can be publicly verified under the Wave 16 trust contract. The observation artifact uses the separate HMAC evidence contract. It requires a trusted issuer and is not itself a public-key provider attestation.

The SQLite write gate serializes an operation mutation with the provider call across gateway workers sharing the local database. A suspension that commits before this gate prevents transport. A suspension racing an already-started request cannot undo it. While a provider request holds the gate, another operation write may wait or return unavailable. Do not treat an unavailable suspension request as committed. Inspect the epoch and state before proceeding.

Transport, operation state, and signed receipt persistence are separate failure domains. The conservative result of an interrupted write can be an unknown outcome even when the provider received nothing. Reservations prevent automatic redispatch of unresolved steps. Arbitrary external systems do not provide exactly-once execution under this contract. This release targets a single deployment with shared local durable storage. Hosted-provider behavior, high availability, automatic detection of all environmental drift, and cross-system rollback require separate deployment work.

## Reproduce the proof

```console
python -m pip install -e ".[dev,aws-kms]"
python -m pytest -q tests/autonomy
python -m ruff check .
python -m mypy src
python -m pytest -q
```

The focused suite uses real gateway and provider HTTP listeners. A separate database reader checks the signed authorization before the provider records a write. An observer separately queries provider state. The suite also exercises duplicate workers, missing evidence, late suspension, dependency invalidation, response loss, restart, and a post-write storage fault. See [the release validation](../VALIDATION_REPORT.md) for measured results.
