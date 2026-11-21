# Wave 19 Closed-Loop Verification

A Wave 19 operation carries a versioned change reference, an immutable execution plan, acceptance criteria, and separately defined rollback criteria. The gateway binds their digest to the operator-approved snapshot and to every signed step authorization. A successful provider response records transport status. The verification gate waits for independently signed evidence about what happened.

## Configure the gateway

Start with the [governed operations configuration](../examples/wave18/blackfox.gateway.toml). Add the following TOML table under the existing autonomy configuration. Paths are relative to the gateway configuration file.

```toml
[autonomy.verification]
provider = "trust/provider.json"
test = "trust/test.json"
simulation = "trust/simulation.json"
```

Each file uses the Wave 16 public trust-policy format. Use distinct signing domains and distinct public keys across all three roles and the gateway authority. Provision those policies out of band. Give the provider observer read-only access to actual provider state and keep its private key and read credential separate from agent credentials and the gateway's write credential. Isolate the test and simulation signers from the proposing agent and the gateway as well. Use separate operator credentials and limit access to the operation database and evidence endpoints.

With the table enabled, managed tools require Wave 19 operations. Existing Wave 18 records can still be inspected and reconciled, but legacy plans cannot start or dispatch new effects through these managed tools. Gateways without the table retain the Wave 18 behavior. Wave 19 uses the same managed REST mutation routes and the same pre-dispatch controls. The Wave 17 named MCP integration remains available through its existing path.

The source pins and the evidence age in effect at proposal are bound into the operation. Changing a pinned source identity, connector scope, or freshness window blocks execution under that proposal. Source key revocations are checked against the currently supplied trust policies. Use synchronized clocks and protect the signing and trust configurations.

## Operation API

Send JSON objects by POST to `/v1/operations/<action>`. Agent actions use the existing federated or configured static agent credentials. Operator actions require the gateway operator credential. For exact-subject approval and per-step evidence, use the [Wave 18 authority protocol](wave18-governed-autonomy.md).

| Action | Actor | Request fields |
| --- | --- | --- |
| `propose-verification` | Agent | `plan`, `contract` |
| `propose-followup` | Agent | `plan`, `parent_operation_id`, `mode`, `change` |
| `inspect`, `conditions`, `approve`, `suspend` | Operator | Existing operation request fields |
| `subject`, `dispatch` | Assigned agent | Existing step request fields |
| `verification-target` | Operator | `operation_id`, `requirement_id` |
| `verification-evidence` | Operator | `operation_id`, `requirement_id`, `envelope` |
| `verification-assess`, `verification-chain`, `verification-export` | Operator | `operation_id` |
| `verification-unresolved` | Operator | `after` (empty string initially), `limit` (1–50) |
| `verification-fail` | Operator | `operation_id`, `epoch`, `assessment_digest`, `reviewer`, `reason` |
| `verification-close` | Operator | Same fields as `verification-fail`, plus `decision` |
| `events` | Operator | `operation_id`, `after` (sequence cursor) |

The contract uses `schema_version: "wave19.requirements.v1"`. The `change` object contains `id`, integer `version`, `summary`, and `artifact_sha256`. Each entry in `requirements` and `rollback_requirements` contains `id`, integer `version`, `description`, `step_id`, `source`, `check`, and an `expected` JSON object. The `source` selects one configured trust role. The `check` identifies the collector's procedure. Each plan step requires exactly one provider criterion whose expected value equals the plan's expected outcome. Rollback criteria must include a provider observation matching each step's declared recovery outcome. Add test or simulation criteria whenever those checks are required. The gateway compares canonical JSON exactly, including the difference between Boolean and numeric values.

1. Propose a plan and contract. The operator reviews the plan, criterion versions, source identities, rollback obligations and current conditions, then approves the snapshot. Each assigned agent separately obtains the exact-subject evidence required by its route before dispatch.
2. Get a target for each criterion after its attempt has a signed authorization. The target contains the exact subject, operation and plan digests, change, criterion, epoch, request ID, authorization receipt ID, and earliest acceptable observation time. The collector correlates the resource and actual provider read with this attempt. For tests and simulations, the collector runs the named check and retains its output.
3. Submit a DSSE envelope signed by the configured role using the domain `application/vnd.ix-blackfox.verification-evidence.v19+json`. Its signed body contains `target_digest`, `observed_at` (ISO 8601 with offset), `artifact_sha256` (raw output bytes), `status` (`pass` or `fail`), and `value` (the actual JSON result). The existing `SigningController.envelope` produces this format. [The executable collector](../examples/wave19/observe.py) shows the protocol.
4. Assess the operation. A step satisfies the dependency gate only when all its criteria pass with current, verifiable evidence. A missing or stale result keeps the assessment pending. A valid mismatch, signed failure, or conflicting result fails the operation. A replay of the same semantic result leaves the original evidence and its timestamp in place. An operator may declare an unresolved attempt failed with a reason. A conditions change or suspension invalidates the current evidence epoch and requires renewed observation. Recorded failures survive restart and require a separate follow-up.
5. Propose a follow-up for an open failure. A remediation inherits the failed operation's criteria. A rollback inherits its preapproved rollback criteria. Both retain the original repository and connector scope and require new snapshot approval, exact step evidence and signed dispatch authority. The parent failure is available as feedback in the child assessment. The operator selects at most one follow-up through approval. Each verified follow-up must pass all inherited criteria and receive its own signed closure. An unresolved follow-up can itself be declared failed and linked to another response, up to four operations in the chain.
6. Close from the exact assessment digest. Use `verified` for a directly verified operation or `followup` after the selected child closes with current verified evidence. Use `abandoned` for unresolved work that is being closed without a success claim. A selected child must also be closed as abandoned before the parent can be abandoned. Evidence or child-closure changes require a fresh assessment. The gateway signs the review and retained proof with its authority signer.

The operation journal keeps proposal, approval, reservation, evidence, failure and closure events. The unresolved endpoint scans open operations in identifier order. Follow `next_after` until null, including when a filtered page is empty. Operation abandonment records the decision and any retained attempts. It confers no recovery or verification status.

## Inspect and independently verify

```console
blackfox verification assess change-19 --gateway https://gateway.example.org
blackfox verification chain change-19 --gateway https://gateway.example.org
blackfox verification unresolved --gateway https://gateway.example.org
blackfox verification events change-19 --gateway https://gateway.example.org --after 0
blackfox verification export change-19 --gateway https://gateway.example.org --output change-19.json
blackfox verification verify change-19.json --operation change-19 --authority trust/authority.json --provider trust/provider.json --test trust/test.json --simulation trust/simulation.json
```

Online CLI commands read the operator token from `BLACKFOX_OPERATOR_TOKEN` or the variable named by `--token-env`. Use HTTPS for a remote gateway. Loopback HTTP is available for local operation. The export command creates a new file. Treat exported plans, observations and reviewer labels as operational data.

Use `ix_blackfox.verification.proof.verify_bundle` for programmatic detached verification. Provide independently obtained public trust policies and the expected operation ID. The verifier checks the signed closure and descendant links, matches signed authority receipts to their approved plans and attempt identifiers, verifies each source's evidence, and recomputes the acceptance verdict. The returned closure hash can be compared with an externally retained copy. The CLI exits 0 for a verified result with current evidence, 1 for a valid historical or abandoned result without current verification, and 2 for an invalid or unreadable proof. A `rolled_back` closure reports the verified recovery criteria, while the signed parent record preserves the original failure.

## Verification boundary

Verification is a time-bounded assessment of the evidence supplied by trusted collectors. The gateway verifies key provenance, target binding and observed values. Collectors remain responsible for genuinely reading the protected resource and retaining artifacts with the signed hashes. A valid signature cannot prove that a compromised collector performed its check. Conflicts submitted before closure are retained. Changes outside the observed interval require another operation or observation before a new closure. A previously signed closure remains a historical record when its evidence ages out.

The closure bundle carries the final assessment and signed authorization receipts. Use the operation journal and existing authority verification commands to inspect earlier epochs, pre-dispatch evidence references and the full authority receipt stream. Reviewer names are gateway-recorded operator assertions backed by the authenticated operator endpoint and gateway signature. Individual human public-key signatures require a separate approval system. SQLite durability and gateway-enforced routing remain subject to the deployment and storage boundaries of Waves 17 and 18.
