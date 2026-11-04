# Changes

## 0.5.0, Wave 17, 2026-11-04

Add named native GitHub Check Run, Jira issue, JSON HTTP and MCP tool connectors. Bind destination contracts into exact-subject authority; isolate outbound credentials; add explicit service-write capability mapping. Require signed authorization and durable scoped request reservations before mesh dispatch. Verify duplicate response bytes against signed outcomes. Preserve ambiguous requests across restarts without automatic mutation retries.

Add a cursor-backed signed-receipt CloudEvents relay with ordered delivery, leased workers, bounded backoff, attempt limits, dead-event recovery and sink-contract pinning. Add real local HTTP provider/audit proof, negative and concurrency tests, operator CLI, configuration, protocol documentation and Ubuntu/Windows CI. Retain the Wave 16.1 signing/verification implementation and prior control layers. Correct the runtime directory ignore pattern so source packages remain trackable in fresh checkouts.


## 0.4.1, Wave 16.1, 2026-10-01

Fix normal signed-append history replay, move signing outside SQLite transactions, accept valid retained-checkpoint prefix extensions, validate denial semantics and define both canonicalization profiles. Add 50 regression cases, fixed byte/hash vectors, a reproducible original-source benchmark and Linux Python 3.11/3.12/3.13 release evidence. External commits/policy changes conservatively replay history; sustained multiwriter scalability, Windows execution, remote CI, live external services and human personal public-key approval signatures remain outside the executed validation.

## 0.4.0, Wave 16, 2026-09-30

Adds required signed pre-dispatch authorizations and linked outcome receipts to configured live gateways; DSSE public verification with pinned keys, strict revocation and independently retained checkpoint comparison; encrypted local software keys, AWS KMS and PKCS11 adapters; explicit Cosign signing/verification; public schemas, live local socket proof, security tests and Linux/Windows CI configuration. Rejects duplicate/non-finite/surrogate JSON before HTTP dispatch. Preserves legacy unsigned configurations and existing identity/evidence controls.

Live cloud, physical hardware, Sigstore issuance and remote CI were not executed in this release. No compliance or production performance claim is introduced.
