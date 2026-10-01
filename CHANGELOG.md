# Changes

## 0.4.1, Wave 16.1, 2026-10-01

Fix normal signed-append history replay, move signing outside SQLite transactions, accept valid retained-checkpoint prefix extensions, validate denial semantics and define both canonicalization profiles. Add 50 regression cases, fixed byte/hash vectors, a reproducible original-source benchmark and Linux Python 3.11/3.12/3.13 release evidence. External commits/policy changes conservatively replay history; sustained multiwriter scalability, Windows execution, remote CI, live external services and human personal public-key approval signatures remain outside the executed validation.

## 0.4.0, Wave 16, 2026-09-30

Adds required signed pre-dispatch authorizations and linked outcome receipts to configured live gateways; DSSE public verification with pinned keys, strict revocation and independently retained checkpoint comparison; encrypted local software keys, AWS KMS and PKCS11 adapters; explicit Cosign signing/verification; public schemas, live local socket proof, security tests and Linux/Windows CI configuration. Rejects duplicate/non-finite/surrogate JSON before HTTP dispatch. Preserves legacy unsigned configurations and existing identity/evidence controls.

Live cloud, physical hardware, Sigstore issuance and remote CI were not executed in this handoff. No compliance or production performance claim is introduced.
