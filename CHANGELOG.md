# Changes

## 0.4.0, Wave 16, 2026-09-30

Adds required signed pre-dispatch authorizations and linked outcome receipts to configured live gateways; DSSE public verification with pinned keys, strict revocation and independently retained checkpoint comparison; encrypted local software keys, AWS KMS and PKCS11 adapters; explicit Cosign signing/verification; public schemas, live local socket proof, security tests and Linux/Windows CI configuration. Rejects duplicate/non-finite/surrogate JSON before HTTP dispatch. Preserves legacy unsigned configurations and existing identity/evidence controls.

Live cloud, physical hardware, Sigstore issuance and remote CI were not executed in this handoff. No compliance or production performance claim is introduced.
