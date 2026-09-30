# Wave 16: Cryptographic Authority Receipts and Externally Anchored Trust

Version 0.4.0 adds required public-key signatures to the live Wave 14/15 gateway when `[receipt_signing]` is configured. Missing or invalid configured signing does not downgrade to unsigned receipts. Configurations without that table retain the historical Wave 14/15 receipt format. This is an explicit deployment mode, not a claim that old history has been cryptographically upgraded.

## Execution contract

For each governed, allowed API invocation or MCP `tools/call`, BlackFox evaluates the authenticated principal, delegated scope, registered grant, revision-bound evidence and required human approval. It atomically reserves configured single-use evidence. A SQLite `BEGIN IMMEDIATE` transaction validates the existing signed stream, creates and signs an authorization receipt, checks the signature against the separately provisioned trust policy, and commits it before upstream dispatch. Connections use WAL and `synchronous=FULL`.

After signing, the gateway authenticates the workload again and reevaluates the subject and evidence. Identity changes, revocation, expiration, altered evidence or policy failure stop dispatch. It rechecks the committed authorization against the current public trust policy immediately before dispatch. The original decision remains the one signed in the authorization; the second evaluation checks continuing eligibility. This reduces the delay caused by remote signing. It does not make filesystem evidence, identity policy and network side effects one distributed transaction. A change after the last local check remains a deployment and concurrency concern.

The upstream request carries `X-BlackFox-Authorization-Receipt`. The outcome receipt links the authorization ID and digest and repeats the exact subject, authority decision, principal, evidence digests and reservations. A received response means `response_received`; a transport failure after dispatch means `outcome_unknown`. The historical `executed` field means the gateway received a response after an allowed request. It does not prove arbitrary remote side effects or their success.

Signing or persistence failure before dispatch returns HTTP 503 with `execution_state=not_attempted`. Failure to persist an outcome after dispatch returns 503 with `execution_state=outcome_unknown`, `retry_safe=false` and the committed authorization ID. The independently verified bundle reports unresolved authorizations. Evidence reservations remain consumed. A revalidation failure after authorization also leaves an unresolved authorization; absence of an outcome is not proof that execution did or did not occur. Malformed requests rejected before authority evaluation need not produce a receipt.

MCP discovery and protocol passthrough retain the existing authenticated allowlist. They are not governed tool executions and do not receive action authorization receipts. Restrict direct access to consequential upstream tools so clients cannot bypass the gateway. This release does not install network isolation, TLS, a reverse proxy or an upstream receipt-enforcement agent for you.

## Signed format and independent verification

Each receipt retains the complete gateway subject and decision, the authenticated principal, hashes of evaluated valid evidence, chain sequence and predecessor. A DSSE envelope signs the canonical body under the receipt domain. Checkpoints use a separate DSSE domain. The signed statement also binds deployment, stream, signing key ID, algorithm and signing time. An envelope accepts exactly one signature from the pinned policy; public keys carried by an untrusted bundle cannot establish authority.

| Profile | Encoding and verification |
|---|---|
| Ed25519 | Ed25519 signature over DSSE PAE |
| RSA-PSS-SHA256 | SHA-256, MGF1 SHA-256, 32-byte salt, RSA at least 2048 bits |
| RSA-PKCS1-SHA256 | PKCS1 v1.5 with SHA-256, RSA at least 2048 bits |
| ECDSA-P256-SHA256 | P-256, SHA-256, DER-encoded ECDSA signature |

`encoding.py` defines BlackFox canonical JSON profile v1: sorted string keys, compact UTF-8, Python 3.11+ finite-number serialization, no duplicate keys, no unpaired Unicode surrogates, and integers within ±(2^53−1). It is explicitly not RFC 8785. Cross-language verifiers must reproduce these bytes, especially floating-point values. The DSSE payload contains those exact bytes, so signature verification itself does not require reserializing it. Canonical checks and receipt digest recomputation do. Proof documents are limited to 64 MiB.

Wave 14 subject/decision hashes retain their original JSON digest algorithm for compatibility. Wave 16 receipt hashes use the new canonical profile. Receipt IDs use the full SHA-256 rather than the old truncated identifier. Detached body tampering, recomputation of unkeyed hashes, signature substitution, altered algorithm, wrong domain, reordered or duplicated records and unauthorized outcome links fail verification.

The public verifier needs only the bundle, a separately trusted public-key policy and optionally an independently retained expected checkpoint. It does not need the signing private key, gateway database or evidence HMAC secrets. It verifies the gateway's endorsed identity and evidence evaluation, not the raw JWT signature or the original HMAC evidence independently. Human approval continues to use the existing issuer-bound HMAC evidence mechanism. This release does not make a human reviewer a public-key signer or prove that a real person performed the synthetic demo review.

## What constitutes an external anchor

A signed bundle checkpoint binds the entire receipt list, including signatures, receipt count and head. An independently retained expected checkpoint allows an auditor to reject a previously valid, older snapshot. Re-signing the identical snapshot produces a different envelope but still matches the authenticated expected checkpoint body. Equality compares canonical bytes, including exact JSON types.

A checkpoint copied into the same ZIP is a useful verification fixture. It is not independent retention. An attacker controlling both delivered bundle and checkpoint may substitute a valid older pair. Retain the expected checkpoint in a separate audit store or distribution channel, with access controls independent of the gateway. The verifier does not contact that store or claim latestness by itself. Use `--allow-unanchored` only when accepting this limitation explicitly.

The optional Cosign adapter can verify a Sigstore bundle for the exact exported artifact, expected certificate identity and OIDC issuer, using an independently reviewed trusted-root JSON file and offline inclusion verification. This establishes the artifact attestation represented by that bundle; it does not prove the artifact is the newest gateway stream snapshot. Keep an expected checkpoint if latestness is required. Gateway signing timestamps are not independently trusted timestamps. A working provider API is not proof of physical HSM custody or production authorization.

## Quick local proof

From the repository root, in PowerShell:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,aws-kms]"
.\.venv\Scripts\python.exe scripts/run_wave16_crypto_authority_ci.py --root .
.\.venv\Scripts\python.exe -m ix_blackfox.authority_crypto.cli verify --bundle .blackfox-artifacts/wave16/authority-bundle.json --trust-policy .blackfox-artifacts/wave16/trust-policy.json --checkpoint .blackfox-artifacts/wave16/external-checkpoint.json
```

The demo provisions fresh local IdP and encrypted Ed25519 keys in a temporary directory, uses real loopback sockets, and checks committed signed authorization through a separate SQLite connection before each of two actual file writes. It exercises API, MCP, authentication/evidence/scope denial, single-use replay, signer outage, identity revocation, tamper and truncation rejection. The private key, evidence and database are removed before a separate Python process verifies the public bundle. Four public JSON artifacts remain under `.blackfox-artifacts/wave16`. Demo trust is ephemeral local trust, not your organization's provisioned trust. The reviewer and CI evidence are explicitly synthetic fixtures.

## Provision an operator-controlled local signer

Use a fresh receipt database for a new signed stream. Preserve historical unsigned receipts as historical evidence; do not re-sign them as though pre-dispatch signatures existed at the time. Choose deployment and stream IDs deliberately. Any table configured with a missing field or unknown provider is rejected.

Set `BLACKFOX_AUTHORITY_KEY_PASSWORD` in your process environment using your organization's secret-management mechanism, with at least 16 UTF-8 bytes. Do not put it in TOML, command arguments or Git. Generate keys:

```powershell
.\.venv\Scripts\python.exe -m ix_blackfox.authority_crypto.cli keygen --directory receipt-keys --password-env BLACKFOX_AUTHORITY_KEY_PASSWORD --key-id operator-ed25519-1 --deployment-id blackfox-local --stream-id signed-stream-1
```

On POSIX the key and directory are owner-only. On Windows, independently restrict ACLs to the gateway service account and trusted administrators; POSIX mode bits do not establish Windows ACL security. The loader requires encrypted PKCS8 and a password environment variable. Local encrypted software keys are not hardware custody.

`examples/wave16/blackfox.gateway.toml` provides a complete local signer configuration, using `receipt-keys` relative to that example directory. Run keygen from that directory if using its relative paths, or adjust paths intentionally. Its JWKS is deliberately empty until an operator provisions a trusted IdP key. Real agent identity, trusted issuer keys, operator credentials, upstream addresses, revision evidence and human approval must be configured for your deployment. The example is not represented as ready for production without these bindings.

```toml
[receipt_signing]
provider = "local"
key_id = "operator-ed25519-1"
algorithm = "Ed25519"
trust_policy = "receipt-keys/trust-policy.json"
private_key = "receipt-keys/authority-signing-key.pem"
password_env = "BLACKFOX_AUTHORITY_KEY_PASSWORD"
```

Distribute the public policy over an authenticated channel independent of receipt delivery. Its SPKI SHA-256 fingerprint detects accidental key mismatch; it is not a substitute for authenticating the source of the policy. Auto-generated policies expire after one year; review and renew them before expiration. The verifier rejects expired current policies and currently revoked signing keys even for old signatures. Keep an appropriate separately controlled archival trust policy when authorized historical verification is required.

## AWS KMS and PKCS#11 providers

Install `.[aws-kms]` or `.[hsm]` for the selected provider. Provision an asymmetric signing key and obtain its public key through an authenticated administrative procedure. Write the public PEM to `authority-public.pem`, then create a policy with `trust-init`. For a configured RSA-PSS key:

```powershell
.\.venv\Scripts\python.exe -m ix_blackfox.authority_crypto.cli trust-init --public-key authority-public.pem --algorithm RSA-PSS-SHA256 --key-id operator-kms-1 --deployment-id blackfox-service --stream-id signed-stream-1 --output authority-trust.json
```

Replace the local `[receipt_signing]` table with exactly the fields for the selected provider. Actual cloud and hardware bindings are operator input; no fictional account ARN or token is shipped as a working service.

| Provider | Required fields in addition to provider, key_id, algorithm, trust_policy |
|---|---|
| `aws_kms` | `kms_key_arn`, `aws_region` |
| `pkcs11` | `module_path`, `token_label`, `private_key_label`, `pin_env` |

KMS supports RSA-PSS-SHA256, RSA-PKCS1-SHA256 and ECDSA-P256-SHA256 in this release. It requires an immutable key ARN, not an alias, and calls `Sign` with a SHA-256 digest of DSSE PAE and `MessageType=DIGEST`, avoiding the raw-message size limit. It checks the returned key ARN, signing algorithm and signature against the pinned public key. Credentials use the normal AWS SDK credential chain. Grant the service only the intended key's signing permission. Connection and read timeouts are bounded, with two total SDK attempts. Review endpoint configuration, IAM, credential isolation and audit logging independently.

The PKCS#11 profile uses RSA-PKCS1-SHA256, the specified native module and token/key labels, and `SHA256_RSA_PKCS`. The private key must report `SENSITIVE=true` and `EXTRACTABLE=false`. PIN material comes from the named environment variable; token sessions close after signing. The pin never appears in configured command arguments or error output. These attributes enforce the requested software contract but do not authenticate a vendor device, its FIPS status or the physical key lifecycle. Verify those properties separately.

Test external signing after configuring the actual service:

```powershell
.\.venv\Scripts\python.exe scripts/validate_wave16_external_services.py --config deployment.gateway.toml --output external-services-validation.json
```

Unrequested services remain `NOT_RUN`. With no requested services, the script returns nonzero. A successful provider round trip establishes that the configured provider produced a signature matching the independently pinned key; physical custody remains unestablished by that script.

## Export, retain and verify

```powershell
.\.venv\Scripts\python.exe -m ix_blackfox.authority_crypto.cli export --config deployment.gateway.toml --output authority-bundle.json --checkpoint-output expected-checkpoint.json
.\.venv\Scripts\python.exe -m ix_blackfox.authority_crypto.cli verify --bundle authority-bundle.json --trust-policy authority-trust.json --checkpoint expected-checkpoint.json
```

Export verifies stored indexes, signatures, chain and evidence-claim records before writing a snapshot. The bundle and checkpoint output paths must be distinct new files. If a filesystem write fails after one output is written, treat the export as failed and inspect partial files before retrying with fresh paths. Move the expected checkpoint to independently controlled retention. Verification failures return nonzero machine-readable JSON.

For a deliberate integrity-only check, supply `--allow-unanchored`. The result explicitly says latestness is not established. Operator HTTP lookup and verification retain the existing operator credential boundary.

## Optional Sigstore attestation

Install and review Cosign 3.x independently. Provision a trusted-root JSON and determine the exact expected certificate identity and OIDC issuer. The adapter uses the absolute executable path provided by the operator, bounded subprocess timeouts and no shell. It enables neither insecure options nor verification bypass flags. Tests in this release validate the command contract through fixtures; no Cosign binary or public issuance was executed in this handoff.

Configure these process environment variables with actual reviewed values: `BLACKFOX_COSIGN_PATH`, `BLACKFOX_SIGSTORE_ROOT`, `BLACKFOX_SIGSTORE_IDENTITY`, `BLACKFOX_SIGSTORE_ISSUER`. Use a non-interactive `SIGSTORE_ID_TOKEN` or the GitHub Actions OIDC environment supplied by an authorized job. This is an explicit operator action: signing may contact the configured Sigstore service and create a transparency log record. Review artifact sensitivity before doing so.

```powershell
.\.venv\Scripts\python.exe -m ix_blackfox.authority_crypto.cli sigstore-sign --bundle authority-bundle.json --trust-policy authority-trust.json --output authority-bundle.sigstore.json --cosign $env:BLACKFOX_COSIGN_PATH --trusted-root $env:BLACKFOX_SIGSTORE_ROOT --certificate-identity $env:BLACKFOX_SIGSTORE_IDENTITY --oidc-issuer $env:BLACKFOX_SIGSTORE_ISSUER
.\.venv\Scripts\python.exe -m ix_blackfox.authority_crypto.cli verify --bundle authority-bundle.json --trust-policy authority-trust.json --sigstore-bundle authority-bundle.sigstore.json --cosign $env:BLACKFOX_COSIGN_PATH --trusted-root $env:BLACKFOX_SIGSTORE_ROOT --certificate-identity $env:BLACKFOX_SIGSTORE_IDENTITY --oidc-issuer $env:BLACKFOX_SIGSTORE_ISSUER
```

The signing adapter verifies the resulting bundle against the configured identity before publishing it. It refuses interactive login without a configured non-interactive identity token source. Supply these same files and identity values to `validate_wave16_external_services.py` using its `--sigstore-artifact` and `--sigstore-bundle` options to produce an operator-run validation report.

## Rotation, revocation and recovery

For ordinary rotation, independently provision the new public key, add it to the same stream's policy, then switch the signing provider/key binding. Keep the old key trusted for authorized history. Mixed-key history is verified against the current policy. Key IDs must be unique.

Strict current revocation invalidates prior receipts signed by the revoked key, even if their signed timestamps precede revocation. The signed store then refuses append/export under that policy. Freeze that stream, retain evidence of the revocation and begin a separately identified new stream under an independently provisioned key. This behavior deliberately favors refusal over silently accepting revoked signatures. Archival acceptance requires an explicitly selected, separately controlled policy and a documented incident decision; do not silently change current trust to make validation green.

SQLite transactions roll back if signing or candidate verification fails. Claims reserved before a failed authorization remain consumed. Restoring a backup cannot by itself establish the latest stream head; compare against separately retained checkpoints and reconcile unresolved authorizations with upstream observations. The system has no automatic side-effect rollback or safe automatic retry for unknown outcomes.

## Validation and limits

The release includes public JSON schemas, strict typing, adversarial tests, real local socket/file-write proof and a GitHub Actions matrix for Ubuntu/Windows and Python 3.11–3.13. Local test evidence is recorded in `VALIDATION_REPORT.md`. Remote GitHub CI is configured but not executed here. Cloud signing, physical HSM use and Sigstore issuance are `NOT_RUN` in the shipped ledger.

Full signed history is validated inside each append transaction. This provides a simple auditable invariant with cost growing with stream length. Throughput, long streams, multiprocess contention, crash/power-loss behavior, backup/restore, production IdP/cloud/hardware interoperability and high availability require deployment testing. There is no production benchmark, retention service, independently witnessed deployment trust root, trusted timestamp authority, FIPS certification, FedRAMP approval, ATO/cATO or claim that a signed gateway statement is necessarily true. The threat boundary assumes the gateway's signing authority and independently managed trust policy are protected.

## Primary interface references

- [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
- [AWS KMS Sign API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html)
- [Python PKCS#11 API](https://python-pkcs11.readthedocs.io/en/latest/api.html)
- [Sigstore blob verification](https://docs.sigstore.dev/cosign/verifying/verify/)
- [Cosign verify-blob command](https://github.com/sigstore/cosign/blob/main/doc/cosign_verify-blob.md)
