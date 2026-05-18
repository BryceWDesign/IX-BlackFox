# Wave 6 Operator Checklist

This checklist helps reviewers evaluate whether a Wave 6 run should be treated as valid sandbox evidence.

It is not a production security certification checklist.

## 1. Confirm the intended claim

Before reviewing artifacts, confirm the claim is bounded.

Acceptable claim:

> This run produced Wave 6 sandbox evidence for a specific commit using bounded sandbox contracts, egress decisions, artifact manifests, receipts, adversarial validation, and local signed artifact statements.

Reject or correct claims that imply:

- production readiness
- formal certification
- official defense approval
- autonomous authority
- operational deployment readiness
- local-audit hardening
- model self-approval

## 2. Confirm PR head SHA binding

Check that all required evidence is bound to the same PR head SHA:

- PR evidence pack
- CI evidence bundle
- sandbox receipt bundle
- adversarial report
- signed artifact statements
- artifact metadata

Fail closed if any required evidence points to a different head SHA or omits the head SHA.

## 3. Confirm required Wave 5 evidence

The PR evidence pack should include:

- run bundle
- test report
- governance receipt
- reliability report
- CI summary when required
- human approval record
- changed files list
- requested checks list

Required artifacts must include:

- artifact ID
- kind
- URI
- producer
- SHA-256 digest
- byte size
- PR head SHA

Fail closed if required artifacts are missing, empty, unmeasured, or stale.

## 4. Confirm human authority

Review approval evidence:

- at least one required human approval must exist
- model approval is advisory only
- PR author self-approval must not satisfy human approval
- rejected reviews or changes-requested reviews block merge readiness

Fail closed if the only approval is model-generated or self-generated.

## 5. Confirm sandbox backend type

For hardened Wave 6 evidence, allowed backend kinds are:

- `container`
- `gvisor`
- `firecracker`

Current implemented real backend:

- `container`

Do not accept `local_audit` as hardened sandbox evidence.

`local_audit` may be useful for development and evidence-shape testing, but it is not isolation.

## 6. Confirm sandbox profile digest

The sandbox receipt should bind:

- profile ID
- profile digest
- request digest
- network policy digest
- backend kind
- expected head SHA

The profile digest should remain stable for the same sandbox policy.

Fail closed if receipts omit profile identity or profile digest.

## 7. Confirm workspace isolation evidence

Workspace evidence should show:

- declared mounts only
- source staged into `/workspace/src`
- output path staged into `/workspace/out`
- temporary path staged into `/workspace/tmp`
- read-only source intent
- writable paths explicitly declared
- artifact manifest collected from output path
- no symlinked output artifacts
- no path traversal

Fail closed if artifact collection accepts symlinked outputs or path escape.

## 8. Confirm egress control evidence

Default expectation:

- direct network egress is denied

Review egress evidence:

- network mode
- network policy digest
- egress request
- egress decision
- decision status
- matched rule, if any
- reason

For deny-all mode, any allowed egress should fail the adversarial check.

For allowlist or proxy-logged mode, exact host, protocol, and port matching must be required. Direct egress should not be silently allowed.

## 9. Confirm artifact manifest evidence

Artifact manifests should include:

- workspace ID
- profile ID
- profile digest
- collection timestamp
- sandbox path
- artifact count
- total byte size
- artifact paths
- artifact SHA-256 digests
- artifact byte sizes
- deterministic manifest digest

Fail closed if artifact manifest digest is missing when required.

## 10. Confirm sandbox run receipts

Receipt bundles should include:

- at least one receipt
- no duplicate receipt IDs
- pass/fail summary
- expected head SHA
- receipt request ID
- request digest
- profile ID
- profile digest
- backend
- status
- command result digest
- network policy digest
- artifact manifest digest when required
- egress audit bundle digest when required

Fail closed if the receipt bundle failed or contains failed receipts.

## 11. Confirm signed artifact statements

Local signed artifact statements should bind:

- subject URI
- subject SHA-256 digest
- subject byte size
- head SHA
- signer ID
- signing algorithm
- timestamp
- profile digest when applicable
- artifact manifest digest when applicable
- signature

Verification should fail closed on:

- unknown signer
- disallowed signer
- invalid signature
- head SHA mismatch
- subject digest mismatch
- artifact manifest digest mismatch

Scope reminder: local HMAC-SHA256 signing is prototype-local signing, not public PKI or Sigstore compliance.

## 12. Confirm adversarial validation

The adversarial report should include required scenario kinds such as:

- deny-all egress
- receipt bundle acceptance
- receipt bundle rejection
- path escape block
- symlink block

Additional useful scenarios:

- output-size policy block
- timeout/resource policy block
- local-audit rejection
- missing artifact manifest rejection
- missing egress audit rejection

Fail closed if required scenarios are missing or failed.

## 13. Confirm CI evidence

Wave 6 CI should run:

- sandbox tests
- sandbox receipt evidence tests
- sandbox adversarial evidence tests
- Wave 6 CI integration tests
- Wave 6 CI evidence generator script

The CI evidence payload should include:

- generated timestamp
- wave value
- head SHA
- pass/fail result
- adversarial report
- adversarial verification
- adversarial artifact
- scope note

Fail closed if the payload reports `passed: false`.

## 14. Review public wording

Use disciplined wording.

Acceptable:

> IX-BlackFox Wave 6 adds a prototype sandbox evidence layer with isolated workspaces, deny-all container execution profiles, egress decisions, artifact manifests, sandbox receipts, local signed artifact statements, adversarial validation, and CI evidence generation.

Avoid:

- “production secure”
- “certified”
- “military approved”
- “autonomous authority”
- “self-improving without human review”
- “unbreakable sandbox”
- “guaranteed safe”
- “compliance-ready”

## 15. Final reviewer decision

A reviewer should only treat Wave 6 evidence as acceptable when:

- required Wave 5 evidence passes
- required human approval exists
- CI evidence passes
- sandbox receipt evidence passes
- adversarial report evidence passes
- artifact identity is digest-bound
- sandbox evidence is head-SHA-bound
- local-audit is not used as hardened evidence
- signed artifact statements verify when required
- claim wording remains bounded

If any required element is missing, stale, failed, or overclaimed, block merge readiness.
