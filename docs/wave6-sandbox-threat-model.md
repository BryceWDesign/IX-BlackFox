# Wave 6 Sandbox Threat Model

## Purpose

Wave 6 adds a hardened-execution-oriented sandbox evidence layer to IX-BlackFox.

The purpose is not to claim production security certification. The purpose is to make AI-assisted repair/test execution more bounded, inspectable, and reviewable by creating evidence around:

- where execution happened
- what profile controlled execution
- what command was requested
- what workspace was staged
- what egress policy applied
- what artifacts were produced
- what receipts were generated
- what adversarial checks passed
- what signatures were attached to artifacts

## Primary trust boundary

The primary trust boundary is between untrusted AI-assisted proposals and reviewable engineering execution.

IX-BlackFox assumes that model output may be wrong, incomplete, maliciously influenced, prompt-injected, stale, or unsafe.

A model may propose. It may not approve itself. It may not bypass policy. It may not become the authority that makes a change merge-ready.

## Assets protected

Wave 6 is designed to protect or account for the following assets:

| Asset | Protection goal |
|---|---|
| Host filesystem | Prevent sandboxed work from casually mutating host files outside declared workspaces |
| Source tree | Stage source into controlled workspace paths and keep declared source mounts read-only in container execution |
| Secrets | Do not inherit host environment variables by default |
| Network boundary | Deny direct egress by default and record egress decisions |
| Evidence artifacts | Bind artifacts to SHA-256 digests, byte sizes, head SHA, manifests, receipts, and signatures |
| Human review authority | Prevent model-only or self-approval from satisfying review gates |
| CI evidence | Bind CI evidence and sandbox reports to a specific PR head SHA |
| Auditability | Preserve deterministic receipts, manifests, and reports for review |

## Threat assumptions

Wave 6 assumes:

- AI-generated code may attempt unsafe actions.
- AI-generated commands may attempt network egress.
- Repository content may include prompt-injection-like instructions.
- Tests may produce misleading or incomplete evidence.
- Artifacts may be stale, empty, tampered with, or produced for the wrong commit.
- Environment variables may contain sensitive values.
- Symlinks and path traversal can be used to escape intended workspace boundaries.
- Local execution without sandboxing is not a hardened security boundary.
- A container backend improves isolation, but does not equal certification.

## Out of scope

Wave 6 does not claim to solve:

- malicious kernel escape
- malicious Docker daemon compromise
- hostile host operating system compromise
- side-channel attacks
- full supply-chain certification
- compliance-grade attestation
- Sigstore/Rekor-backed public transparency
- SLSA compliance
- formal methods proof
- production multi-tenant isolation
- classified or regulated operational deployment

Those belong to later maturity work, hardened deployment architecture, or Wave 9 compliance/audit attestation.

## Implemented controls

### 1. Sandbox profiles

Sandbox profiles define:

- backend kind
- filesystem policy
- network policy
- environment policy
- resource limits
- allowed commands
- denied command fragments
- deterministic profile digest

The profile digest allows later receipts and artifacts to identify the exact sandbox rules applied.

### 2. Isolated workspaces

The workspace manager creates per-run workspace roots and stages declared mounts into those roots.

Controls include:

- rejecting workspace root escape
- rejecting mount source symlinks
- rejecting symlinked output artifacts
- rejecting path traversal
- resolving sandbox paths only through declared mount targets
- collecting output artifacts by digest and byte size
- enforcing artifact byte limits
- cleanup of temporary workspace roots

### 3. Container backend

The container backend builds Docker commands using:

- `--network none`
- `--read-only`
- `--cap-drop ALL`
- `--security-opt no-new-privileges:true`
- `--pids-limit`
- `--memory`
- `--cpus`
- declared bind mounts
- read-only source mount
- writable output and temporary mounts
- explicit environment injection only

The backend intentionally rejects non-deny-all network modes until a stronger proxy/allowlist runtime path is implemented.

### 4. Local-audit backend

The local-audit backend is explicitly not hardened isolation.

It exists for:

- development compatibility
- policy evidence shape testing
- command/result receipt testing
- local validation flows

It must not satisfy hardened Wave 6 evidence gates.

### 5. Egress decisions

The egress guard creates auditable decisions for:

- `deny_all`
- `allowlist`
- `proxy_logged`
- `offline_package_cache`

Default mode is deny-all.

Allowlist and proxy decisions require exact host, protocol, and port matching. Offline package cache mode denies direct sandbox network egress.

### 6. Artifact manifests

Artifact manifests bind output artifacts to:

- workspace ID
- profile ID
- profile digest
- sandbox output path
- artifact paths
- SHA-256 digests
- byte sizes
- deterministic manifest digest

### 7. Sandbox receipts

Sandbox run receipts bind:

- request ID
- request digest
- profile ID
- profile digest
- backend kind
- result status
- command result digest
- network policy digest
- artifact manifest digest when present
- egress audit bundle digest when present
- expected head SHA

Receipt bundles summarize receipt pass/fail status and reject duplicate receipt IDs.

### 8. Signed artifact statements

Wave 6 local signing uses deterministic HMAC-SHA256 statements.

Signed artifact statements bind:

- statement ID
- subject URI
- subject digest
- subject size
- PR head SHA
- signer ID
- algorithm
- created timestamp
- profile digest
- artifact manifest digest
- metadata
- signature

This is local prototype signing. It is not public PKI, Sigstore, Rekor, SLSA, or compliance-grade attestation.

### 9. Adversarial validation

The adversarial harness can validate scenarios such as:

- deny-all egress was denied
- unexpected egress allowance fails the check
- hardened receipt bundles are accepted
- local-audit receipts are rejected
- failed receipt bundles are rejected
- missing artifact manifest digests are rejected
- missing egress audit digests are rejected
- path escape exceptions are raised
- symlink output exceptions are raised
- policy exceptions are raised

### 10. CI evidence generation

Wave 6 CI generates a deterministic sandbox evidence payload that includes:

- adversarial report
- adversarial verification report
- PR evidence artifact representation
- head-SHA binding
- bounded scope note

## Failure model

Wave 6 should fail closed when:

- required sandbox evidence is missing
- required artifact digests are missing
- artifact byte sizes are missing or zero
- evidence is bound to the wrong head SHA
- local-audit is used as hardened sandbox evidence
- receipt bundle fails
- adversarial report fails
- required adversarial scenario kind is missing
- egress audit bundle digest is missing when required
- artifact manifest digest is missing when required
- signed artifact statement verification fails
- signer is unknown or disallowed
- subject digest does not match expected artifact digest
- artifact manifest digest does not match expected manifest digest

## Claim boundary

Accurate claim:

> IX-BlackFox Wave 6 adds a prototype sandbox evidence layer with isolated workspaces, container-based deny-all execution profiles, egress decisions, artifact manifests, sandbox receipts, local signed artifact statements, adversarial validation, and CI evidence generation.

Inaccurate claims:

- “IX-BlackFox is production-ready.”
- “IX-BlackFox is certified secure.”
- “IX-BlackFox is defense-approved.”
- “IX-BlackFox provides autonomous authority.”
- “The model can approve its own repairs.”
- “Local-audit execution is hardened isolation.”
- “Docker flags equal formal sandbox certification.”
- “Local HMAC signatures equal Sigstore/Rekor/SLSA compliance.”

## Future hardening path

Likely future hardening areas include:

- gVisor backend
- Firecracker backend
- egress proxy with logged allowlist enforcement
- offline package cache verification
- stronger artifact signing
- public transparency log integration
- SLSA-aligned provenance
- policy-pack-based compliance reports
- reviewer signoff artifacts
- governance reports

Those map naturally toward Waves 7, 8, and 9 without renumbering the locked roadmap.
