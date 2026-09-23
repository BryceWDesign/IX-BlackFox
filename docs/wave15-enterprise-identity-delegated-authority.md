# Wave 15: Enterprise Identity & Delegated Authority

Wave 15 moves IX-BlackFox beyond Wave 14 static ingress credentials and makes a
cryptographically verified workload identity part of the live authority subject.
The objective is narrow: prove which externally authenticated workload identity
requested an action, what authority was delegated to it, whether that delegation
still applies to the exact action, and whether the resulting decision can be
replayed from durable evidence.

## What is real in Wave 15

Wave 15 adds a local OIDC/JWT verification boundary using configured trusted JWKS
files and asymmetric RS256 signatures. The gateway validates the token signature,
issuer, audience, subject, key id (`kid`), token id (`jti`), issued-at (`iat`),
not-before (`nbf`), expiration (`exp`), maximum credential age, and allowed
algorithm before an external identity can map to a registered BlackFox agent.

The gateway does not accept a caller-provided agent id as proof of identity. An
`issuer` + `subject` pair must be explicitly bound to one registered BlackFox
agent. A claimed agent id must agree with that binding.

Wave 15 also supports an ordered `blackfox_delegation` claim. Each delegation can
restrict:

- tool names
- repository ids
- path roots
- delegation expiration

A child delegation may narrow its parent, but cannot expand tool, repository, path,
or lifetime authority. Every delegation id is independently revocable.

The final authenticated identity context, including the issuer, subject, audience,
key id, `jti`, token lifetime, and delegation chain, is hashed into the exact
authority context. Evidence that is action-bound therefore cannot be silently
reused under a different federated identity context.

## Fail-closed identity modes

`[identity].mode` supports three explicit modes:

- `static_only`: Wave 14 behavior; federated bearer identity is rejected.
- `static_or_federated`: migration mode; either configured mechanism can identify
  the registered agent.
- `federated_required`: static agent credentials are rejected and a verified
  federated bearer identity is mandatory.

For the Wave 15 proof, `federated_required` is used so a legacy static secret
cannot bypass the enterprise identity boundary.

## Revocation

Wave 15 keeps a durable SQLite revocation store separate from the receipt chain.
A token can be revoked by `jti`; a delegated authority can be revoked by
`delegation_id`. Revocation is checked before the identity is accepted for an
authority decision.

The revocation database is a bounded local mechanism, not a claim of globally
synchronized enterprise revocation.

## Trusted key handling

Wave 15 deliberately **does not fetch JWKS over the network**. Each trusted
provider references a configured local JWKS document. This avoids turning live
identity decisions into implicit network trust or availability dependencies and
allows operators to control how trusted keys are acquired, reviewed, rotated,
and deployed.

The current Wave 15 runtime supports RS256 through PyJWT's cryptographic backend.
The allowed algorithm set is explicit per provider; `alg=none` is rejected.

## Live proof

Run:

```bash
PYTHONPATH=src python scripts/run_wave15_enterprise_identity_ci.py --root .
```

The proof creates an ephemeral RSA keypair and local JWKS, starts an actual
BlackFox HTTP gateway and an actual local upstream server, then demonstrates:

1. a static credential is rejected in `federated_required` mode;
2. a correctly signed token with the wrong audience is rejected;
3. an expired token is rejected;
4. a valid token whose delegation does not cover the requested path is blocked;
5. all four denied requests produce zero upstream executions;
6. a valid short-lived workload token with scoped delegation plus required test
   evidence and exact human approval reaches the real upstream and causes a real
   file write;
7. the same token is then revoked by `jti` and is rejected before another upstream
   execution; and
8. the durable authority receipt chain verifies after the sequence.

The machine-readable result is written to:

`.blackfox-artifacts/wave15/wave15-enterprise-identity-summary.json`

## Security boundaries and non-claims

Wave 15 strengthens an identity and delegation control boundary. It **does not claim DoD authorization**, ATO/cATO, FedRAMP authorization, AWS certification,
production identity-provider integration, HSM/KMS-backed key custody, OCSP/CRL
semantics, SPIFFE/SPIRE, SCIM lifecycle management, globally distributed
revocation, HA, or an external transparency log.

Those are integration/deployment concerns that must be demonstrated in the target
environment. Wave 15 provides a concrete enforcement surface and evidence that can
be tested against such environments rather than substituting documentation for
them.

## Operator revocation

A deployed gateway can persistently revoke either a token id or a delegation id:

```bash
blackfox gateway revoke-identity \
  --config examples/wave15/blackfox.gateway.toml \
  --kind jti \
  --value TOKEN_JTI \
  --reason incident-response
```

Use `--kind delegation` with the delegation id to invalidate a delegated authority
without revoking every token for the workload identity.

The example `trusted-jwks.json` is intentionally empty. Operators must provision
reviewed public keys from their own identity system; no private signing key is
shipped with the repository.
