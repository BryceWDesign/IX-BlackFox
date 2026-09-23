# IX-BlackFox Wave 15 Handoff Manifest

## Release

- Version: `0.3.0`
- Wave: `15 — Enterprise Identity & Delegated Authority`
- Prior wave preserved: Wave 14 Live Authority Gateway

## Added implementation

- `src/ix_blackfox/live_gateway/enterprise_identity.py`
  - trusted local JWKS verification
  - RS256 JWT authentication
  - issuer/audience/subject/`kid`/`jti`/time validation
  - issuer/subject-to-agent binding
  - bounded delegation chains
  - monotonic scope narrowing
  - durable token/delegation revocation
- `src/ix_blackfox/live_gateway/wave15_demo.py`
  - real-network federated identity and delegation proof
- Wave 15 configuration integrated into the existing live gateway
- identity context bound into exact authority subjects for federated calls
- `revoke-identity` operator command
- `federated_required` and required-delegation enforcement modes

## Added verification surface

- Wave 15 enterprise-identity tests
- Wave 15 CI runner
- Wave 15 GitHub Actions workflow across Python 3.11/3.12/3.13
- machine-readable Wave 15 CI schema
- retained machine-readable validation proof
- architecture, operator, security-boundary, and DoD/AWS control-mapping documentation

## Validation snapshot

- 1,615 repository tests executed: all passed
- Wave 15 real-network proof: passed
- receipt chain: passed, zero issues
- Python compilation: passed
- editable install and standard wheel build: passed with local build isolation disabled
- Ruff/mypy: configured in CI but not executable in this sandbox because those binaries are absent and outbound package installation is blocked; see `VALIDATION_REPORT.md`

## Important boundary

This release provides engineering controls and evidence. It does not claim an
ATO/cATO, FedRAMP authorization, DoD approval, AWS certification, or production
enterprise identity-provider integration.
