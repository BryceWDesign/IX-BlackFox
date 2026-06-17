<p align="center">
  <img src="IX-BlackFox-Logo.png" alt="IX-BlackFox Logo">
</p>

# IX-BlackFox

**AI proposes. Humans decide. Evidence decides trust.**

IX-BlackFox is a source-available AI engineering control plane for governing AI-assisted software-change workflows.

It treats AI output as untrusted input and wraps proposed actions in scoped authority, policy gates, evidence bundles, replay checks, provenance, and human review.

Wave 11 adds an explicit **agent identity and capability registry**.

Before an actor can participate in a governed action, BlackFox asks:

```
Who is acting?
What capability are they requesting?
What scope limits that capability?
What evidence supports the request?
Does a separate human authority need to review it?
```
What Wave 11 adds

Wave 11 introduces:

agent identities,
trust tiers,
lifecycle states,
scoped capability grants,
capability posture validation,
authorization requests,
authorization decisions,
human-authority checks,
self-approval prevention,
provenance records,
an append-only provenance ledger,
readiness reports,
and offline CI evidence generation.

The Wave 11 package lives here:
```
src/ix_blackfox/agents/
```
The detailed evidence contract is here:
```
docs/wave11-agent-identity.md
```
Core boundary

IX-BlackFox is designed to prevent AI-assisted workflows from silently treating models, tools, CI runners, or system services as trusted authorities.

A model may propose.

A tool may execute only inside scope.

A CI runner may produce evidence.

A human authority must decide.

Wave 11 is built to block or expose:

unknown actors,
revoked actors,
expired grants,
out-of-scope requests,
model approval attempts,
tool approval attempts,
CI approval attempts,
system approval attempts,
self-approval,
missing human authority,
missing provenance,
invalid provenance chains,
and unsupported readiness claims.

Main modules
| Module                    | Purpose                                                                          |
| ------------------------- | -------------------------------------------------------------------------------- |
| `agents.models`           | Agent identities, trust tiers, lifecycle states, and capability grants.          |
| `agents.capabilities`     | Human-only rules, model/tool/system deny rules, and posture validation.          |
| `agents.registry`         | Agent registry, registry snapshots, lookup, and capability search.               |
| `agents.authorization`    | Authorization requests, decisions, and allow/review/block evaluation.            |
| `agents.authority`        | Human-authority checks and self-approval blocking.                               |
| `agents.provenance`       | Authorization records and append-only chain-digest ledger.                       |
| `agents.adapters`         | Converts BrainManifest, ToolManifest, and ReviewerAuthority records into agents. |
| `agents.operating_bridge` | Exports Wave 11 evidence into Wave 10 operating envelopes.                       |
| `agents.tool_gateway`     | Adds agent authorization preflight before governed tool execution.               |
| `agents.report`           | Builds Wave 11 readiness reports.                                                |
Offline CI evidence

Wave 11 includes an offline diagnostic runner:
```
scripts/run_wave11_agent_identity_ci.py
```
It generates:
```
.blackfox-artifacts/wave11/wave11-agent-readiness-report.json
.blackfox-artifacts/wave11/wave11-agent-identity-engine-evidence.json
.blackfox-artifacts/wave11/wave11-agent-identity-ci-summary.json
```
Example:
```
PYTHONPATH=src python scripts/run_wave11_agent_identity_ci.py \
  --head-sha "local-dev" \
  --output ".blackfox-artifacts/wave11/wave11-agent-readiness-report.json" \
  --engine-evidence-output ".blackfox-artifacts/wave11/wave11-agent-identity-engine-evidence.json" \
  --summary-output ".blackfox-artifacts/wave11/wave11-agent-identity-ci-summary.json" \
  --expected-status "warning"
```
The runner is local and deterministic. It does not call model APIs, use cloud credentials, contact external services, grant production authorization, or create autonomous authority.

Running tests

From the repository root:
```
PYTHONPATH=src python -m pytest
```
Wave 11 only:
```
PYTHONPATH=src python -m pytest tests/agents -q
```
Wave 11 CI runner tests:
```
PYTHONPATH=src python -m pytest tests/ci/test_wave11_agent_identity_ci_integration.py -q
```
Syntax check:
```
PYTHONPATH=src python -m compileall -q src scripts tests
```
When available:
```
ruff check .
mypy src
```
Trust your local or GitHub Actions output, not this README, as proof that checks passed.

What IX-BlackFox is not

IX-BlackFox is not:

a replacement for human review,
a production authorization system,
a certified compliance product,
a FedRAMP-authorized product,
a DoD-approved product,
an AWS-approved product,
a live AWS Security Hub integration,
an autonomous deployment authority,
an autonomous agent approval system,
or a guarantee that model-generated code is correct.

It is an evidence-bound control plane and research prototype for making AI-assisted engineering workflows more inspectable, reviewable, identity-bound, and governable.

License and use

IX-BlackFox is source-available for technical evaluation under the repository license.

Unless a separate written commercial license says otherwise, public visibility does not grant permission for commercial use, production use, hosted service use, contractor use, funded operational use, derivative operational use, procurement use, or resale.

See LICENSE for the exact legal terms.

Authorship

IX-BlackFox was originated and created by Bryce Lovell.

Positioning

IX-BlackFox governs AI-assisted code change through agent identity, scoped capabilities, policy gates, evidence bundles, replay checks, human authority, provenance, readiness reports, and fail-closed review.

AI proposes. Humans decide. Evidence decides trust.
