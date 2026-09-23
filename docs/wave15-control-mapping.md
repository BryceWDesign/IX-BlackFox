# Wave 15 Control Mapping

This document is an engineering crosswalk, not a certification claim. It maps
implemented Wave 15 controls to public DoD Zero Trust and AWS identity/security
principles so reviewers can see what is actually enforced and what still depends
on deployment-specific infrastructure.

## DoD Zero Trust relevance

The DoD Zero Trust Strategy and execution roadmap emphasize identity federation,
least-privileged access, integrated identity/credential/access management,
resource authorization, secure software development, policy decision points,
automation, logging, and continuous authorization. Wave 15 contributes concrete
mechanisms in that direction:

| Public DoD Zero Trust theme | Wave 15 implementation | Boundary |
| --- | --- | --- |
| Identity federation / credentialing | Trusted issuer + subject mapping, signed JWT verification | Uses configured local JWKS; no enterprise IdP connector is claimed |
| Least-privileged access | Delegation narrows tool, repository, and path authority | Does not replace the target organization's ABAC/RBAC system |
| Integrated ICAM / non-person entity identity | Workload identity maps to a registered BlackFox agent | BlackFox is not an enterprise ICAM authority |
| Resource authorization | Per-action delegation plus existing route/scope/policy evaluation | Applies only to traffic mediated by the BlackFox gateway |
| Policy decision point | Fail-closed authority decision before upstream invocation | Not a replacement for enterprise policy orchestration |
| Continuous / ongoing authorization | Short-lived credentials, per-request verification, durable revocation checks | Revocation is local, not globally distributed |
| Auditability | Identity context is hashed into the authority subject and receipt chain | No external transparency service is claimed |

## AWS relevance

AWS IAM guidance recommends temporary workload credentials, least privilege,
conditions, federation, and regular credential/permission review. Amazon Bedrock
AgentCore Identity also models agents as workload identities and explicitly
supports delegation-oriented access patterns. Wave 15 aligns technically with
those ideas by requiring short-lived signed workload tokens, scoped delegation,
revocation, and per-request identity binding.

Wave 15 does **not** claim native IAM role assumption, STS integration, AgentCore
registration, KMS/HSM custody, or AWS certification. Those are appropriate Wave 17
integration targets after the identity contract is stable.

## Evidence produced by this wave

The Wave 15 CI proof demonstrates, over real local HTTP sockets, that:

- a legacy static credential is rejected in `federated_required` mode;
- wrong-audience and expired credentials fail authentication;
- a signed credential without required delegation fails authentication;
- an out-of-scope delegation cannot reach the upstream;
- all denied cases leave upstream invocation count at zero;
- a valid signed workload identity with bounded delegation can execute only when
  the existing evidence and human-review requirements are also satisfied;
- revoking the token `jti` blocks subsequent use before upstream execution; and
- the resulting authority receipts retain a valid hash chain.

That is implementation evidence. It is not an ATO, cATO, FedRAMP authorization,
AWS certification, or a claim that the repository by itself satisfies every
control in a target deployment.
