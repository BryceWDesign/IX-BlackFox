"""Live BlackFox authority gateway with Wave 15 federated identity controls."""

from ix_blackfox.live_gateway.authority import evaluate_live_authority
from ix_blackfox.live_gateway.config import (
    AgentCredential,
    GatewayConfig,
    GatewayServerConfig,
    McpParameterHeaderBinding,
    ToolRoute,
    load_gateway_config,
)
from ix_blackfox.live_gateway.enterprise_identity import (
    AuthenticatedPrincipal,
    FederatedIdentityVerifier,
    IdentityBinding,
    IdentityRevocationStore,
    OidcProvider,
)
from ix_blackfox.live_gateway.evidence import (
    EvidencePolicy,
    EvidenceStore,
    SignedEvidenceArtifact,
    TrustedEvidenceIssuer,
    issue_signed_evidence,
)
from ix_blackfox.live_gateway.http_server import (
    BlackFoxGatewayHttpServer,
    serve_gateway,
)
from ix_blackfox.live_gateway.models import (
    AuthoritySubject,
    LiveAuthorityDecision,
    LiveAuthorityStatus,
)
from ix_blackfox.live_gateway.receipts import AuthorityReceiptStore
from ix_blackfox.live_gateway.service import LiveAuthorityGateway

__all__ = [
    "AgentCredential",
    "AuthenticatedPrincipal",
    "AuthorityReceiptStore",
    "AuthoritySubject",
    "BlackFoxGatewayHttpServer",
    "EvidencePolicy",
    "EvidenceStore",
    "FederatedIdentityVerifier",
    "GatewayConfig",
    "GatewayServerConfig",
    "IdentityBinding",
    "IdentityRevocationStore",
    "LiveAuthorityDecision",
    "LiveAuthorityGateway",
    "LiveAuthorityStatus",
    "McpParameterHeaderBinding",
    "OidcProvider",
    "SignedEvidenceArtifact",
    "ToolRoute",
    "TrustedEvidenceIssuer",
    "evaluate_live_authority",
    "issue_signed_evidence",
    "load_gateway_config",
    "serve_gateway",
]
