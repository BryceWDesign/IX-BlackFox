from __future__ import annotations

import ix_blackfox.agents as agents


def test_wave11_public_api_exports_core_models_and_registry() -> None:
    exported = set(agents.__all__)

    assert "AgentIdentity" in exported
    assert "AgentCapability" in exported
    assert "AgentCapabilityGrant" in exported
    assert "AgentCapabilityScope" in exported
    assert "AgentKind" in exported
    assert "AgentTrustTier" in exported
    assert "CapabilityRiskTier" in exported
    assert "AgentRegistry" in exported
    assert "AgentRegistrySnapshot" in exported
    assert "build_agent_registry" in exported


def test_wave11_public_api_exports_authorization_authority_and_provenance() -> None:
    exported = set(agents.__all__)

    assert "AgentAuthorizationEvaluator" in exported
    assert "AgentAuthorizationRequest" in exported
    assert "AgentAuthorizationDecision" in exported
    assert "AgentAuthorizationStatus" in exported
    assert "AgentAuthorizationReason" in exported
    assert "evaluate_human_authority" in exported
    assert "AuthorityEvaluation" in exported
    assert "AgentProvenanceLedger" in exported
    assert "AgentProvenanceRecord" in exported
    assert "build_provenance_record_id" in exported


def test_wave11_public_api_exports_existing_system_adapters() -> None:
    exported = set(agents.__all__)

    assert "brain_manifest_to_agent_identity" in exported
    assert "brain_snapshot_to_agent_registry" in exported
    assert "tool_manifest_to_agent_identity" in exported
    assert "tool_registry_to_agent_registry" in exported
    assert "reviewer_authority_to_agent_identity" in exported
    assert "review_board_to_agent_registry" in exported


def test_wave11_public_api_exports_operating_and_tool_gateway_bridges() -> None:
    exported = set(agents.__all__)

    assert "agent_registry_to_operating_envelope" in exported
    assert "agent_registry_snapshot_to_operating_envelope" in exported
    assert "authorization_decision_to_operating_envelope" in exported
    assert "provenance_record_to_operating_envelope" in exported
    assert "AgentAuthorizedToolGateway" in exported
    assert "AgentAuthorizedToolInvocationReport" in exported
    assert "build_tool_authorization_request" in exported


def test_wave11_public_api_exports_readiness_report() -> None:
    exported = set(agents.__all__)

    assert "AgentReadinessReport" in exported
    assert "AgentReadinessStatus" in exported
    assert "AgentReadinessFinding" in exported
    assert "AgentReadinessFindingCode" in exported
    assert "build_agent_readiness_report" in exported


def test_wave11_public_api_objects_are_importable_from_package_root() -> None:
    identity_class = agents.AgentIdentity
    registry_class = agents.AgentRegistry
    evaluator_class = agents.AgentAuthorizationEvaluator
    ledger_class = agents.AgentProvenanceLedger
    report_builder = agents.build_agent_readiness_report

    assert identity_class.__name__ == "AgentIdentity"
    assert registry_class.__name__ == "AgentRegistry"
    assert evaluator_class.__name__ == "AgentAuthorizationEvaluator"
    assert ledger_class.__name__ == "AgentProvenanceLedger"
    assert callable(report_builder)
