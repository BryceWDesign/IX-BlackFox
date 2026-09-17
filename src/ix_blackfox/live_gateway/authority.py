from __future__ import annotations

from datetime import UTC, datetime

from ix_blackfox.agents.authorization import (
    AgentAuthorizationEvaluator,
    AgentAuthorizationStatus,
)
from ix_blackfox.agents.tool_gateway import build_tool_authorization_request
from ix_blackfox.live_gateway.evidence import EvidencePolicy, EvidenceStore
from ix_blackfox.live_gateway.models import (
    AuthoritySubject,
    EvidenceEvaluation,
    LiveAuthorityDecision,
    LiveAuthorityStatus,
)
from ix_blackfox.tools.contracts import ToolInvocationRequest


def evaluate_live_authority(
    *,
    evaluator: AgentAuthorizationEvaluator,
    evidence_store: EvidenceStore,
    subject: AuthoritySubject,
    invocation: ToolInvocationRequest,
    evidence_policy: EvidencePolicy,
    evidence_ids: tuple[str, ...],
    decided_at: str | None = None,
) -> LiveAuthorityDecision:
    """Evaluate identity/scope and verified evidence before any external tool call."""

    timestamp = decided_at or datetime.now(tz=UTC).isoformat()
    authorization_request = build_tool_authorization_request(
        agent_id=subject.agent_id,
        request=invocation,
    )
    authorization_decision = evaluator.evaluate(
        authorization_request,
        decided_at=timestamp,
        evidence_artifact_ids=evidence_ids,
    )
    evidence = evidence_store.verify_many(
        evidence_ids,
        subject=subject,
        policy=evidence_policy,
    )

    if authorization_decision.status is AgentAuthorizationStatus.BLOCK:
        return LiveAuthorityDecision(
            subject=subject,
            status=LiveAuthorityStatus.BLOCK,
            reason_codes=tuple(reason.value for reason in authorization_decision.reasons),
            agent_authorization=authorization_decision,
            evidence=evidence,
            decided_at=timestamp,
        )

    if not evidence.passed:
        return LiveAuthorityDecision(
            subject=subject,
            status=LiveAuthorityStatus.EVIDENCE_REQUIRED,
            reason_codes=("evidence_conditions_unsatisfied",),
            agent_authorization=authorization_decision,
            evidence=evidence,
            decided_at=timestamp,
        )

    # A Wave 14 route that explicitly declares a human approval kind creates an
    # independent execution condition.  It must remain effective even when the
    # underlying Wave 11 grant happens to return ALLOW rather than REQUIRE_REVIEW;
    # otherwise a route-level policy could silently become weaker than configured.
    if evidence_policy.human_approval_kind and not evidence.human_approval_satisfied:
        return LiveAuthorityDecision(
            subject=subject,
            status=LiveAuthorityStatus.REVIEW_REQUIRED,
            reason_codes=("human_authority_required",),
            agent_authorization=authorization_decision,
            evidence=evidence,
            decided_at=timestamp,
        )

    if authorization_decision.status is AgentAuthorizationStatus.REQUIRE_REVIEW:
        if evidence_policy.human_approval_kind and evidence.human_approval_satisfied:
            return LiveAuthorityDecision(
                subject=subject,
                status=LiveAuthorityStatus.ALLOW,
                reason_codes=("verified_human_approval_satisfied",),
                agent_authorization=authorization_decision,
                evidence=evidence,
                decided_at=timestamp,
            )
        return LiveAuthorityDecision(
            subject=subject,
            status=LiveAuthorityStatus.REVIEW_REQUIRED,
            reason_codes=("human_authority_required",),
            agent_authorization=authorization_decision,
            evidence=evidence,
            decided_at=timestamp,
        )

    return LiveAuthorityDecision(
        subject=subject,
        status=LiveAuthorityStatus.ALLOW,
        reason_codes=(
            "verified_human_approval_satisfied"
            if evidence_policy.human_approval_kind
            else "identity_scope_and_evidence_satisfied",
        ),
        agent_authorization=authorization_decision,
        evidence=evidence,
        decided_at=timestamp,
    )


def no_evidence_policy(policy_id: str = "none") -> EvidencePolicy:
    return EvidencePolicy(
        policy_id=policy_id,
        required_kinds=(),
        max_age_seconds=86_400,
        require_signature=False,
        require_repository_match=False,
        require_revision_match=False,
    )


def empty_evidence_evaluation(policy_id: str = "none") -> EvidenceEvaluation:
    return EvidenceEvaluation(
        policy_id=policy_id,
        required_kinds=(),
        valid_evidence_ids=(),
        missing_kinds=(),
        human_approval_satisfied=False,
        verifications=(),
        issues=(),
    )
