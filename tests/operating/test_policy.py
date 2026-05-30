from __future__ import annotations

import pytest

from ix_blackfox.operating import (
    OperatingControl,
    OperatingControlEffect,
    OperatingControlResultStatus,
    OperatingDisposition,
    OperatingDomain,
    OperatingGateDecision,
    OperatingPolicyContext,
    OperatingPolicyPack,
    OperatingSeverity,
)


def test_policy_evaluation_is_deterministic_and_ready_when_all_controls_pass() -> None:
    policy_pack = _policy_pack()
    context = _ready_context()

    evaluation = policy_pack.evaluate(context, evaluation_id=" Wave 10 Policy Evaluation ")
    same_evaluation = _policy_pack().evaluate(
        _ready_context(),
        evaluation_id="wave-10-policy-evaluation",
    )

    assert evaluation.evaluation_id == "wave-10-policy-evaluation"
    assert [result.status for result in evaluation.results] == [
        OperatingControlResultStatus.PASSED,
        OperatingControlResultStatus.PASSED,
        OperatingControlResultStatus.PASSED,
        OperatingControlResultStatus.PASSED,
        OperatingControlResultStatus.PASSED,
    ]
    assert evaluation.failed_control_ids == ()
    assert evaluation.findings == ()
    assert evaluation.disposition is OperatingDisposition.READY
    assert evaluation.to_envelope().disposition is OperatingDisposition.READY
    assert evaluation.to_dict()["digest"] == same_evaluation.to_dict()["digest"]


def test_policy_evaluation_blocks_missing_authority_evidence_replay_traceability_and_blockers() -> None:
    context = OperatingPolicyContext(
        context_id="blocked-context",
        repository_ids=("ix-blackfox",),
        domains=(OperatingDomain.POLICY_GOVERNED, OperatingDomain.REVIEWABLE),
        artifact_ids=("wave9-governance-report",),
        authoritative_approval_count=0,
        replay_passed=False,
        traceability_passed=False,
        review_bundle_disposition=OperatingDisposition.BLOCKED,
        evidence_inventory_disposition=OperatingDisposition.READY,
        campaign_disposition=OperatingDisposition.READY,
        registry_disposition=OperatingDisposition.READY,
        unresolved_blocker_ids=("critical-blocker",),
    )

    evaluation = _policy_pack().evaluate(context, evaluation_id="blocked-evaluation")

    assert set(evaluation.failed_control_ids) == {
        "evidence-inventory-ready",
        "human-authority-required",
        "no-unresolved-blockers",
        "replay-and-traceability-required",
        "review-bundle-ready",
    }
    assert evaluation.disposition is OperatingDisposition.BLOCKED
    assert evaluation.to_envelope().disposition is OperatingDisposition.BLOCKED
    result_by_id = {result.control_id: result for result in evaluation.results}
    assert result_by_id["evidence-inventory-ready"].missing_artifact_ids == (
        "replay-manifest",
    )
    assert "insufficient authoritative human approvals" in result_by_id[
        "human-authority-required"
    ].summary
    assert "replay validation did not pass" in result_by_id[
        "replay-and-traceability-required"
    ].summary
    assert "unresolved blockers are present" in result_by_id[
        "no-unresolved-blockers"
    ].summary


def test_policy_evaluation_warns_for_optional_control_failures() -> None:
    policy_pack = OperatingPolicyPack(
        policy_pack_id="optional-policy",
        name="Optional Policy",
        version="v1",
        required_for_domains=(OperatingDomain.MEASURABLE,),
        controls=(
            OperatingControl(
                control_id="optional-scorecard-artifact",
                title="Optional scorecard artifact",
                intent="Warn when the optional scorecard artifact has not been attached.",
                effect=OperatingControlEffect.WARN,
                domains=(OperatingDomain.MEASURABLE,),
                severity=OperatingSeverity.MEDIUM,
                required_artifact_ids=("scorecard",),
                mandatory=False,
            ),
        ),
    )
    context = OperatingPolicyContext(
        context_id="warning-context",
        repository_ids=("ix-blackfox",),
        domains=(OperatingDomain.MEASURABLE,),
        artifact_ids=(),
        review_bundle_disposition=OperatingDisposition.READY,
        evidence_inventory_disposition=OperatingDisposition.READY,
        campaign_disposition=OperatingDisposition.READY,
        registry_disposition=OperatingDisposition.READY,
    )

    evaluation = policy_pack.evaluate(context, evaluation_id="warning-evaluation")

    assert evaluation.warning_control_ids == ("optional-scorecard-artifact",)
    assert evaluation.failed_control_ids == ()
    assert evaluation.findings[0].blocking is False
    assert evaluation.disposition is OperatingDisposition.WARNING


def test_policy_control_not_applicable_outside_context_domain() -> None:
    control = OperatingControl(
        control_id="replay-only-control",
        title="Replay only control",
        intent="This control applies only to replayable contexts.",
        effect=OperatingControlEffect.REQUIRE_REPLAY,
        domains=(OperatingDomain.REPLAYABLE,),
        require_replay_passed=True,
    )
    context = OperatingPolicyContext(
        context_id="review-context",
        repository_ids=("ix-blackfox",),
        domains=(OperatingDomain.REVIEWABLE,),
    )

    result = control.evaluate(context)

    assert result.status is OperatingControlResultStatus.NOT_APPLICABLE
    assert result.blocking is False
    assert result.to_finding(policy_pack_id="policy", evaluation_id="eval") is None


def test_operating_gate_decision_blocks_failed_policy_evaluation_and_allows_ready() -> None:
    ready_evaluation = _policy_pack().evaluate(_ready_context(), evaluation_id="ready")
    ready_gate = OperatingGateDecision(
        gate_id="ready-gate",
        evaluations=(ready_evaluation,),
        required_evaluation_ids=("ready",),
        decided_by="platform security reviewer",
        rationale="All required Wave 10 policy controls passed.",
    )
    blocked_evaluation = _policy_pack().evaluate(
        OperatingPolicyContext(
            context_id="blocked-context",
            repository_ids=("ix-blackfox",),
            domains=(OperatingDomain.POLICY_GOVERNED, OperatingDomain.REVIEWABLE),
            artifact_ids=(),
            authoritative_approval_count=0,
            replay_passed=False,
            traceability_passed=False,
            review_bundle_disposition=OperatingDisposition.BLOCKED,
            evidence_inventory_disposition=OperatingDisposition.BLOCKED,
            campaign_disposition=OperatingDisposition.BLOCKED,
            registry_disposition=OperatingDisposition.BLOCKED,
            unresolved_blocker_ids=("critical-blocker",),
        ),
        evaluation_id="blocked",
    )
    blocked_gate = OperatingGateDecision(
        gate_id="blocked-gate",
        evaluations=(blocked_evaluation,),
        required_evaluation_ids=("blocked",),
        decided_by="platform security reviewer",
        rationale="The gate must fail closed when policy controls fail.",
    )

    assert ready_gate.can_proceed is True
    assert ready_gate.disposition is OperatingDisposition.READY
    assert blocked_gate.can_proceed is False
    assert blocked_gate.disposition is OperatingDisposition.BLOCKED
    assert blocked_gate.blocking_evaluation_ids == ("blocked",)
    assert "operating.gate.blocked-policy-evaluation" in {
        finding.code for finding in blocked_gate.findings
    }


def test_policy_pack_and_gate_reject_duplicate_or_missing_scope() -> None:
    control = OperatingControl(
        control_id="duplicate",
        title="Duplicate",
        intent="Duplicate control should fail.",
        effect=OperatingControlEffect.BLOCK,
        domains=(OperatingDomain.POLICY_GOVERNED,),
    )

    with pytest.raises(ValueError, match="control_id values must be unique"):
        OperatingPolicyPack(
            policy_pack_id="duplicate-pack",
            name="Duplicate Pack",
            version="v1",
            controls=(control, control),
            required_for_domains=(OperatingDomain.POLICY_GOVERNED,),
        )

    evaluation = _policy_pack().evaluate(_ready_context(), evaluation_id="present")
    with pytest.raises(ValueError, match="required evaluations are not present"):
        OperatingGateDecision(
            gate_id="missing-evaluation",
            evaluations=(evaluation,),
            required_evaluation_ids=("missing",),
            decided_by="platform security reviewer",
            rationale="Missing evaluations must fail before a gate can exist.",
        )


def _policy_pack() -> OperatingPolicyPack:
    return OperatingPolicyPack(
        policy_pack_id="Wave 10 Operating Controls",
        name="Wave 10 Operating Controls",
        version="v1",
        description="Controls for buyer-grade Wave 10 operating evidence.",
        required_for_domains=(OperatingDomain.POLICY_GOVERNED, OperatingDomain.REVIEWABLE),
        controls=(
            OperatingControl(
                control_id="human-authority-required",
                title="Human authority required",
                intent="Require two authoritative human approvals before final operating readiness.",
                effect=OperatingControlEffect.REQUIRE_REVIEW,
                domains=(OperatingDomain.REVIEWABLE, OperatingDomain.MULTI_TEAM),
                minimum_human_approvals=2,
                references=("review-board",),
            ),
            OperatingControl(
                control_id="evidence-inventory-ready",
                title="Evidence inventory ready",
                intent="Require Wave 10 evidence inventory readiness and attached key artifacts.",
                effect=OperatingControlEffect.REQUIRE_EVIDENCE,
                domains=(OperatingDomain.MEASURABLE, OperatingDomain.REVIEWABLE),
                required_artifact_ids=("wave9-governance-report", "replay-manifest"),
                require_evidence_inventory_ready=True,
            ),
            OperatingControl(
                control_id="replay-and-traceability-required",
                title="Replay and traceability required",
                intent="Require replay validation and assurance traceability before readiness.",
                effect=OperatingControlEffect.REQUIRE_TRACEABILITY,
                domains=(OperatingDomain.REPLAYABLE, OperatingDomain.POLICY_GOVERNED),
                require_replay_passed=True,
                require_traceability_passed=True,
            ),
            OperatingControl(
                control_id="review-bundle-ready",
                title="Review bundle ready",
                intent="Require digest-bound human review bundle readiness.",
                effect=OperatingControlEffect.REQUIRE_REVIEW,
                domains=(OperatingDomain.REVIEWABLE,),
                require_review_bundle_ready=True,
                require_campaign_ready=True,
                require_registry_ready=True,
            ),
            OperatingControl(
                control_id="no-unresolved-blockers",
                title="No unresolved blockers",
                intent="Prevent final readiness when unresolved operating blockers are present.",
                effect=OperatingControlEffect.BLOCK,
                domains=(OperatingDomain.POLICY_GOVERNED, OperatingDomain.REVIEWABLE),
                require_no_unresolved_blockers=True,
            ),
        ),
    )


def _ready_context() -> OperatingPolicyContext:
    return OperatingPolicyContext(
        context_id=" Wave 10 Policy Context ",
        repository_ids=("IX-BlackFox",),
        domains=(
            OperatingDomain.MULTI_TEAM,
            OperatingDomain.MEASURABLE,
            OperatingDomain.POLICY_GOVERNED,
            OperatingDomain.REPLAYABLE,
            OperatingDomain.REVIEWABLE,
        ),
        artifact_ids=("wave9-governance-report", "replay-manifest"),
        authoritative_approval_count=2,
        replay_passed=True,
        traceability_passed=True,
        review_bundle_disposition=OperatingDisposition.READY,
        evidence_inventory_disposition=OperatingDisposition.READY,
        campaign_disposition=OperatingDisposition.READY,
        registry_disposition=OperatingDisposition.READY,
        unresolved_blocker_ids=(),
    )
