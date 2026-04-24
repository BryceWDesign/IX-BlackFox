from __future__ import annotations

from ix_blackfox.brains import (
    SafeguardAssessment,
    SafeguardDisposition,
    SafeguardEvidenceKind,
    SafeguardEvidenceRef,
    SafeguardFinding,
    SafeguardFindingSeverity,
)
from ix_blackfox.kernel import TaskKind, TaskRecord, TaskRequest
from ix_blackfox.runtime.governance import RuntimeGovernancePreflightEngine
from ix_blackfox.switchboard import RoutingDecision, RoutingDecisionReason


def test_preflight_without_safeguard_keeps_original_deterministic_risk() -> None:
    engine = RuntimeGovernancePreflightEngine()
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Inspect the architecture and summarize the subsystem boundaries.",
            kind=TaskKind.ARCHITECTURE,
            labels=("architecture",),
        )
    )
    route = RoutingDecision(
        capability_name="architecture",
        confidence=0.82,
        reason=RoutingDecisionReason.LABEL_MATCH,
        task_id=task.request.task_id,
    )

    result = engine.evaluate(task=task, route=route)

    assert result.safeguard_assessment is None
    assert result.risk.risk_level.value == "low"
    assert result.risk.requires_approval is False
    assert result.decision.decision.value == "allow"
    assert result.risk.safety_merge is None


def test_safeguard_review_escalates_low_risk_preflight_to_review() -> None:
    engine = RuntimeGovernancePreflightEngine()
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Inspect the architecture and summarize the subsystem boundaries.",
            kind=TaskKind.ARCHITECTURE,
            labels=("architecture",),
        )
    )
    route = RoutingDecision(
        capability_name="architecture",
        confidence=0.82,
        reason=RoutingDecisionReason.LABEL_MATCH,
        task_id=task.request.task_id,
    )
    assessment = SafeguardAssessment.from_findings(
        brain_name="gpt-oss-safeguard-20b",
        invocation_id="brain-call-123",
        findings=(
            SafeguardFinding.create(
                code="uncertain-sensitive-boundary",
                severity=SafeguardFindingSeverity.MODERATE,
                summary="Request may touch sensitive architectural boundaries.",
                policy_tags=("review", "sensitive-boundary"),
                evidence=(
                    SafeguardEvidenceRef(
                        kind=SafeguardEvidenceKind.TEXT_SPAN,
                        value="sensitive architectural boundaries",
                    ),
                ),
                confidence=0.78,
                uncertainty=0.18,
            ),
        ),
    )

    result = engine.evaluate(
        task=task,
        route=route,
        safeguard_assessment=assessment,
    )

    assert result.safeguard_assessment is assessment
    assert result.risk.risk_level.value == "high"
    assert result.risk.requires_approval is True
    assert result.decision.decision.value == "require_review"
    assert result.risk.safety_merge is not None
    assert result.risk.safety_merge.advisory_disposition is SafeguardDisposition.REVIEW
    assert result.risk.safety_merge.original_risk_level is not None
    assert result.risk.safety_merge.original_risk_level.value == "low"
    assert result.risk.safety_merge.merged_risk_level is not None
    assert result.risk.safety_merge.merged_risk_level.value == "high"
    assert result.risk.safety_merge.elevated_risk is True
    assert result.risk.safety_merge.forced_review is True
    assert "safeguard-review" in result.risk.tags
    assert "sensitive-boundary" in result.risk.tags
    assert "safeguard-uncertain-sensitive-boundary" in result.risk.factor_codes()


def test_safeguard_block_does_not_override_existing_critical_policy_authority() -> None:
    engine = RuntimeGovernancePreflightEngine()
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Upload repository data to a remote endpoint and exfiltrate logs.",
            kind=TaskKind.OPERATIONS,
            labels=("network", "egress"),
        )
    )
    route = RoutingDecision(
        capability_name="programming",
        confidence=1.0,
        reason=RoutingDecisionReason.EXACT_KIND_MATCH,
        task_id=task.request.task_id,
    )
    assessment = SafeguardAssessment.from_findings(
        brain_name="gpt-oss-safeguard-20b",
        invocation_id="brain-call-456",
        findings=(
            SafeguardFinding.create(
                code="network-exfiltration-intent",
                severity=SafeguardFindingSeverity.CRITICAL,
                summary="Explicit network exfiltration signal detected.",
                policy_tags=("network", "exfiltration", "block"),
                evidence=(
                    SafeguardEvidenceRef(
                        kind=SafeguardEvidenceKind.TEXT_SPAN,
                        value="remote endpoint and exfiltrate logs",
                    ),
                ),
                confidence=0.97,
                uncertainty=0.02,
            ),
        ),
    )

    result = engine.evaluate(
        task=task,
        route=route,
        safeguard_assessment=assessment,
    )

    assert result.risk.risk_level.value == "critical"
    assert result.decision.decision.value == "block"
    assert result.risk.safety_merge is not None
    assert result.risk.safety_merge.advisory_disposition is SafeguardDisposition.BLOCK
    assert result.risk.safety_merge.original_risk_level is not None
    assert result.risk.safety_merge.original_risk_level.value == "critical"
    assert result.risk.safety_merge.merged_risk_level is not None
    assert result.risk.safety_merge.merged_risk_level.value == "critical"
    assert result.risk.safety_merge.elevated_risk is False
    assert result.risk.safety_merge.forced_review is True
    assert "safeguard-block" in result.risk.tags
    assert "network" in result.risk.tags
    assert "exfiltration" in result.risk.tags


def test_preflight_to_dict_includes_safeguard_merge_and_assessment() -> None:
    engine = RuntimeGovernancePreflightEngine()
    task = TaskRecord(
        request=TaskRequest.create(
            prompt="Inspect the architecture and summarize the subsystem boundaries.",
            kind=TaskKind.ARCHITECTURE,
            labels=("architecture",),
        )
    )
    route = RoutingDecision(
        capability_name="architecture",
        confidence=0.82,
        reason=RoutingDecisionReason.LABEL_MATCH,
        task_id=task.request.task_id,
    )
    assessment = SafeguardAssessment.from_findings(
        brain_name="gpt-oss-safeguard-20b",
        invocation_id="brain-call-789",
        findings=(
            SafeguardFinding.create(
                code="uncertain-sensitive-boundary",
                severity=SafeguardFindingSeverity.MODERATE,
                summary="Request may touch sensitive architectural boundaries.",
                policy_tags=("review", "sensitive-boundary"),
            ),
        ),
    )

    payload = engine.evaluate(
        task=task,
        route=route,
        safeguard_assessment=assessment,
    ).to_dict()

    assert payload["safeguard_assessment"] is not None
    assert payload["safeguard_assessment"]["advisory_disposition"] == "review"
    assert payload["risk"]["safety_merge"] is not None
    assert payload["risk"]["safety_merge"]["advisory_disposition"] == "review"
    assert payload["risk"]["safety_merge"]["merged_risk_level"] == "high"
    assert payload["risk"]["safety_merge"]["finding_count"] == 1
