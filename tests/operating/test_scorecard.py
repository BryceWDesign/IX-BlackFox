from __future__ import annotations

import pytest

from ix_blackfox.operating import (
    CoverageMetric,
    EvidenceMetric,
    MetricStatus,
    OperatingDisposition,
    OperatingScorecard,
    PolicyMetric,
    ReplayMetric,
    ReviewMetric,
    RiskMetric,
)


def test_operating_scorecard_is_ready_when_all_metrics_pass() -> None:
    scorecard = _ready_scorecard()
    same_scorecard = _ready_scorecard(scorecard_id="wave-10-scorecard")

    assert scorecard.scorecard_id == "wave-10-scorecard"
    assert scorecard.registry_id == "wave-10-registry"
    assert scorecard.campaign_id == "wave-10-campaign"
    assert scorecard.repository_ids == ("ix-blackfox",)
    assert scorecard.total_metric_count == 6
    assert scorecard.status_counts == {
        "passing": 6,
        "warning": 0,
        "failing": 0,
        "not_measured": 0,
    }
    assert scorecard.passing_metric_ids == (
        "artifact-coverage",
        "evidence-trust",
        "policy-controls",
        "repository-risk",
        "replay-validation",
        "review-authority",
    )
    assert scorecard.blocking_metric_ids == ()
    assert scorecard.operating_score == 100.0
    assert scorecard.findings == ()
    assert scorecard.disposition is OperatingDisposition.READY
    assert scorecard.to_envelope().disposition is OperatingDisposition.READY
    assert scorecard.to_dict()["digest"] == same_scorecard.to_dict()["digest"]


def test_operating_scorecard_blocks_buyer_critical_metric_gaps() -> None:
    scorecard = OperatingScorecard(
        scorecard_id="blocked-scorecard",
        registry_id="wave10-registry",
        campaign_id="wave10-campaign",
        repository_ids=("ix-blackfox",),
        coverage_metrics=(
            CoverageMetric(
                metric_id="coverage-gap",
                title="Coverage gap",
                covered_count=3,
                required_count=5,
            ),
        ),
        risk_metrics=(
            RiskMetric(
                metric_id="risk-gap",
                title="Risk gap",
                risk_score=9,
                maximum_allowed_score=4,
            ),
        ),
        review_metrics=(
            ReviewMetric(
                metric_id="review-gap",
                title="Review gap",
                authoritative_approval_count=1,
                required_authoritative_approvals=2,
                self_approval_attempt_count=1,
            ),
        ),
        replay_metrics=(
            ReplayMetric(
                metric_id="replay-gap",
                title="Replay gap",
                replay_passed=False,
                required_step_count=2,
                executed_step_count=1,
                artifact_mismatch_count=1,
            ),
        ),
        policy_metrics=(
            PolicyMetric(
                metric_id="policy-gap",
                title="Policy gap",
                evaluated_control_count=5,
                failed_control_count=1,
            ),
        ),
        evidence_metrics=(
            EvidenceMetric(
                metric_id="evidence-gap",
                title="Evidence gap",
                required_artifact_count=3,
                trusted_artifact_count=1,
                missing_artifact_count=1,
                untrusted_artifact_count=1,
            ),
        ),
    )

    assert set(scorecard.blocking_metric_ids) == {
        "coverage-gap",
        "evidence-gap",
        "policy-gap",
        "replay-gap",
        "review-gap",
        "risk-gap",
    }
    assert scorecard.status_counts == {
        "passing": 0,
        "warning": 0,
        "failing": 6,
        "not_measured": 0,
    }
    assert scorecard.operating_score == 0.0
    assert scorecard.disposition is OperatingDisposition.BLOCKED
    assert scorecard.to_envelope().disposition is OperatingDisposition.BLOCKED
    assert {finding.code for finding in scorecard.findings} == {
        "operating.scorecard.coverage-gap",
        "operating.scorecard.evidence-gap",
        "operating.scorecard.policy-gap",
        "operating.scorecard.replay-gap",
        "operating.scorecard.review-authority-gap",
        "operating.scorecard.risk-threshold-exceeded",
    }


def test_operating_scorecard_warns_for_nonblocking_warning_metrics() -> None:
    scorecard = OperatingScorecard(
        scorecard_id="warning-scorecard",
        registry_id="wave10-registry",
        campaign_id="wave10-campaign",
        repository_ids=("ix-blackfox",),
        policy_metrics=(
            PolicyMetric(
                metric_id="policy-warning",
                title="Policy warning",
                evaluated_control_count=5,
                failed_control_count=0,
                warning_control_count=1,
            ),
        ),
        evidence_metrics=(
            EvidenceMetric(
                metric_id="evidence-warning",
                title="Evidence warning",
                required_artifact_count=2,
                trusted_artifact_count=2,
                stale_artifact_count=1,
            ),
        ),
    )

    assert scorecard.warning_metric_ids == ("evidence-warning", "policy-warning")
    assert scorecard.blocking_metric_ids == ()
    assert scorecard.operating_score == 75.0
    assert all(finding.blocking is False for finding in scorecard.findings)
    assert scorecard.disposition is OperatingDisposition.WARNING


def test_operating_scorecard_blocks_not_measured_mandatory_metrics() -> None:
    scorecard = OperatingScorecard(
        scorecard_id="not-measured-scorecard",
        registry_id="wave10-registry",
        campaign_id="wave10-campaign",
        repository_ids=("ix-blackfox",),
        coverage_metrics=(
            CoverageMetric(
                metric_id="not-measured-coverage",
                title="Not measured coverage",
                covered_count=0,
                required_count=0,
            ),
        ),
    )

    assert scorecard.not_measured_metric_ids == ("not-measured-coverage",)
    assert scorecard.blocking_metric_ids == ("not-measured-coverage",)
    assert scorecard.coverage_metrics[0].status is MetricStatus.NOT_MEASURED
    assert scorecard.disposition is OperatingDisposition.BLOCKED


def test_operating_scorecard_rejects_empty_metrics_duplicate_ids_and_negative_values() -> None:
    with pytest.raises(ValueError, match="at least one metric"):
        OperatingScorecard(
            scorecard_id="empty",
            registry_id="wave10-registry",
            campaign_id="wave10-campaign",
            repository_ids=("ix-blackfox",),
        )

    duplicate = CoverageMetric(
        metric_id="duplicate",
        title="Duplicate",
        covered_count=1,
        required_count=1,
    )
    with pytest.raises(ValueError, match="metric_id values must be unique"):
        OperatingScorecard(
            scorecard_id="duplicate",
            registry_id="wave10-registry",
            campaign_id="wave10-campaign",
            repository_ids=("ix-blackfox",),
            coverage_metrics=(duplicate,),
            evidence_metrics=(
                EvidenceMetric(
                    metric_id="duplicate",
                    title="Duplicate evidence",
                    required_artifact_count=1,
                    trusted_artifact_count=1,
                ),
            ),
        )

    with pytest.raises(ValueError, match="risk_score must not be negative"):
        RiskMetric(
            metric_id="bad-risk",
            title="Bad risk",
            risk_score=-1,
            maximum_allowed_score=4,
        )


def test_individual_metric_statuses_are_explicit() -> None:
    assert CoverageMetric(
        metric_id="coverage",
        title="Coverage",
        covered_count=4,
        required_count=5,
        mandatory=False,
    ).status is MetricStatus.WARNING

    assert RiskMetric(
        metric_id="risk",
        title="Risk",
        risk_score=5,
        maximum_allowed_score=4,
        mandatory=False,
    ).status is MetricStatus.WARNING

    assert ReplayMetric(
        metric_id="replay",
        title="Replay",
        replay_passed=True,
        required_step_count=2,
        executed_step_count=2,
        network_required_step_count=1,
    ).status is MetricStatus.FAILING


def _ready_scorecard(*, scorecard_id: str = " Wave 10 Scorecard ") -> OperatingScorecard:
    return OperatingScorecard(
        scorecard_id=scorecard_id,
        registry_id="Wave 10 Registry",
        campaign_id="Wave 10 Campaign",
        repository_ids=("IX-BlackFox",),
        coverage_metrics=(
            CoverageMetric(
                metric_id="artifact-coverage",
                title="Required artifact coverage",
                covered_count=10,
                required_count=10,
            ),
        ),
        risk_metrics=(
            RiskMetric(
                metric_id="repository-risk",
                title="Repository risk below threshold",
                risk_score=3,
                maximum_allowed_score=4,
            ),
        ),
        review_metrics=(
            ReviewMetric(
                metric_id="review-authority",
                title="Human review authority",
                authoritative_approval_count=2,
                required_authoritative_approvals=2,
            ),
        ),
        replay_metrics=(
            ReplayMetric(
                metric_id="replay-validation",
                title="Replay validation",
                replay_passed=True,
                required_step_count=2,
                executed_step_count=2,
            ),
        ),
        policy_metrics=(
            PolicyMetric(
                metric_id="policy-controls",
                title="Policy controls",
                evaluated_control_count=5,
            ),
        ),
        evidence_metrics=(
            EvidenceMetric(
                metric_id="evidence-trust",
                title="Evidence trust",
                required_artifact_count=5,
                trusted_artifact_count=5,
            ),
        ),
    )
