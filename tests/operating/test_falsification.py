from __future__ import annotations

import pytest

from ix_blackfox.operating import (
    FalsificationGate,
    KillCriterion,
    KillCriterionStatus,
    NegativeControlCase,
    NegativeControlOutcome,
    NegativeControlResult,
    NegativeControlType,
    OperatingDisposition,
    OperatingDomain,
    OperatingSeverity,
)


def test_falsification_gate_is_ready_when_negative_controls_block_as_expected() -> None:
    case = _case(
        "self-approval-control",
        NegativeControlType.SELF_APPROVAL,
        ("operating.authority.self-approval-attempt",),
    )
    result = _result(
        "self-approval-result",
        "self-approval-control",
        ("operating.authority.self-approval-attempt",),
    )
    criterion = KillCriterion(
        criterion_id="no-self-approval-survival-rule",
        title="No self approval survival rule",
        description="Any accepted self approval attempt kills final Wave 10 readiness.",
        severity=OperatingSeverity.CRITICAL,
        status=KillCriterionStatus.NOT_TRIGGERED,
        trigger_finding_codes=("operating.authority.self-approval-attempt",),
        repository_ids=("ix-blackfox",),
        owner_team_id="platform-security",
        evidence_artifact_ids=("negative-control-report",),
    )
    gate = FalsificationGate(
        gate_id=" Wave 10 Falsification ",
        target_id="Wave 10 Campaign",
        negative_control_cases=(case,),
        negative_control_results=(result,),
        kill_criteria=(criterion,),
        required_artifact_ids=("negative-control-report",),
        observed_artifact_ids=("negative-control-report",),
    )
    same_gate = FalsificationGate(
        gate_id="wave-10-falsification",
        target_id="wave-10-campaign",
        negative_control_cases=(case,),
        negative_control_results=(result,),
        kill_criteria=(criterion,),
        required_artifact_ids=("negative-control-report",),
        observed_artifact_ids=("negative-control-report",),
    )

    assert gate.gate_id == "wave-10-falsification"
    assert gate.case_ids == ("self-approval-control",)
    assert gate.result_ids == ("self-approval-result",)
    assert gate.failed_case_ids == ()
    assert gate.blocking_kill_criterion_ids == ()
    assert gate.warning_kill_criterion_ids == ()
    assert gate.findings == ()
    assert gate.disposition is OperatingDisposition.READY
    assert gate.to_envelope().disposition is OperatingDisposition.READY
    assert gate.to_dict()["digest"] == same_gate.to_dict()["digest"]


def test_falsification_gate_blocks_missing_required_artifacts_and_unrun_cases() -> None:
    gate = FalsificationGate(
        gate_id="missing-proof",
        target_id="wave10-campaign",
        negative_control_cases=(
            _case(
                "missing-evidence-control",
                NegativeControlType.MISSING_EVIDENCE,
                ("operating.evidence.missing-required-wave-evidence",),
            ),
        ),
        negative_control_results=(),
        kill_criteria=(),
        required_artifact_ids=("negative-control-report", "kill-criteria-report"),
        observed_artifact_ids=("negative-control-report",),
    )

    finding_codes = {finding.code for finding in gate.findings}
    assert finding_codes == {
        "operating.falsification.missing-required-artifact",
        "operating.falsification.required-negative-control-not-run",
    }
    assert gate.missing_required_artifact_ids == ("kill-criteria-report",)
    assert gate.required_case_ids_without_results == ("missing-evidence-control",)
    assert gate.disposition is OperatingDisposition.BLOCKED


def test_falsification_gate_blocks_failed_negative_control_result() -> None:
    case = _case(
        "replay-mismatch-control",
        NegativeControlType.REPLAY_MISMATCH,
        ("operating.replay.artifact-digest-mismatch",),
        required_artifact_ids=("replay-negative-control",),
    )
    result = NegativeControlResult(
        result_id="bad-replay-result",
        case_id="replay-mismatch-control",
        outcome=NegativeControlOutcome.PASSED,
        observed_blocking=False,
        observed_finding_codes=("operating.replay.unexpected-artifact",),
        evidence_artifact_ids=(),
        checked_by="security-reviewer",
    )
    gate = FalsificationGate(
        gate_id="failed-negative-control",
        target_id="wave10-campaign",
        negative_control_cases=(case,),
        negative_control_results=(result,),
        kill_criteria=(),
        required_artifact_ids=("replay-negative-control",),
        observed_artifact_ids=("replay-negative-control",),
    )

    assert gate.failed_case_ids == ("replay-mismatch-control",)
    assert "operating.falsification.negative-control-failed" in {
        finding.code for finding in gate.findings
    }
    finding = gate.findings[0]
    assert finding.metadata["expected_finding_gaps"] == [
        "operating.replay.artifact-digest-mismatch"
    ]
    assert finding.metadata["missing_required_artifacts"] == ["replay-negative-control"]
    assert gate.disposition is OperatingDisposition.BLOCKED


def test_falsification_gate_blocks_triggered_or_unevaluated_mandatory_kill_criteria() -> None:
    triggered = KillCriterion(
        criterion_id="triggered-kill",
        title="Triggered kill criterion",
        description="A critical kill criterion was triggered.",
        severity=OperatingSeverity.CRITICAL,
        status=KillCriterionStatus.TRIGGERED,
        trigger_finding_codes=("operating.policy.failed.human-authority-required",),
        repository_ids=("ix-blackfox",),
        owner_team_id="platform-security",
    )
    not_evaluated = KillCriterion(
        criterion_id="not-evaluated-kill",
        title="Not evaluated kill criterion",
        description="A mandatory kill criterion was not evaluated.",
        severity=OperatingSeverity.CRITICAL,
        status=KillCriterionStatus.NOT_EVALUATED,
        trigger_finding_codes=("operating.replay.required-step-not-executed",),
        repository_ids=("ix-blackfox",),
        owner_team_id="platform-security",
    )
    gate = FalsificationGate(
        gate_id="kill-blocked",
        target_id="wave10-campaign",
        negative_control_cases=(
            _case(
                "policy-bypass-control",
                NegativeControlType.POLICY_BYPASS,
                ("operating.policy.failed.human-authority-required",),
                required=False,
            ),
        ),
        negative_control_results=(),
        kill_criteria=(triggered, not_evaluated),
        required_artifact_ids=(),
        observed_artifact_ids=(),
    )

    assert gate.blocking_kill_criterion_ids == ("not-evaluated-kill", "triggered-kill")
    assert gate.triggered_kill_criterion_ids == ("triggered-kill",)
    assert {finding.code for finding in gate.findings} == {
        "operating.falsification.kill-criterion-blocked",
    }
    assert gate.disposition is OperatingDisposition.BLOCKED


def test_falsification_gate_warns_for_human_waived_kill_criteria() -> None:
    waived = KillCriterion(
        criterion_id="human-waived-kill",
        title="Human waived kill criterion",
        description="A reviewer waived the criterion with an evidence-bound rationale.",
        severity=OperatingSeverity.HIGH,
        status=KillCriterionStatus.WAIVED_BY_HUMAN_REVIEW,
        trigger_finding_codes=("operating.trust.freshness-warning",),
        repository_ids=("ix-blackfox",),
        owner_team_id="platform-security",
        evidence_artifact_ids=("waiver-record",),
        waived_by_human_review_id="human-review",
        waiver_rationale="The evidence is aging but still inside the accepted review window.",
    )
    gate = FalsificationGate(
        gate_id="waived-warning",
        target_id="wave10-campaign",
        negative_control_cases=(
            _case(
                "aging-evidence-control",
                NegativeControlType.UNTRUSTED_EVIDENCE,
                ("operating.trust.freshness-warning",),
                required=False,
            ),
        ),
        negative_control_results=(),
        kill_criteria=(waived,),
        required_artifact_ids=("waiver-record",),
        observed_artifact_ids=("waiver-record",),
    )

    assert gate.warning_kill_criterion_ids == ("human-waived-kill",)
    assert gate.blocking_kill_criterion_ids == ()
    assert {finding.code for finding in gate.findings} == {
        "operating.falsification.kill-criterion-warning",
    }
    assert gate.disposition is OperatingDisposition.WARNING


def test_falsification_gate_rejects_duplicate_ids_and_unknown_case_result() -> None:
    case = _case(
        "duplicate",
        NegativeControlType.CLAIM_OVERREACH,
        ("operating.traceability.unsupported-assurance-claim",),
    )

    with pytest.raises(ValueError, match="case_id values must be unique"):
        FalsificationGate(
            gate_id="duplicate-cases",
            target_id="wave10-campaign",
            negative_control_cases=(case, case),
            negative_control_results=(),
            kill_criteria=(),
            required_artifact_ids=(),
            observed_artifact_ids=(),
        )

    with pytest.raises(ValueError, match="unknown case"):
        FalsificationGate(
            gate_id="unknown-case",
            target_id="wave10-campaign",
            negative_control_cases=(case,),
            negative_control_results=(
                _result(
                    "unknown-result",
                    "missing-case",
                    ("operating.traceability.unsupported-assurance-claim",),
                ),
            ),
            kill_criteria=(),
            required_artifact_ids=(),
            observed_artifact_ids=(),
        )


def test_kill_criterion_requires_human_review_for_waiver() -> None:
    with pytest.raises(ValueError, match="human review id and waiver rationale"):
        KillCriterion(
            criterion_id="bad-waiver",
            title="Bad waiver",
            description="A waiver without human review binding must fail.",
            severity=OperatingSeverity.HIGH,
            status=KillCriterionStatus.WAIVED_BY_HUMAN_REVIEW,
            trigger_finding_codes=("operating.trust.freshness-warning",),
            repository_ids=("ix-blackfox",),
            owner_team_id="platform-security",
        )


def _case(
    case_id: str,
    control_type: NegativeControlType,
    expected_codes: tuple[str, ...],
    *,
    required_artifact_ids: tuple[str, ...] = ("negative-control-report",),
    required: bool = True,
) -> NegativeControlCase:
    return NegativeControlCase(
        case_id=case_id,
        control_type=control_type,
        title=f"{case_id} negative control",
        description="The operating gate must block this deliberately bad state.",
        domains=(OperatingDomain.POLICY_GOVERNED, OperatingDomain.REVIEWABLE),
        expected_blocking_finding_codes=expected_codes,
        required_artifact_ids=required_artifact_ids,
        required=required,
    )


def _result(
    result_id: str,
    case_id: str,
    observed_codes: tuple[str, ...],
) -> NegativeControlResult:
    return NegativeControlResult(
        result_id=result_id,
        case_id=case_id,
        outcome=NegativeControlOutcome.PASSED,
        observed_blocking=True,
        observed_finding_codes=observed_codes,
        evidence_artifact_ids=("negative-control-report",),
        checked_by="security-reviewer",
        notes=("The bad state was blocked as expected.",),
    )
