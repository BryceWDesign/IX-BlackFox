from __future__ import annotations

import pytest

from ix_blackfox.operating import (
    BlockerSeverity,
    BlockerStatus,
    OperatingBlocker,
    OperatingDisposition,
    ReadinessGate,
    ReadinessState,
    ReadinessTransition,
)


def test_readiness_gate_is_ready_when_artifacts_reviews_and_blockers_are_closed() -> None:
    closed = OperatingBlocker(
        blocker_id="resolved-policy-gap",
        title="Resolved policy gap",
        summary="Policy coverage was missing and is now resolved.",
        severity=BlockerSeverity.HIGH,
        status=BlockerStatus.CLOSED,
        owner_team_id="platform-security",
        repository_ids=("ix-blackfox",),
        opened_by="security-reviewer",
        artifact_ids=("policy-evaluation",),
        resolution="Policy coverage was added and validated.",
    )
    transition = ReadinessTransition(
        transition_id="blocked-to-ready",
        from_state=ReadinessState.BLOCKED,
        to_state=ReadinessState.READY,
        reason="All blocking evidence and human review requirements were satisfied.",
        authorized_by="security-reviewer",
        blocker_ids=("resolved-policy-gap",),
        evidence_artifact_ids=("policy-evaluation",),
        human_review_ids=("human-review",),
    )
    gate = ReadinessGate(
        gate_id="wave10-readiness",
        target_id="wave10-campaign",
        declared_state=ReadinessState.READY,
        repository_ids=("IX-BlackFox",),
        owner_team_id="Platform Security",
        blockers=(closed,),
        transitions=(transition,),
        required_artifact_ids=("policy-evaluation",),
        observed_artifact_ids=("policy-evaluation",),
        required_human_review_ids=("human-review",),
        observed_human_review_ids=("human-review",),
    )
    same_gate = ReadinessGate(
        gate_id="wave10-readiness",
        target_id="wave10-campaign",
        declared_state=ReadinessState.READY,
        repository_ids=("ix-blackfox",),
        owner_team_id="platform-security",
        blockers=(closed,),
        transitions=(transition,),
        required_artifact_ids=("policy-evaluation",),
        observed_artifact_ids=("policy-evaluation",),
        required_human_review_ids=("human-review",),
        observed_human_review_ids=("human-review",),
    )

    assert gate.gate_id == "wave10-readiness"
    assert gate.repository_ids == ("ix-blackfox",)
    assert gate.blocking_blocker_ids == ()
    assert gate.warning_blocker_ids == ()
    assert gate.missing_artifact_ids == ()
    assert gate.missing_human_review_ids == ()
    assert gate.findings == ()
    assert gate.effective_state is ReadinessState.READY
    assert gate.disposition is OperatingDisposition.READY
    assert gate.to_dict()["digest"] == same_gate.to_dict()["digest"]


def test_readiness_gate_blocks_unresolved_high_and_critical_blockers() -> None:
    high = _blocker("open-high", BlockerSeverity.HIGH)
    critical = _blocker("open-critical", BlockerSeverity.CRITICAL)
    gate = ReadinessGate(
        gate_id="blocked-gate",
        target_id="wave10-campaign",
        declared_state=ReadinessState.READY,
        repository_ids=("ix-blackfox",),
        owner_team_id="platform-security",
        blockers=(critical, high),
    )

    assert gate.blocking_blocker_ids == ("open-critical", "open-high")
    assert gate.effective_state is ReadinessState.BLOCKED
    assert gate.disposition is OperatingDisposition.BLOCKED
    assert {finding.code for finding in gate.findings} == {
        "operating.readiness.unresolved-blocking-blocker",
    }


def test_readiness_gate_warns_on_unresolved_medium_low_or_nonblocking_blockers() -> None:
    medium = _blocker("open-medium", BlockerSeverity.MEDIUM)
    nonblocking_high = _blocker(
        "tracked-high",
        BlockerSeverity.HIGH,
        blocks_readiness=False,
    )
    gate = ReadinessGate(
        gate_id="warning-gate",
        target_id="wave10-campaign",
        declared_state=ReadinessState.WARNING,
        repository_ids=("ix-blackfox",),
        owner_team_id="platform-security",
        blockers=(nonblocking_high, medium),
    )

    assert gate.blocking_blocker_ids == ()
    assert gate.warning_blocker_ids == ("open-medium", "tracked-high")
    assert gate.effective_state is ReadinessState.WARNING
    assert gate.disposition is OperatingDisposition.WARNING
    assert {finding.code for finding in gate.findings} == {
        "operating.readiness.unresolved-warning-blocker",
    }


def test_readiness_gate_blocks_missing_artifacts_reviews_unknown_state_and_ready_transition_gap() -> None:
    transition = ReadinessTransition(
        transition_id="bad-ready-transition",
        from_state=ReadinessState.DEGRADED,
        to_state=ReadinessState.READY,
        reason="This transition should fail because it lacks review binding.",
        authorized_by="security-reviewer",
        evidence_artifact_ids=("policy-evaluation",),
    )
    gate = ReadinessGate(
        gate_id="gap-gate",
        target_id="wave10-campaign",
        declared_state=ReadinessState.UNKNOWN,
        repository_ids=("ix-blackfox",),
        owner_team_id="platform-security",
        transitions=(transition,),
        required_artifact_ids=("policy-evaluation", "replay-validation"),
        observed_artifact_ids=("policy-evaluation",),
        required_human_review_ids=("human-review",),
        observed_human_review_ids=(),
    )

    finding_codes = {finding.code for finding in gate.findings}
    assert finding_codes == {
        "operating.readiness.missing-human-review",
        "operating.readiness.missing-required-artifact",
        "operating.readiness.ready-transition-not-review-bound",
        "operating.readiness.unknown-state",
    }
    assert gate.missing_artifact_ids == ("replay-validation",)
    assert gate.missing_human_review_ids == ("human-review",)
    assert gate.ready_transition_gap_ids == ("bad-ready-transition",)
    assert gate.disposition is OperatingDisposition.BLOCKED


def test_blocker_requires_resolution_or_human_acceptance_for_terminal_states() -> None:
    with pytest.raises(ValueError, match="must include a resolution"):
        OperatingBlocker(
            blocker_id="bad-closed",
            title="Bad closed blocker",
            summary="A closed blocker without resolution must fail.",
            severity=BlockerSeverity.HIGH,
            status=BlockerStatus.CLOSED,
            owner_team_id="platform-security",
            repository_ids=("ix-blackfox",),
            opened_by="security-reviewer",
        )

    with pytest.raises(ValueError, match="human review acceptance"):
        OperatingBlocker(
            blocker_id="bad-accepted-risk",
            title="Bad accepted risk",
            summary="Accepted risk without human review must fail.",
            severity=BlockerSeverity.HIGH,
            status=BlockerStatus.ACCEPTED_RISK,
            owner_team_id="platform-security",
            repository_ids=("ix-blackfox",),
            opened_by="security-reviewer",
            resolution="Risk was accepted by process but lacks the review binding.",
        )


def test_readiness_gate_rejects_duplicate_blockers_unknown_transition_blockers_and_scope_mismatch() -> None:
    blocker = _blocker("duplicate", BlockerSeverity.HIGH)
    with pytest.raises(ValueError, match="blocker_id values must be unique"):
        ReadinessGate(
            gate_id="duplicate-blockers",
            target_id="wave10-campaign",
            declared_state=ReadinessState.BLOCKED,
            repository_ids=("ix-blackfox",),
            owner_team_id="platform-security",
            blockers=(blocker, blocker),
        )

    with pytest.raises(ValueError, match="unknown blocker"):
        ReadinessGate(
            gate_id="unknown-transition-blocker",
            target_id="wave10-campaign",
            declared_state=ReadinessState.BLOCKED,
            repository_ids=("ix-blackfox",),
            owner_team_id="platform-security",
            transitions=(
                ReadinessTransition(
                    transition_id="bad-transition",
                    from_state=ReadinessState.BLOCKED,
                    to_state=ReadinessState.DEGRADED,
                    reason="References a blocker that is not in the gate.",
                    authorized_by="security-reviewer",
                    blocker_ids=("missing",),
                ),
            ),
        )

    with pytest.raises(ValueError, match="does not apply to gate repositories"):
        ReadinessGate(
            gate_id="scope-mismatch",
            target_id="wave10-campaign",
            declared_state=ReadinessState.BLOCKED,
            repository_ids=("ix-blackfox",),
            owner_team_id="platform-security",
            blockers=(
                _blocker(
                    "wrong-repo",
                    BlockerSeverity.HIGH,
                    repository_ids=("other-repo",),
                ),
            ),
        )


def _blocker(
    blocker_id: str,
    severity: BlockerSeverity,
    *,
    blocks_readiness: bool = True,
    repository_ids: tuple[str, ...] = ("ix-blackfox",),
) -> OperatingBlocker:
    return OperatingBlocker(
        blocker_id=blocker_id,
        title=f"{blocker_id} blocker",
        summary="A blocker used by the Wave 10 sustainment tests.",
        severity=severity,
        status=BlockerStatus.OPEN,
        owner_team_id="platform-security",
        repository_ids=repository_ids,
        opened_by="security-reviewer",
        blocks_readiness=blocks_readiness,
    )
