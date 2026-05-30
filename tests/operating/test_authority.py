from __future__ import annotations

import pytest

from ix_blackfox.operating import (
    ApprovalQuorum,
    OperatingDisposition,
    OperatingDomain,
    OperatingTeam,
    ReviewBoard,
    ReviewDecision,
    ReviewerAuthority,
    ReviewerKind,
    TeamReviewDecision,
    TeamRole,
)


def test_review_board_accepts_multi_team_human_authority_and_deterministic_digest() -> None:
    security_team = OperatingTeam(
        team_id=" Security Team ",
        name="Product Security",
        roles=(TeamRole.SECURITY_REVIEWER,),
        owned_repository_ids=("IX-BlackFox",),
    )
    release_team = OperatingTeam(
        team_id="Release Team",
        name="Release Management",
        roles=(TeamRole.RELEASE_MANAGER,),
        owned_repository_ids=("IX-BlackFox",),
    )
    security_reviewer = _authority(
        reviewer_id=" Alice.Security ",
        team_id="security-team",
        roles=(TeamRole.SECURITY_REVIEWER,),
    )
    release_reviewer = _authority(
        reviewer_id=" Bob.Release ",
        team_id="release-team",
        roles=(TeamRole.RELEASE_MANAGER,),
    )
    quorum = ApprovalQuorum(
        quorum_id=" Wave 10 Final Approval ",
        repository_ids=("IX-BlackFox",),
        domains=(OperatingDomain.MULTI_TEAM, OperatingDomain.REVIEWABLE),
        required_roles=(TeamRole.SECURITY_REVIEWER, TeamRole.RELEASE_MANAGER),
        minimum_approvals=2,
        required_human_approvals=2,
        required_distinct_teams=2,
    )
    first_decision = _decision("security-approval", "alice.security")
    second_decision = _decision("release-approval", "bob.release")

    board = ReviewBoard(
        board_id=" Wave 10 Board ",
        teams=(release_team, security_team),
        reviewer_authorities=(release_reviewer, security_reviewer),
        quorums=(quorum,),
        decisions=(second_decision, first_decision),
    )
    same_board = ReviewBoard(
        board_id="wave-10-board",
        teams=(security_team, release_team),
        reviewer_authorities=(security_reviewer, release_reviewer),
        quorums=(quorum,),
        decisions=(first_decision, second_decision),
    )

    assert board.board_id == "wave-10-board"
    assert board.team_ids == ("release-team", "security-team")
    assert board.reviewer_ids == ("alice.security", "bob.release")
    assert board.findings == ()
    assert board.authoritative_approval_count == 2
    assert board.to_envelope().disposition is OperatingDisposition.READY
    assert board.to_dict()["digest"] == same_board.to_dict()["digest"]


def test_review_board_blocks_model_system_self_approval_and_missing_evidence() -> None:
    team = OperatingTeam(
        team_id="platform-security",
        name="Platform Security",
        roles=(TeamRole.SECURITY_REVIEWER, TeamRole.DEVSECOPS_OPERATOR),
    )
    human = _authority("human-reviewer", "platform-security", (TeamRole.SECURITY_REVIEWER,))
    model = _authority(
        "model-reviewer",
        "platform-security",
        (TeamRole.DEVSECOPS_OPERATOR,),
        reviewer_kind=ReviewerKind.MODEL,
    )
    system = _authority(
        "system-reviewer",
        "platform-security",
        (TeamRole.QA_VERIFIER,),
        reviewer_kind=ReviewerKind.SYSTEM,
    )
    quorum = ApprovalQuorum(
        quorum_id="human-security-quorum",
        repository_ids=("ix-blackfox",),
        domains=(OperatingDomain.MULTI_TEAM,),
        required_roles=(TeamRole.SECURITY_REVIEWER,),
    )
    board = ReviewBoard(
        board_id="blocked-board",
        teams=(team,),
        reviewer_authorities=(human, model, system),
        quorums=(quorum,),
        decisions=(
            _decision("self-approval", "human-reviewer", author_id="human-reviewer"),
            _decision("model-approval", "model-reviewer"),
            _decision("system-approval", "system-reviewer"),
            _decision("missing-evidence", "human-reviewer", evidence_artifact_ids=()),
        ),
    )

    finding_codes = {finding.code for finding in board.findings}
    assert "operating.authority.self-approval-attempt" in finding_codes
    assert "operating.authority.model-approval-attempt" in finding_codes
    assert "operating.authority.system-approval-attempt" in finding_codes
    assert "operating.authority.approval-missing-evidence" in finding_codes
    assert "operating.authority.quorum-minimum-not-met" in finding_codes
    assert board.to_envelope().disposition is OperatingDisposition.BLOCKED
    assert board.authoritative_approval_count == 0


def test_review_board_blocks_out_of_scope_and_inactive_approval() -> None:
    team = OperatingTeam(
        team_id="security-team",
        name="Security Team",
        roles=(TeamRole.SECURITY_REVIEWER,),
    )
    inactive = ReviewerAuthority(
        reviewer_id="inactive-reviewer",
        reviewer_kind=ReviewerKind.HUMAN,
        team_id="security-team",
        roles=(TeamRole.SECURITY_REVIEWER,),
        approved_repository_ids=("ix-blackfox",),
        approved_domains=(OperatingDomain.MULTI_TEAM,),
        active=False,
    )
    scoped = ReviewerAuthority(
        reviewer_id="scoped-reviewer",
        reviewer_kind=ReviewerKind.HUMAN,
        team_id="security-team",
        roles=(TeamRole.SECURITY_REVIEWER,),
        approved_repository_ids=("ix-blackfox",),
        approved_domains=(OperatingDomain.MULTI_TEAM,),
    )
    quorum = ApprovalQuorum(
        quorum_id="security-quorum",
        repository_ids=("ix-blackfox",),
        domains=(OperatingDomain.MULTI_TEAM,),
        required_roles=(TeamRole.SECURITY_REVIEWER,),
    )
    board = ReviewBoard(
        board_id="scope-board",
        teams=(team,),
        reviewer_authorities=(inactive, scoped),
        quorums=(quorum,),
        decisions=(
            _decision("inactive-decision", "inactive-reviewer"),
            _decision(
                "wrong-domain",
                "scoped-reviewer",
                domains=(OperatingDomain.REPLAYABLE,),
            ),
        ),
    )

    finding_codes = {finding.code for finding in board.findings}
    assert "operating.authority.inactive-reviewer-approval" in finding_codes
    assert "operating.authority.out-of-scope-approval" in finding_codes
    assert board.disposition == "blocked"
    assert board.authoritative_approvals(repository_id="ix-blackfox") == ()


def test_review_board_blocks_quorum_role_and_distinct_team_gaps() -> None:
    team = OperatingTeam(
        team_id="security-team",
        name="Security Team",
        roles=(TeamRole.SECURITY_REVIEWER,),
    )
    reviewer = _authority(
        reviewer_id="security-reviewer",
        team_id="security-team",
        roles=(TeamRole.SECURITY_REVIEWER,),
    )
    quorum = ApprovalQuorum(
        quorum_id="two-team-quorum",
        repository_ids=("ix-blackfox",),
        domains=(OperatingDomain.MULTI_TEAM,),
        required_roles=(TeamRole.SECURITY_REVIEWER, TeamRole.RELEASE_MANAGER),
        minimum_approvals=2,
        required_human_approvals=2,
        required_distinct_teams=2,
    )
    board = ReviewBoard(
        board_id="quorum-gap-board",
        teams=(team,),
        reviewer_authorities=(reviewer,),
        quorums=(quorum,),
        decisions=(_decision("security-approval", "security-reviewer"),),
    )

    finding_codes = {finding.code for finding in board.findings}
    assert "operating.authority.quorum-minimum-not-met" in finding_codes
    assert "operating.authority.quorum-human-approval-not-met" in finding_codes
    assert "operating.authority.quorum-distinct-team-not-met" in finding_codes
    assert "operating.authority.quorum-required-role-not-met" in finding_codes
    assert board.to_dict()["authoritative_approval_count"] == 1


def test_review_board_rejects_unknown_team_unknown_reviewer_and_duplicate_decisions() -> None:
    team = OperatingTeam(
        team_id="security-team",
        name="Security Team",
        roles=(TeamRole.SECURITY_REVIEWER,),
    )
    authority = _authority("security-reviewer", "security-team", (TeamRole.SECURITY_REVIEWER,))
    unknown_team_authority = _authority("bad-reviewer", "missing-team", (TeamRole.SECURITY_REVIEWER,))
    quorum = ApprovalQuorum(
        quorum_id="security-quorum",
        repository_ids=("ix-blackfox",),
        domains=(OperatingDomain.MULTI_TEAM,),
        required_roles=(TeamRole.SECURITY_REVIEWER,),
    )

    with pytest.raises(ValueError, match="unknown team"):
        ReviewBoard(
            board_id="unknown-team",
            teams=(team,),
            reviewer_authorities=(unknown_team_authority,),
            quorums=(quorum,),
        )

    with pytest.raises(ValueError, match="unknown reviewer"):
        ReviewBoard(
            board_id="unknown-reviewer",
            teams=(team,),
            reviewer_authorities=(authority,),
            quorums=(quorum,),
            decisions=(_decision("unknown", "missing-reviewer"),),
        )

    duplicate = _decision("duplicate", "security-reviewer")
    with pytest.raises(ValueError, match="decision_id values must be unique"):
        ReviewBoard(
            board_id="duplicate-decisions",
            teams=(team,),
            reviewer_authorities=(authority,),
            quorums=(quorum,),
            decisions=(duplicate, duplicate),
        )


def test_authority_and_quorum_require_explicit_scope() -> None:
    with pytest.raises(ValueError, match="approved_repository_ids"):
        ReviewerAuthority(
            reviewer_id="reviewer",
            reviewer_kind=ReviewerKind.HUMAN,
            team_id="team",
            roles=(TeamRole.SECURITY_REVIEWER,),
            approved_repository_ids=(),
            approved_domains=(OperatingDomain.MULTI_TEAM,),
        )

    with pytest.raises(ValueError, match="required_human_approvals cannot exceed"):
        ApprovalQuorum(
            quorum_id="bad-quorum",
            repository_ids=("ix-blackfox",),
            domains=(OperatingDomain.MULTI_TEAM,),
            required_roles=(TeamRole.SECURITY_REVIEWER,),
            minimum_approvals=1,
            required_human_approvals=2,
        )


def _authority(
    reviewer_id: str,
    team_id: str,
    roles: tuple[TeamRole, ...],
    *,
    reviewer_kind: ReviewerKind = ReviewerKind.HUMAN,
) -> ReviewerAuthority:
    return ReviewerAuthority(
        reviewer_id=reviewer_id,
        reviewer_kind=reviewer_kind,
        team_id=team_id,
        roles=roles,
        approved_repository_ids=("ix-blackfox",),
        approved_domains=(OperatingDomain.MULTI_TEAM, OperatingDomain.REVIEWABLE),
    )


def _decision(
    decision_id: str,
    reviewer_id: str,
    *,
    author_id: str = "model-proposer",
    domains: tuple[OperatingDomain, ...] = (OperatingDomain.MULTI_TEAM, OperatingDomain.REVIEWABLE),
    evidence_artifact_ids: tuple[str, ...] = ("wave9-governance-report",),
) -> TeamReviewDecision:
    return TeamReviewDecision(
        decision_id=decision_id,
        reviewer_id=reviewer_id,
        decision=ReviewDecision.APPROVED,
        repository_ids=("ix-blackfox",),
        domains=domains,
        subject_id="wave10-campaign",
        subject_author_id=author_id,
        evidence_artifact_ids=evidence_artifact_ids,
        rationale="Approval is bound to evidence and reviewed under Wave 10 authority.",
    )
