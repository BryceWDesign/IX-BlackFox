from __future__ import annotations

import json

import pytest

from ix_blackfox.authoring import (
    AuthoringEvidence,
    AuthoringEvidenceStrength,
    AuthoringPolicyDecision,
    AuthoringPolicyGate,
    CandidateDisposition,
    CandidateRejectionReason,
    CandidateScoreBreakdown,
    PatchAuthoringResponseParser,
    PatchProposalCompiler,
    RankedRepairCandidate,
    RepairCandidateRanker,
    RepairCandidateRankerConfig,
    RepairCandidateSelectionReport,
    RepairHypothesisEngine,
    RepairTaskDecomposer,
)


def test_ranker_selects_low_risk_allowed_candidate(tmp_path) -> None:
    workspace = tmp_path
    _write(workspace, "src/example.py", "def add(a, b):\n    return a - b\n")

    proposal = _parse_proposal(
        proposal_id="proposal-1",
        path="src/example.py",
        before_text="return a - b",
        after_text="return a + b",
    )
    candidate = PatchProposalCompiler(workspace_root=workspace).compile(proposal)
    evidence = _direct_evidence()
    policy = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        candidate=candidate,
        evidence=(evidence,),
    )

    report = RepairCandidateRanker().rank(
        candidates=(candidate,),
        proposals=(proposal,),
        policy_reports=(policy,),
        evidence=(evidence,),
    )

    assert report.selected_candidate_id == candidate.candidate_id
    assert report.selected_candidate is not None
    assert report.selected_candidate.disposition is CandidateDisposition.SELECTED
    assert report.selected_candidate.score.total_score >= 40.0
    assert report.findings[0].code == "authoring.candidates.candidate_selected"


def test_ranker_preserves_review_required_candidate_without_selecting(tmp_path) -> None:
    workspace = tmp_path
    _write(workspace, "tests/test_example.py", "assert add(2, 2) == 4\n")

    proposal = _parse_proposal(
        proposal_id="proposal-1",
        path="tests/test_example.py",
        before_text="assert add(2, 2) == 4",
        after_text="assert add(2, 2) == 4\nassert add(1, 1) == 2",
    )
    candidate = PatchProposalCompiler(workspace_root=workspace).compile(proposal)
    evidence = _direct_evidence()
    policy = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        candidate=candidate,
        evidence=(evidence,),
    )

    report = RepairCandidateRanker().rank(
        candidates=(candidate,),
        proposals=(proposal,),
        policy_reports=(policy,),
        evidence=(evidence,),
    )

    assert report.selected_candidate_id is None
    assert report.review_required_candidates[0].candidate_id == candidate.candidate_id
    assert CandidateRejectionReason.REVIEW_REQUIRED in report.review_required_candidates[0].rejection_reasons


def test_ranker_preserves_blocked_candidate_without_selecting(tmp_path) -> None:
    workspace = tmp_path
    _write(workspace, "config/api_token.txt", "old\n")

    proposal = _parse_proposal(
        proposal_id="proposal-1",
        path="config/api_token.txt",
        before_text="old",
        after_text="new",
    )
    candidate = PatchProposalCompiler(
        workspace_root=workspace,
    ).compile(proposal)
    evidence = _direct_evidence()
    policy = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        candidate=candidate,
        evidence=(evidence,),
    )

    report = RepairCandidateRanker().rank(
        candidates=(candidate,),
        proposals=(proposal,),
        policy_reports=(policy,),
        evidence=(evidence,),
    )

    assert report.selected_candidate_id is None
    assert report.blocked_candidates[0].disposition is CandidateDisposition.BLOCKED
    assert CandidateRejectionReason.BLOCKED_BY_POLICY in report.blocked_candidates[0].rejection_reasons


def test_ranker_rejects_candidate_when_proposal_is_missing(tmp_path) -> None:
    workspace = tmp_path
    _write(workspace, "src/example.py", "before\n")

    proposal = _parse_proposal(
        proposal_id="proposal-1",
        path="src/example.py",
        before_text="before",
        after_text="after",
    )
    candidate = PatchProposalCompiler(workspace_root=workspace).compile(proposal)
    evidence = _direct_evidence()
    policy = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        candidate=candidate,
        evidence=(evidence,),
    )

    report = RepairCandidateRanker().rank(
        candidates=(candidate,),
        proposals=(),
        policy_reports=(policy,),
        evidence=(evidence,),
    )

    assert report.selected_candidate_id is None
    assert report.ranked_candidates[0].disposition is CandidateDisposition.REJECTED
    assert CandidateRejectionReason.PROPOSAL_NOT_FOUND in report.ranked_candidates[0].rejection_reasons


def test_ranker_rejects_candidate_when_policy_is_missing(tmp_path) -> None:
    workspace = tmp_path
    _write(workspace, "src/example.py", "before\n")

    proposal = _parse_proposal(
        proposal_id="proposal-1",
        path="src/example.py",
        before_text="before",
        after_text="after",
    )
    candidate = PatchProposalCompiler(workspace_root=workspace).compile(proposal)

    report = RepairCandidateRanker().rank(
        candidates=(candidate,),
        proposals=(proposal,),
        policy_reports=(),
        evidence=(_direct_evidence(),),
    )

    assert report.selected_candidate_id is None
    assert CandidateRejectionReason.POLICY_NOT_FOUND in report.ranked_candidates[0].rejection_reasons


def test_ranker_selects_best_candidate_and_rejects_lower_ranked_available_candidate(tmp_path) -> None:
    workspace = tmp_path
    _write(workspace, "src/a.py", "before\n")
    _write(workspace, "src/b.py", "before\n")

    better_proposal = _parse_proposal(
        proposal_id="proposal-better",
        path="src/a.py",
        before_text="before",
        after_text="after",
        confidence=0.90,
    )
    weaker_proposal = _parse_proposal(
        proposal_id="proposal-weaker",
        path="src/b.py",
        before_text="before",
        after_text="after",
        confidence=0.55,
    )

    better_candidate = PatchProposalCompiler(workspace_root=workspace).compile(better_proposal)
    weaker_candidate = PatchProposalCompiler(workspace_root=workspace).compile(weaker_proposal)
    evidence = _direct_evidence()
    better_policy = AuthoringPolicyGate().evaluate(
        proposal=better_proposal,
        candidate=better_candidate,
        evidence=(evidence,),
    )
    weaker_policy = AuthoringPolicyGate().evaluate(
        proposal=weaker_proposal,
        candidate=weaker_candidate,
        evidence=(evidence,),
    )

    report = RepairCandidateRanker().rank(
        candidates=(weaker_candidate, better_candidate),
        proposals=(weaker_proposal, better_proposal),
        policy_reports=(weaker_policy, better_policy),
        evidence=(evidence,),
    )

    assert report.selected_candidate_id == better_candidate.candidate_id
    assert report.ranked_candidates[0].candidate_id == better_candidate.candidate_id
    assert report.ranked_candidates[1].disposition is CandidateDisposition.REJECTED
    assert CandidateRejectionReason.NOT_TOP_RANKED in report.ranked_candidates[1].rejection_reasons


def test_ranker_rejects_low_confidence_candidate(tmp_path) -> None:
    workspace = tmp_path
    _write(workspace, "src/example.py", "before\n")

    proposal = _parse_proposal(
        proposal_id="proposal-low-confidence",
        path="src/example.py",
        before_text="before",
        after_text="after",
        confidence=0.20,
    )
    candidate = PatchProposalCompiler(workspace_root=workspace).compile(proposal)
    evidence = _direct_evidence()
    policy = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        candidate=candidate,
        evidence=(evidence,),
    )

    report = RepairCandidateRanker().rank(
        candidates=(candidate,),
        proposals=(proposal,),
        policy_reports=(policy,),
        evidence=(evidence,),
    )

    assert report.selected_candidate_id is None
    assert CandidateRejectionReason.LOW_CONFIDENCE in report.ranked_candidates[0].rejection_reasons


def test_ranker_rejects_when_no_authorable_hypothesis_exists(tmp_path) -> None:
    workspace = tmp_path
    _write(workspace, "src/example.py", "before\n")

    proposal = _parse_proposal(
        proposal_id="proposal-1",
        path="src/example.py",
        before_text="before",
        after_text="after",
    )
    candidate = PatchProposalCompiler(workspace_root=workspace).compile(proposal)
    evidence = AuthoringEvidence.create(
        source="operator",
        strength=AuthoringEvidenceStrength.WEAK,
        summary="Objective-only evidence.",
    )

    from ix_blackfox.authoring import AuthoringRequest

    request = AuthoringRequest.create(
        task_id="task-1",
        objective="Repair reported issue.",
    )
    request = AuthoringRequest(
        request_id=request.request_id,
        objective=request.objective,
        mode=request.mode,
        status=request.status,
        context=request.context,
        evidence=(),
        subtasks=request.subtasks,
        findings=request.findings,
        metadata=request.metadata,
    )
    hypotheses = RepairHypothesisEngine().generate(request=request)
    policy = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        candidate=candidate,
        evidence=(evidence,),
    )

    report = RepairCandidateRanker().rank(
        candidates=(candidate,),
        proposals=(proposal,),
        policy_reports=(policy,),
        evidence=(evidence,),
        hypotheses=hypotheses,
    )

    assert report.selected_candidate_id is None
    assert CandidateRejectionReason.NO_AUTHORABLE_HYPOTHESIS in report.ranked_candidates[0].rejection_reasons


def test_ranker_rewards_hypothesis_path_match(tmp_path) -> None:
    workspace = tmp_path
    _write(workspace, "src/example.py", "def add(a, b):\n    return a - b\n")

    proposal = _parse_proposal(
        proposal_id="proposal-1",
        path="src/example.py",
        before_text="return a - b",
        after_text="return a + b",
    )
    candidate = PatchProposalCompiler(workspace_root=workspace).compile(proposal)
    evidence = AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="AssertionError: expected addition behavior.",
        raw_text="assert 0 == 4",
        related_paths=("src/example.py",),
    )

    from ix_blackfox.authoring import AuthoringRequest

    request = AuthoringRequest.create(
        task_id="task-1",
        objective="Repair addition behavior.",
    )
    request = AuthoringRequest(
        request_id=request.request_id,
        objective=request.objective,
        mode=request.mode,
        status=request.status,
        context=request.context,
        evidence=(evidence,),
        subtasks=request.subtasks,
        findings=request.findings,
        metadata=request.metadata,
    )
    decomposition = RepairTaskDecomposer().decompose_request(request)
    hypotheses = RepairHypothesisEngine().generate(
        request=request,
        decomposition=decomposition,
    )
    policy = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        candidate=candidate,
        evidence=(evidence,),
    )

    report = RepairCandidateRanker().rank(
        candidates=(candidate,),
        proposals=(proposal,),
        policy_reports=(policy,),
        evidence=(evidence,),
        hypotheses=hypotheses,
    )

    assert report.selected_candidate_id == candidate.candidate_id
    assert report.ranked_candidates[0].score.hypothesis_score > 0


def test_score_breakdown_round_trip() -> None:
    score = CandidateScoreBreakdown(
        candidate_id="candidate-1",
        total_score=70.0,
        confidence_score=20.0,
        policy_score=20.0,
        evidence_score=15.0,
        path_risk_score=5.0,
        patch_size_score=10.0,
        hypothesis_score=10.0,
        review_penalty=0.0,
        reasons=("direct evidence rewarded",),
    )

    restored = CandidateScoreBreakdown.from_dict(score.to_dict())

    assert restored == score


def test_selection_report_rejects_unknown_selected_candidate_id(tmp_path) -> None:
    workspace = tmp_path
    _write(workspace, "src/example.py", "before\n")

    proposal = _parse_proposal(
        proposal_id="proposal-1",
        path="src/example.py",
        before_text="before",
        after_text="after",
    )
    candidate = PatchProposalCompiler(workspace_root=workspace).compile(proposal)
    score = CandidateScoreBreakdown(
        candidate_id=candidate.candidate_id,
        total_score=50.0,
        confidence_score=20.0,
        policy_score=20.0,
        evidence_score=15.0,
        path_risk_score=0.0,
        patch_size_score=10.0,
        hypothesis_score=0.0,
        review_penalty=0.0,
    )
    ranked = RankedRepairCandidate(
        candidate=candidate,
        score=score,
        disposition=CandidateDisposition.AVAILABLE,
        proposal_id=proposal.proposal_id,
        proposal_digest=proposal.digest,
    )

    with pytest.raises(ValueError, match="selected_candidate_id"):
        RepairCandidateSelectionReport(
            report_id="report-1",
            ranked_candidates=(ranked,),
            selected_candidate_id="missing",
        )


def test_ranker_rejects_empty_candidate_iterable() -> None:
    with pytest.raises(ValueError, match="At least one compiled candidate"):
        RepairCandidateRanker().rank(
            candidates=(),
            proposals=(),
        )


def test_ranker_custom_threshold_can_force_low_score_rejection(tmp_path) -> None:
    workspace = tmp_path
    _write(workspace, "src/example.py", "before\n")

    proposal = _parse_proposal(
        proposal_id="proposal-1",
        path="src/example.py",
        before_text="before",
        after_text="after",
    )
    candidate = PatchProposalCompiler(workspace_root=workspace).compile(proposal)
    evidence = _direct_evidence()
    policy = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        candidate=candidate,
        evidence=(evidence,),
    )

    ranker = RepairCandidateRanker(
        config=RepairCandidateRankerConfig(minimum_selectable_score=10_000.0)
    )
    report = ranker.rank(
        candidates=(candidate,),
        proposals=(proposal,),
        policy_reports=(policy,),
        evidence=(evidence,),
    )

    assert report.selected_candidate_id is None
    assert CandidateRejectionReason.LOW_SCORE in report.ranked_candidates[0].rejection_reasons


def _write(workspace, path: str, text: str) -> None:
    file_path = workspace / path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(text, encoding="utf-8")


def _direct_evidence() -> AuthoringEvidence:
    return AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="Direct pytest failure evidence supports the candidate.",
        raw_text="FAILED tests/test_example.py::test_add",
        related_paths=("src/example.py",),
    )


def _parse_proposal(
    *,
    proposal_id: str = "proposal-1",
    path: str = "src/example.py",
    before_text: str = "return a - b",
    after_text: str = "return a + b",
    confidence: float = 0.72,
):
    return PatchAuthoringResponseParser().parse(
        json.dumps(
            {
                "schema_version": "wave3.patch_authoring_response.v1",
                "proposal_id": proposal_id,
                "objective_summary": "Repair the failing behavior.",
                "reasoning_summary": "The proposed source change aligns with the failure evidence.",
                "confidence": confidence,
                "assumptions": [
                    "The compiler must verify before_text.",
                ],
                "risk_notes": [
                    "The patch still requires policy and Wave 2 execution.",
                ],
                "expected_tests": [
                    "The targeted behavior test should pass after governed execution.",
                ],
                "mutations": [
                    {
                        "mutation_id": "mutation-1",
                        "mutation_type": "replace_text",
                        "path": path,
                        "before_text": before_text,
                        "after_text": after_text,
                        "rationale": "Repair source behavior.",
                    }
                ],
            },
            sort_keys=True,
        )
    )
