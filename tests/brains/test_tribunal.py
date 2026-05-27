from __future__ import annotations

import pytest

from ix_blackfox.brains import (
    BrainComparisonCandidate,
    BrainComparisonScore,
    BrainModelTribunal,
    BrainRole,
    BrainTribunalAction,
    BrainTribunalAssignment,
    BrainTribunalDisposition,
    BrainTribunalIdentity,
    BrainTribunalReviewRequest,
    BrainTribunalRole,
    BrainTribunalRoleKind,
)


def test_identity_normalizes_names_and_builds_from_comparison_candidate() -> None:
    candidate = BrainComparisonCandidate(
        brain_name=" Local Generator ",
        provider_name=" Ollama ",
        model_name=" gpt-oss:20b ",
        role=BrainRole.PRIMARY,
        score=BrainComparisonScore(correctness_score=80),
        output_text="candidate patch",
    )
    identity = BrainTribunalIdentity.from_candidate(candidate)

    assert identity.brain_name == "local-generator"
    assert identity.provider_name == "ollama"
    assert identity.model_name == "gpt-oss:20b"
    assert identity.human_operator is False
    assert identity.model_identity_key == ("ollama", "gpt-oss:20b")


def test_identity_detects_same_provider_model_pair() -> None:
    left = BrainTribunalIdentity(
        brain_name="generator-a",
        provider_name="ollama",
        model_name="gpt-oss:20b",
    )
    right = BrainTribunalIdentity(
        brain_name="generator-b",
        provider_name=" Ollama ",
        model_name="gpt-oss:20b",
    )

    assert left.same_model_as(right) is True


def test_role_rejects_nonhuman_approval_authority() -> None:
    with pytest.raises(ValueError, match="only human authority roles may approve"):
        BrainTribunalRole(
            role_id="model-approver",
            role_kind=BrainTribunalRoleKind.CRITIC,
            description="Bad model approver.",
            may_review=True,
            may_approve=True,
        )


def test_human_authority_role_cannot_generate() -> None:
    with pytest.raises(ValueError, match="human authority roles cannot also generate"):
        BrainTribunalRole(
            role_id="human-generator",
            role_kind=BrainTribunalRoleKind.HUMAN_REVIEW_COORDINATOR,
            description="Bad human authority generator.",
            may_generate=True,
            may_review=True,
            may_approve=True,
            human_authority_role=True,
        )


def test_role_must_allow_at_least_one_action() -> None:
    with pytest.raises(ValueError, match="must allow at least one action"):
        BrainTribunalRole(
            role_id="empty-role",
            role_kind=BrainTribunalRoleKind.CRITIC,
            description="No permitted actions.",
        )


def test_assignment_rejects_human_authority_role_without_human_identity() -> None:
    with pytest.raises(ValueError, match="must be assigned to a human operator"):
        BrainTribunalAssignment(
            assignment_id="human-reviewer",
            role=_human_role(),
            identity=_identity("model-reviewer"),
        )


def test_assignment_rejects_human_identity_on_model_role() -> None:
    with pytest.raises(ValueError, match="must use a human authority role"):
        BrainTribunalAssignment(
            assignment_id="model-critic",
            role=_critic_role(),
            identity=_identity("human-reviewer", human_operator=True),
        )


def test_tribunal_routes_generated_candidate_to_separated_critic() -> None:
    request = _review_request(
        generated_by=_identity("generator", provider_name="ollama", model_name="gpt-oss:20b"),
        originating_role_id="generator-role",
    )
    assignments = (
        _assignment(
            "generator-assignment",
            _generator_role(),
            _identity("generator", provider_name="ollama", model_name="gpt-oss:20b"),
        ),
        _assignment(
            "critic-assignment",
            _critic_role(),
            _identity("critic", provider_name="vllm", model_name="critic-model"),
        ),
    )

    decision = BrainModelTribunal().route_review(request, assignments)

    assert decision.disposition is BrainTribunalDisposition.ROUTED
    assert decision.selected_brain_name == "critic"
    assert decision.selected_assignment is not None
    assert decision.selected_assignment.role.role_kind is BrainTribunalRoleKind.CRITIC


def test_tribunal_blocks_same_brain_and_same_model_self_review() -> None:
    generated_by = _identity(
        "generator",
        provider_name="ollama",
        model_name="gpt-oss:20b",
    )
    request = _review_request(generated_by=generated_by)
    assignments = (
        _assignment("self-critic", _critic_role(), generated_by),
    )

    decision = BrainModelTribunal().route_review(request, assignments)

    assert decision.disposition is BrainTribunalDisposition.BLOCKED
    finding = decision.findings[0]
    assert "self-review blocked for brain: generator" in finding.reasons
    assert "self-review blocked for provider/model: ollama/gpt-oss:20b" in (
        finding.reasons
    )


def test_tribunal_blocks_originating_role_from_reviewing_itself() -> None:
    request = _review_request(
        generated_by=_identity("generator"),
        originating_role_id="critic-role",
    )
    assignments = (
        _assignment(
            "critic-assignment",
            _critic_role(role_id="critic-role"),
            _identity("critic"),
        ),
    )

    decision = BrainModelTribunal().route_review(request, assignments)

    assert decision.disposition is BrainTribunalDisposition.BLOCKED
    assert "originating role cannot review itself: critic-role" in (
        decision.findings[0].reasons
    )


def test_tribunal_honors_required_role_kinds() -> None:
    request = _review_request(
        generated_by=_identity("generator"),
        required_role_kinds=(BrainTribunalRoleKind.SECURITY_REVIEWER,),
    )
    assignments = (
        _assignment("critic-assignment", _critic_role(), _identity("critic")),
        _assignment(
            "security-assignment",
            _security_role(),
            _identity("security-reviewer"),
        ),
    )

    decision = BrainModelTribunal().route_review(request, assignments)

    assert decision.disposition is BrainTribunalDisposition.ROUTED
    assert decision.selected_brain_name == "security-reviewer"
    blocked_critic = decision.findings[0]
    assert "role kind is not allowed: critic" in blocked_critic.reasons


def test_tribunal_requires_human_authority_when_requested() -> None:
    request = _review_request(
        generated_by=_identity("generator"),
        human_authority_required=True,
    )
    assignments = (
        _assignment("critic-assignment", _critic_role(), _identity("critic")),
        _assignment(
            "human-assignment",
            _human_role(),
            _identity("human-reviewer", human_operator=True),
        ),
    )

    decision = BrainModelTribunal().route_review(request, assignments)

    assert decision.disposition is BrainTribunalDisposition.ROUTED
    assert decision.selected_brain_name == "human-reviewer"
    assert decision.selected_assignment is not None
    assert decision.selected_assignment.role.human_authority_role is True


def test_tribunal_approval_routes_only_to_human_authority() -> None:
    request = BrainTribunalReviewRequest(
        request_id="approval-request",
        generated_by=_identity("generator"),
        action=BrainTribunalAction.APPROVE,
    )
    assignments = (
        _assignment("critic-assignment", _critic_role(), _identity("critic")),
        _assignment(
            "human-assignment",
            _human_role(),
            _identity("human-reviewer", human_operator=True),
        ),
    )

    decision = BrainModelTribunal().route_review(request, assignments)

    assert decision.disposition is BrainTribunalDisposition.ROUTED
    assert decision.selected_brain_name == "human-reviewer"
    assert "role cannot perform action: critic-role=approve" in (
        decision.findings[0].reasons
    )


def test_tribunal_returns_review_required_when_human_authority_has_no_route() -> None:
    request = _review_request(
        generated_by=_identity("generator"),
        human_authority_required=True,
    )
    assignments = (
        _assignment("critic-assignment", _critic_role(), _identity("critic")),
    )

    decision = BrainModelTribunal().route_review(request, assignments)

    assert decision.disposition is BrainTribunalDisposition.REVIEW_REQUIRED
    assert decision.selected_assignment is None
    assert decision.selected_brain_name is None


def test_tribunal_blocks_disabled_assignments() -> None:
    request = _review_request(generated_by=_identity("generator"))
    assignments = (
        _assignment(
            "critic-assignment",
            _critic_role(),
            _identity("critic"),
            enabled=False,
        ),
    )

    decision = BrainModelTribunal().route_review(request, assignments)

    assert decision.disposition is BrainTribunalDisposition.BLOCKED
    assert "assignment is disabled: critic-assignment" in decision.findings[0].reasons


def test_tribunal_decision_serializes_review_evidence() -> None:
    request = _review_request(generated_by=_identity("generator"))
    assignments = (
        _assignment("critic-assignment", _critic_role(), _identity("critic")),
    )

    decision = BrainModelTribunal().route_review(request, assignments)
    payload = decision.to_dict()

    assert payload["disposition"] == "routed"
    assert payload["selected_brain_name"] == "critic"
    assert payload["request"]["generated_by"]["brain_name"] == "generator"
    assert payload["findings"][0]["eligible"] is True


def _identity(
    brain_name: str,
    *,
    provider_name: str = "ollama",
    model_name: str | None = None,
    human_operator: bool = False,
) -> BrainTribunalIdentity:
    return BrainTribunalIdentity(
        brain_name=brain_name,
        provider_name=provider_name,
        model_name=model_name or brain_name,
        human_operator=human_operator,
    )


def _generator_role(role_id: str = "generator-role") -> BrainTribunalRole:
    return BrainTribunalRole(
        role_id=role_id,
        role_kind=BrainTribunalRoleKind.GENERATOR,
        description="Generates repair candidates.",
        may_generate=True,
    )


def _critic_role(role_id: str = "critic-role") -> BrainTribunalRole:
    return BrainTribunalRole(
        role_id=role_id,
        role_kind=BrainTribunalRoleKind.CRITIC,
        description="Reviews generated repair candidates.",
        may_review=True,
    )


def _security_role(role_id: str = "security-role") -> BrainTribunalRole:
    return BrainTribunalRole(
        role_id=role_id,
        role_kind=BrainTribunalRoleKind.SECURITY_REVIEWER,
        description="Reviews security impact of repair candidates.",
        may_review=True,
    )


def _human_role(role_id: str = "human-role") -> BrainTribunalRole:
    return BrainTribunalRole(
        role_id=role_id,
        role_kind=BrainTribunalRoleKind.HUMAN_REVIEW_COORDINATOR,
        description="Coordinates explicit human authority.",
        may_review=True,
        may_approve=True,
        human_authority_role=True,
    )


def _assignment(
    assignment_id: str,
    role: BrainTribunalRole,
    identity: BrainTribunalIdentity,
    *,
    enabled: bool = True,
) -> BrainTribunalAssignment:
    return BrainTribunalAssignment(
        assignment_id=assignment_id,
        role=role,
        identity=identity,
        enabled=enabled,
    )


def _review_request(
    *,
    generated_by: BrainTribunalIdentity,
    originating_role_id: str | None = None,
    required_role_kinds: tuple[BrainTribunalRoleKind, ...] = (),
    human_authority_required: bool = False,
) -> BrainTribunalReviewRequest:
    return BrainTribunalReviewRequest(
        request_id="review-request",
        generated_by=generated_by,
        action=BrainTribunalAction.REVIEW,
        originating_role_id=originating_role_id,
        required_role_kinds=required_role_kinds,
        human_authority_required=human_authority_required,
    )
