from __future__ import annotations

import json

from ix_blackfox.authoring import (
    AuthoringEvidence,
    AuthoringEvidenceStrength,
    AuthoringFindingSeverity,
    AuthoringPolicyDecision,
    AuthoringPolicyFinding,
    AuthoringPolicyFindingCode,
    AuthoringPolicyGate,
    AuthoringPolicyGateConfig,
    AuthoringPolicyReport,
    AuthoringRiskLevel,
    PatchAuthoringResponseParser,
    PatchProposalCompiler,
)


def test_policy_gate_allows_low_risk_direct_evidence_source_patch(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()
    (workspace / "src" / "example.py").write_text(
        "def add(a, b):\n    return a - b\n",
        encoding="utf-8",
    )
    proposal = _parse_proposal(
        mutations=[
            {
                "mutation_id": "mutation-1",
                "mutation_type": "replace_text",
                "path": "src/example.py",
                "before_text": "return a - b",
                "after_text": "return a + b",
                "rationale": "Repair source behavior.",
            }
        ]
    )
    evidence = _direct_evidence()
    candidate = PatchProposalCompiler(workspace_root=workspace).compile(proposal)

    report = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        candidate=candidate,
        evidence=(evidence,),
    )

    assert report.decision is AuthoringPolicyDecision.ALLOW
    assert report.allowed
    assert not report.blocked
    assert AuthoringPolicyFindingCode.ALLOWED_LOW_RISK.value in report.finding_codes


def test_policy_gate_requires_review_for_test_mutation() -> None:
    proposal = _parse_proposal(
        mutations=[
            {
                "mutation_id": "mutation-1",
                "mutation_type": "replace_text",
                "path": "tests/test_example.py",
                "before_text": "assert add(2, 2) == 4",
                "after_text": "assert add(2, 2) == 4\nassert add(1, 1) == 2",
                "rationale": "Add test coverage.",
            }
        ]
    )

    report = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        evidence=(_direct_evidence(),),
    )

    assert report.decision is AuthoringPolicyDecision.REQUIRE_REVIEW
    assert report.requires_review
    assert AuthoringPolicyFindingCode.TEST_MUTATION_REQUIRES_REVIEW.value in report.finding_codes


def test_policy_gate_detects_test_weakening() -> None:
    proposal = _parse_proposal(
        mutations=[
            {
                "mutation_id": "mutation-1",
                "mutation_type": "replace_text",
                "path": "tests/test_example.py",
                "before_text": "def test_add():\n    assert add(2, 2) == 4\n",
                "after_text": "def test_add():\n    pytest.skip('not needed')\n",
                "rationale": "Skip the failing test.",
            }
        ]
    )

    report = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        evidence=(_direct_evidence(),),
    )

    assert report.decision is AuthoringPolicyDecision.REQUIRE_REVIEW
    assert AuthoringPolicyFindingCode.TEST_WEAKENING_RISK.value in report.finding_codes


def test_policy_gate_blocks_secret_like_path() -> None:
    proposal = _parse_proposal(
        mutations=[
            {
                "mutation_id": "mutation-1",
                "mutation_type": "create_file",
                "path": "config/api_token.txt",
                "before_text": "",
                "after_text": "TOKEN=abc\n",
                "rationale": "Create token file.",
            }
        ]
    )

    report = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        evidence=(_direct_evidence(),),
    )

    assert report.decision is AuthoringPolicyDecision.BLOCK
    assert report.blocked
    assert AuthoringPolicyFindingCode.SECRET_LIKE_PATH.value in report.finding_codes


def test_policy_gate_blocks_blocked_root() -> None:
    proposal = _parse_proposal(
        mutations=[
            {
                "mutation_id": "mutation-1",
                "mutation_type": "create_file",
                "path": "run_bundles/fake_receipt.json",
                "before_text": "",
                "after_text": "{}\n",
                "rationale": "Create fake receipt.",
            }
        ]
    )

    report = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        evidence=(_direct_evidence(),),
    )

    assert report.decision is AuthoringPolicyDecision.BLOCK
    assert AuthoringPolicyFindingCode.BLOCKED_PATH.value in report.finding_codes
    assert AuthoringPolicyFindingCode.RECEIPT_LOGIC_REQUIRES_REVIEW.value in report.finding_codes


def test_policy_gate_requires_review_for_governance_path() -> None:
    proposal = _parse_proposal(
        mutations=[
            {
                "mutation_id": "mutation-1",
                "mutation_type": "replace_text",
                "path": "src/ix_blackfox/runtime/wave2_acceptance.py",
                "before_text": "required = True",
                "after_text": "required = False",
                "rationale": "Change acceptance logic.",
            }
        ]
    )

    report = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        evidence=(_direct_evidence(),),
    )

    assert report.decision is AuthoringPolicyDecision.REQUIRE_REVIEW
    assert AuthoringPolicyFindingCode.GOVERNANCE_PATH_REQUIRES_REVIEW.value in report.finding_codes
    assert AuthoringPolicyFindingCode.ACCEPTANCE_LOGIC_REQUIRES_REVIEW.value in report.finding_codes


def test_policy_gate_requires_review_for_dependency_config() -> None:
    proposal = _parse_proposal(
        mutations=[
            {
                "mutation_id": "mutation-1",
                "mutation_type": "replace_text",
                "path": "pyproject.toml",
                "before_text": "[project]\nname = 'x'\n",
                "after_text": "[project]\nname = 'x'\ndependencies = ['new']\n",
                "rationale": "Add dependency.",
            }
        ]
    )

    report = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        evidence=(_direct_evidence(),),
    )

    assert report.decision is AuthoringPolicyDecision.REQUIRE_REVIEW
    assert AuthoringPolicyFindingCode.DEPENDENCY_CONFIG_REQUIRES_REVIEW.value in report.finding_codes


def test_policy_gate_requires_review_for_ci_workflow() -> None:
    proposal = _parse_proposal(
        mutations=[
            {
                "mutation_id": "mutation-1",
                "mutation_type": "create_file",
                "path": ".github/workflows/ci.yml",
                "before_text": "",
                "after_text": "name: CI\n",
                "rationale": "Create workflow.",
            }
        ]
    )

    report = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        evidence=(_direct_evidence(),),
    )

    assert report.decision is AuthoringPolicyDecision.REQUIRE_REVIEW
    assert AuthoringPolicyFindingCode.CI_WORKFLOW_REQUIRES_REVIEW.value in report.finding_codes
    assert AuthoringPolicyFindingCode.CREATE_FILE_REQUIRES_REVIEW.value in report.finding_codes


def test_policy_gate_requires_review_for_executable_script() -> None:
    proposal = _parse_proposal(
        mutations=[
            {
                "mutation_id": "mutation-1",
                "mutation_type": "create_file",
                "path": "scripts/run.sh",
                "before_text": "",
                "after_text": "echo ok\n",
                "rationale": "Create script.",
            }
        ]
    )

    report = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        evidence=(_direct_evidence(),),
    )

    assert report.decision is AuthoringPolicyDecision.REQUIRE_REVIEW
    assert AuthoringPolicyFindingCode.EXECUTABLE_SCRIPT_REQUIRES_REVIEW.value in report.finding_codes


def test_policy_gate_requires_review_for_low_confidence() -> None:
    proposal = _parse_proposal(confidence=0.25)

    report = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        evidence=(_direct_evidence(),),
    )

    assert report.decision is AuthoringPolicyDecision.REQUIRE_REVIEW
    assert AuthoringPolicyFindingCode.LOW_CONFIDENCE_REQUIRES_REVIEW.value in report.finding_codes


def test_policy_gate_requires_review_for_missing_evidence() -> None:
    proposal = _parse_proposal()

    report = AuthoringPolicyGate().evaluate(proposal=proposal)

    assert report.decision is AuthoringPolicyDecision.REQUIRE_REVIEW
    assert report.evidence_strength is None
    assert AuthoringPolicyFindingCode.MISSING_EVIDENCE_REQUIRES_REVIEW.value in report.finding_codes


def test_policy_gate_requires_review_for_weak_evidence() -> None:
    proposal = _parse_proposal()
    evidence = AuthoringEvidence.create(
        source="operator",
        strength=AuthoringEvidenceStrength.WEAK,
        summary="Operator reported a failure.",
    )

    report = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        evidence=(evidence,),
    )

    assert report.decision is AuthoringPolicyDecision.REQUIRE_REVIEW
    assert report.evidence_strength is AuthoringEvidenceStrength.WEAK
    assert AuthoringPolicyFindingCode.WEAK_EVIDENCE_REQUIRES_REVIEW.value in report.finding_codes


def test_policy_gate_blocks_unsafe_content() -> None:
    proposal = _parse_proposal(
        mutations=[
            {
                "mutation_id": "mutation-1",
                "mutation_type": "replace_text",
                "path": "src/example.py",
                "before_text": "def run():\n    return None\n",
                "after_text": "def run():\n    os.system('echo bad')\n",
                "rationale": "Use dynamic execution.",
            }
        ]
    )

    report = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        evidence=(_direct_evidence(),),
    )

    assert report.decision is AuthoringPolicyDecision.BLOCK
    assert AuthoringPolicyFindingCode.UNSAFE_CONTENT_BLOCKED.value in report.finding_codes


def test_policy_gate_blocks_delete_like_language() -> None:
    proposal = _parse_proposal(
        mutations=[
            {
                "mutation_id": "mutation-1",
                "mutation_type": "replace_text",
                "path": "src/example.py",
                "before_text": "VALUE = 1\n",
                "after_text": "VALUE = 2\n",
                "rationale": "Delete assertion to make this pass.",
            }
        ]
    )

    report = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        evidence=(_direct_evidence(),),
    )

    assert report.decision is AuthoringPolicyDecision.BLOCK
    assert AuthoringPolicyFindingCode.DELETE_LIKE_MUTATION_BLOCKED.value in report.finding_codes


def test_policy_gate_requires_review_for_large_patch() -> None:
    proposal = _parse_proposal(
        mutations=[
            {
                "mutation_id": f"mutation-{index}",
                "mutation_type": "create_file",
                "path": f"src/file_{index}.py",
                "before_text": "",
                "after_text": f"VALUE = {index}\n",
                "rationale": "Create file.",
            }
            for index in range(5)
        ]
    )
    gate = AuthoringPolicyGate(
        config=AuthoringPolicyGateConfig(require_review_for_create_file=False)
    )

    report = gate.evaluate(
        proposal=proposal,
        evidence=(_direct_evidence(),),
    )

    assert report.decision is AuthoringPolicyDecision.REQUIRE_REVIEW
    assert AuthoringPolicyFindingCode.LARGE_PATCH_REQUIRES_REVIEW.value in report.finding_codes


def test_policy_gate_blocks_candidate_proposal_mismatch(tmp_path) -> None:
    workspace = tmp_path
    (workspace / "src").mkdir()
    (workspace / "src" / "example.py").write_text("before\n", encoding="utf-8")

    proposal = _parse_proposal(
        mutations=[
            {
                "mutation_id": "mutation-1",
                "mutation_type": "replace_text",
                "path": "src/example.py",
                "before_text": "before",
                "after_text": "after",
                "rationale": "Update source.",
            }
        ]
    )
    candidate = PatchProposalCompiler(workspace_root=workspace).compile(proposal)

    tampered_candidate = type(candidate)(
        candidate_id=candidate.candidate_id,
        status=candidate.status,
        proposal_id="different-proposal",
        proposal_digest=candidate.proposal_digest,
        patch_diff=candidate.patch_diff,
        findings=candidate.findings,
        metadata=candidate.metadata,
    )

    report = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        candidate=tampered_candidate,
        evidence=(_direct_evidence(),),
    )

    assert report.decision is AuthoringPolicyDecision.BLOCK
    assert AuthoringPolicyFindingCode.CANDIDATE_PROPOSAL_MISMATCH.value in report.finding_codes


def test_policy_report_round_trip_preserves_decision() -> None:
    proposal = _parse_proposal()
    report = AuthoringPolicyGate().evaluate(
        proposal=proposal,
        evidence=(_direct_evidence(),),
    )

    restored = AuthoringPolicyReport.from_dict(report.to_dict())

    assert restored.report_id == report.report_id
    assert restored.decision is report.decision
    assert restored.proposal_id == report.proposal_id
    assert restored.proposal_digest == report.proposal_digest
    assert restored.affected_paths == report.affected_paths
    assert restored.finding_codes == report.finding_codes


def test_policy_finding_converts_to_authoring_finding() -> None:
    finding = AuthoringPolicyFinding(
        code=AuthoringPolicyFindingCode.TEST_MUTATION_REQUIRES_REVIEW,
        decision=AuthoringPolicyDecision.REQUIRE_REVIEW,
        severity=AuthoringFindingSeverity.WARNING,
        summary="Test mutation requires review.",
        path="tests/test_example.py",
        risk_level=AuthoringRiskLevel.MODERATE,
    )

    authoring_finding = finding.to_authoring_finding()

    assert authoring_finding.code == "authoring.policy.test_mutation_requires_review"
    assert authoring_finding.path == "tests/test_example.py"
    assert authoring_finding.metadata["decision"] == "require_review"


def _direct_evidence() -> AuthoringEvidence:
    return AuthoringEvidence.create(
        source="pytest",
        strength=AuthoringEvidenceStrength.DIRECT,
        summary="Direct pytest failure evidence supports the patch.",
        raw_text="FAILED tests/test_example.py::test_add",
        related_paths=("src/example.py",),
    )


def _parse_proposal(
    *,
    mutations: list[dict[str, object]] | None = None,
    confidence: float = 0.72,
):
    return PatchAuthoringResponseParser().parse(
        json.dumps(
            {
                "schema_version": "wave3.patch_authoring_response.v1",
                "proposal_id": "proposal-1",
                "objective_summary": "Repair the failing addition behavior.",
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
                "mutations": mutations
                if mutations is not None
                else [
                    {
                        "mutation_id": "mutation-1",
                        "mutation_type": "replace_text",
                        "path": "src/example.py",
                        "before_text": "return a - b",
                        "after_text": "return a + b",
                        "rationale": "Repair source behavior.",
                    }
                ],
            },
            sort_keys=True,
        )
    )
