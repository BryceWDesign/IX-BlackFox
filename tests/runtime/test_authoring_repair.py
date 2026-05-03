from __future__ import annotations

import json

from ix_blackfox.runtime.authoring_repair import (
    AuthoredRepairRuntime,
    AuthoredRepairRuntimeConfig,
    AuthoredRepairStatus,
    NullPatchProposalProvider,
    StaticPatchProposalProvider,
)


def test_authored_repair_runtime_selects_governed_patch_candidate(tmp_path) -> None:
    workspace = tmp_path
    _write(workspace, "src/example.py", "def add(a, b):\n    return a - b\n")

    runtime = AuthoredRepairRuntime(
        config=AuthoredRepairRuntimeConfig(
            workspace_root=workspace,
            include_paths=("src",),
        ),
        provider=StaticPatchProposalProvider(
            responses=(
                _proposal_json(
                    path="src/example.py",
                    before_text="return a - b",
                    after_text="return a + b",
                ),
            )
        ),
    )

    report = runtime.run(
        task_id="task-add",
        run_id="run-add",
        objective="Repair addition behavior.",
        raw_test_output=_pytest_failure_text(),
        test_return_code=1,
    )

    assert report.status is AuthoredRepairStatus.AUTHORED
    assert report.succeeded
    assert report.selected_patch is not None
    assert report.selected_patch.changed_paths == ("src/example.py",)
    assert report.selected_patch.file_changes[0].after_text == "def add(a, b):\n    return a + b\n"
    assert report.context_snapshot is not None
    assert report.decomposition is not None
    assert report.hypotheses is not None
    assert report.prompt_contract is not None
    assert report.selection_report is not None
    assert report.receipt_snapshot.verify_chain()


def test_authored_repair_runtime_produces_no_candidate_with_null_provider(tmp_path) -> None:
    workspace = tmp_path
    _write(workspace, "src/example.py", "VALUE = 1\n")

    runtime = AuthoredRepairRuntime(
        config=AuthoredRepairRuntimeConfig(
            workspace_root=workspace,
            include_paths=("src",),
        ),
        provider=NullPatchProposalProvider(),
    )

    report = runtime.run(
        task_id="task-none",
        run_id="run-none",
        objective="Repair reported behavior.",
    )

    assert report.status is AuthoredRepairStatus.NO_CANDIDATE
    assert not report.succeeded
    assert report.selected_patch is None
    assert report.errors == ("No raw proposal responses were produced.",)
    assert report.receipt_snapshot.verify_chain()


def test_authored_repair_runtime_marks_review_required_candidate(tmp_path) -> None:
    workspace = tmp_path
    _write(workspace, "tests/test_example.py", "assert add(2, 2) == 4\n")

    runtime = AuthoredRepairRuntime(
        config=AuthoredRepairRuntimeConfig(
            workspace_root=workspace,
            include_paths=("tests",),
        ),
        provider=StaticPatchProposalProvider(
            responses=(
                _proposal_json(
                    path="tests/test_example.py",
                    before_text="assert add(2, 2) == 4",
                    after_text="assert add(2, 2) == 4\nassert add(1, 1) == 2",
                ),
            )
        ),
    )

    report = runtime.run(
        task_id="task-review",
        run_id="run-review",
        objective="Add missing test coverage.",
        raw_test_output=_pytest_failure_text(),
        test_return_code=1,
    )

    assert report.status is AuthoredRepairStatus.REQUIRES_REVIEW
    assert report.requires_review
    assert report.selected_patch is None
    assert report.selection_report is not None
    assert report.selection_report.review_required_candidates
    assert report.receipt_snapshot.verify_chain()


def test_authored_repair_runtime_marks_blocked_candidate(tmp_path) -> None:
    workspace = tmp_path
    _write(workspace, "config/api_token.txt", "old\n")

    runtime = AuthoredRepairRuntime(
        config=AuthoredRepairRuntimeConfig(
            workspace_root=workspace,
            include_paths=("config",),
        ),
        provider=StaticPatchProposalProvider(
            responses=(
                _proposal_json(
                    path="config/api_token.txt",
                    before_text="old",
                    after_text="new",
                ),
            )
        ),
    )

    report = runtime.run(
        task_id="task-blocked",
        run_id="run-blocked",
        objective="Repair token config.",
        raw_test_output=_pytest_failure_text(),
        test_return_code=1,
    )

    assert report.status is AuthoredRepairStatus.BLOCKED
    assert report.blocked
    assert report.selected_patch is None
    assert report.selection_report is not None
    assert report.selection_report.blocked_candidates
    assert report.receipt_snapshot.verify_chain()


def test_authored_repair_runtime_uses_direct_raw_proposal_responses(tmp_path) -> None:
    workspace = tmp_path
    _write(workspace, "src/example.py", "before\n")

    runtime = AuthoredRepairRuntime(
        config=AuthoredRepairRuntimeConfig(
            workspace_root=workspace,
            include_paths=("src",),
        ),
    )

    report = runtime.run(
        task_id="task-direct",
        run_id="run-direct",
        objective="Repair direct proposal.",
        raw_test_output=_pytest_failure_text(),
        test_return_code=1,
        raw_proposal_responses=(
            _proposal_json(
                path="src/example.py",
                before_text="before",
                after_text="after",
            ),
        ),
    )

    assert report.status is AuthoredRepairStatus.AUTHORED
    assert report.selected_patch is not None
    assert report.selected_patch.file_changes[0].after_text == "after\n"
    assert report.receipt_snapshot.verify_chain()


def test_authored_repair_runtime_records_failed_parse_as_no_candidate(tmp_path) -> None:
    workspace = tmp_path
    _write(workspace, "src/example.py", "before\n")

    runtime = AuthoredRepairRuntime(
        config=AuthoredRepairRuntimeConfig(
            workspace_root=workspace,
            include_paths=("src",),
        ),
        provider=StaticPatchProposalProvider(responses=("```json\n{}\n```",)),
    )

    report = runtime.run(
        task_id="task-bad-json",
        run_id="run-bad-json",
        objective="Repair malformed proposal.",
        raw_test_output=_pytest_failure_text(),
        test_return_code=1,
    )

    assert report.status is AuthoredRepairStatus.NO_CANDIDATE
    assert report.proposals == ()
    assert report.selected_patch is None
    assert report.receipt_snapshot.verify_chain()


def test_authored_repair_report_exports_selected_patch_candidates_for_wave2(tmp_path) -> None:
    workspace = tmp_path
    _write(workspace, "src/example.py", "before\n")

    runtime = AuthoredRepairRuntime(
        config=AuthoredRepairRuntimeConfig(
            workspace_root=workspace,
            include_paths=("src",),
        ),
        provider=StaticPatchProposalProvider(
            responses=(
                _proposal_json(
                    path="src/example.py",
                    before_text="before",
                    after_text="after",
                ),
            )
        ),
    )

    report = runtime.run(
        task_id="task-export",
        run_id="run-export",
        objective="Repair export behavior.",
        raw_test_output=_pytest_failure_text(),
        test_return_code=1,
    )

    assert len(report.selected_patch_candidates) == 1
    assert report.selected_patch_candidates[0] is report.selected_patch
    assert report.to_dict()["selected_patch_id"] == report.selected_patch.patch_id


def test_static_provider_rejects_empty_responses() -> None:
    try:
        StaticPatchProposalProvider(responses=())
        raised = False
    except ValueError:
        raised = True

    assert raised


def _write(workspace, path: str, text: str) -> None:
    file_path = workspace / path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(text, encoding="utf-8")


def _pytest_failure_text() -> str:
    return """
============================= FAILURES =============================
____________________________ test_add ____________________________

    def test_add():
>       assert add(2, 2) == 4
E       assert 0 == 4

tests/test_example.py:12: AssertionError
====================== short test summary info ======================
FAILED tests/test_example.py::test_add - assert 0 == 4
=========================== 1 failed in 0.09s =======================
""".strip()


def _proposal_json(
    *,
    path: str,
    before_text: str,
    after_text: str,
    confidence: float = 0.72,
) -> str:
    if not after_text.endswith("\n"):
        after_text = after_text + "\n"

    return json.dumps(
        {
            "schema_version": "wave3.patch_authoring_response.v1",
            "proposal_id": "proposal-1",
            "objective_summary": "Repair the failing behavior.",
            "reasoning_summary": "The proposed source change aligns with the failure evidence.",
            "confidence": confidence,
            "assumptions": [
                "The compiler must verify before_text against the current workspace.",
            ],
            "risk_notes": [
                "The patch must still pass policy and Wave 2 execution.",
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
