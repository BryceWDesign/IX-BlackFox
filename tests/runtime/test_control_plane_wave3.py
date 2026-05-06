from __future__ import annotations

import json
import sys

from ix_blackfox.runtime.authoring_repair import (
    AuthoredRepairStatus,
    StaticPatchProposalProvider,
)
from ix_blackfox.runtime.control_plane import (
    AuthoredEngineeringControlPlaneReport,
    EngineeringControlPlane,
)


def test_control_plane_runs_authored_repair_through_wave2(tmp_path) -> None:
    workspace = tmp_path
    _make_workspace_marker(workspace)
    _write(workspace, "src/example.py", "def add(a, b):\n    return a - b\n")
    _write(
        workspace,
        "tests/test_example.py",
        "from pathlib import Path\n\n"
        "def test_patch_changed_source():\n"
        "    text = Path('src/example.py').read_text(encoding='utf-8')\n"
        "    assert 'return a + b' in text\n",
    )

    control_plane = EngineeringControlPlane.from_workspace(
        workspace_root=workspace,
        artifact_root=workspace,
        test_command=(sys.executable, "-m", "pytest", "-q", "tests"),
        allowed_test_executables=(sys.executable, "python", "python3", "py", "pytest"),
        test_timeout_seconds=30,
    )

    report = control_plane.run_authored_programming_repair(
        task_id="task-add",
        run_id="run-add",
        objective="Repair addition behavior.",
        include_paths=("src", "tests"),
        proposal_provider=StaticPatchProposalProvider(
            responses=(
                _proposal_json(
                    path="src/example.py",
                    before_text="return a - b",
                    after_text="return a + b",
                ),
            )
        ),
        raw_test_output=_authoring_failure_text(),
        authoring_test_return_code=1,
        test_command=(sys.executable, "-m", "pytest", "-q", "tests"),
    )

    assert isinstance(report, AuthoredEngineeringControlPlaneReport)
    assert report.authored_repair_report.status is AuthoredRepairStatus.AUTHORED
    assert report.wave2_executed
    assert report.wave2_report is not None
    assert report.succeeded
    assert report.selected_patch_id is not None
    assert report.bundle_root is not None
    assert report.authored_repair_report.receipt_snapshot.verify_chain()
    assert "return a + b" in (workspace / "src" / "example.py").read_text(encoding="utf-8")


def test_control_plane_does_not_execute_wave2_when_authoring_has_no_candidate(tmp_path) -> None:
    workspace = tmp_path
    _make_workspace_marker(workspace)
    _write(workspace, "src/example.py", "VALUE = 1\n")

    control_plane = EngineeringControlPlane.from_workspace(
        workspace_root=workspace,
        artifact_root=workspace,
        test_command=(sys.executable, "-m", "pytest", "-q"),
        allowed_test_executables=(sys.executable, "python", "python3", "py", "pytest"),
    )

    report = control_plane.run_authored_programming_repair(
        task_id="task-none",
        run_id="run-none",
        objective="Repair reported behavior.",
        include_paths=("src",),
        raw_test_output=_authoring_failure_text(),
        authoring_test_return_code=1,
    )

    assert report.authored_repair_report.status is AuthoredRepairStatus.NO_CANDIDATE
    assert not report.wave2_executed
    assert report.wave2_report is None
    assert not report.succeeded
    assert report.bundle_root is None
    assert "VALUE = 1" in (workspace / "src" / "example.py").read_text(encoding="utf-8")


def test_control_plane_does_not_execute_wave2_when_authoring_requires_review(tmp_path) -> None:
    workspace = tmp_path
    _make_workspace_marker(workspace)
    _write(workspace, "tests/test_example.py", "assert True\n")

    control_plane = EngineeringControlPlane.from_workspace(
        workspace_root=workspace,
        artifact_root=workspace,
        test_command=(sys.executable, "-m", "pytest", "-q", "tests"),
        allowed_test_executables=(sys.executable, "python", "python3", "py", "pytest"),
    )

    report = control_plane.run_authored_programming_repair(
        task_id="task-review",
        run_id="run-review",
        objective="Add test coverage.",
        include_paths=("tests",),
        proposal_provider=StaticPatchProposalProvider(
            responses=(
                _proposal_json(
                    path="tests/test_example.py",
                    before_text="assert True",
                    after_text="assert True\nassert 1 == 1",
                ),
            )
        ),
        raw_test_output=_authoring_failure_text(),
        authoring_test_return_code=1,
    )

    assert report.authored_repair_report.status is AuthoredRepairStatus.REQUIRES_REVIEW
    assert report.requires_review
    assert not report.wave2_executed
    assert report.wave2_report is None
    assert not report.succeeded


def test_authored_engineering_report_to_dict_preserves_both_layers(tmp_path) -> None:
    workspace = tmp_path
    _make_workspace_marker(workspace)
    _write(workspace, "src/example.py", "before\n")
    _write(
        workspace,
        "tests/test_example.py",
        "from pathlib import Path\n\n"
        "def test_patch_changed_source():\n"
        "    assert Path('src/example.py').read_text(encoding='utf-8') == 'after\\n'\n",
    )

    control_plane = EngineeringControlPlane.from_workspace(
        workspace_root=workspace,
        artifact_root=workspace,
        test_command=(sys.executable, "-m", "pytest", "-q", "tests"),
        allowed_test_executables=(sys.executable, "python", "python3", "py", "pytest"),
    )

    report = control_plane.run_authored_programming_repair(
        task_id="task-dict",
        run_id="run-dict",
        objective="Repair file content.",
        include_paths=("src", "tests"),
        raw_proposal_responses=(
            _proposal_json(
                path="src/example.py",
                before_text="before",
                after_text="after",
            ),
        ),
        raw_test_output=_authoring_failure_text(),
        authoring_test_return_code=1,
        test_command=(sys.executable, "-m", "pytest", "-q", "tests"),
    )

    payload = report.to_dict()

    assert payload["succeeded"] is True
    assert payload["wave2_executed"] is True
    assert payload["authored_repair_report"]["status"] == "authored"
    assert payload["wave2_report"] is not None
    assert payload["selected_patch_id"] == report.selected_patch_id


def _make_workspace_marker(workspace) -> None:
    (workspace / ".blackfox-workspace").write_text(
        "reserved IX-BlackFox test workspace\n",
        encoding="utf-8",
    )


def _write(workspace, path: str, text: str) -> None:
    file_path = workspace / path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(text, encoding="utf-8")


def _authoring_failure_text() -> str:
    return """
============================= FAILURES =============================
____________________________ test_patch_changed_source ____________________________

    def test_patch_changed_source():
>       assert False
E       assert False

tests/test_example.py:4: AssertionError
====================== short test summary info ======================
FAILED tests/test_example.py::test_patch_changed_source - assert False
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
