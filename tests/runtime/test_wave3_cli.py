from __future__ import annotations

import json
import sys

from ix_blackfox.runtime.wave3_acceptance import Wave3AcceptanceStatus
from ix_blackfox.runtime.wave3_cli import (
    Wave3CliRequest,
    build_parser,
    run_wave3_cli,
    run_wave3_cli_request,
)


def test_wave3_cli_request_runs_and_writes_output(tmp_path) -> None:
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

    output_path = workspace / "artifacts" / "wave3-result.json"
    request = Wave3CliRequest(
        workspace_root=workspace,
        artifact_root=workspace,
        task_id="task-cli",
        run_id="run-cli",
        objective="Repair file content.",
        include_paths=("src", "tests"),
        proposal_responses=(
            _proposal_json(
                path="src/example.py",
                before_text="before",
                after_text="after",
            ),
        ),
        raw_test_output=_authoring_failure_text(),
        output_path=output_path,
        test_command=(sys.executable, "-m", "pytest", "-q", "tests"),
        allowed_test_executables=(sys.executable, "python", "python3", "py", "pytest"),
    )

    result = run_wave3_cli_request(request)

    assert result.exit_code == 0
    assert result.succeeded
    assert result.output_path == output_path
    assert output_path.is_file()

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "wave3.cli.result.v1"
    assert payload["wave3_acceptance_report"]["status"] == Wave3AcceptanceStatus.PASSED.value
    assert payload["authored_engineering_report"]["wave2_executed"] is True


def test_wave3_cli_accepts_proposal_file_and_raw_test_output_file(tmp_path) -> None:
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

    proposal_file = workspace / "proposal.json"
    proposal_file.write_text(
        _proposal_json(
            path="src/example.py",
            before_text="before",
            after_text="after",
        ),
        encoding="utf-8",
    )

    evidence_file = workspace / "pytest-output.txt"
    evidence_file.write_text(_authoring_failure_text(), encoding="utf-8")

    output_path = workspace / "wave3-result.json"

    result = run_wave3_cli(
        (
            "--workspace-root",
            str(workspace),
            "--artifact-root",
            str(workspace),
            "--task-id",
            "task-cli-file",
            "--run-id",
            "run-cli-file",
            "--objective",
            "Repair file content.",
            "--include-path",
            "src",
            "--include-path",
            "tests",
            "--proposal-file",
            str(proposal_file),
            "--raw-test-output-file",
            str(evidence_file),
            "--output-path",
            str(output_path),
            "--test-command",
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests",
            "--allowed-test-executable",
            sys.executable,
        )
    )

    assert result.exit_code == 0
    assert output_path.is_file()
    assert result.payload["wave3_acceptance_report"]["status"] == "passed"


def test_wave3_cli_returns_review_exit_code_for_review_required_candidate(tmp_path) -> None:
    workspace = tmp_path
    _make_workspace_marker(workspace)
    _write(workspace, "tests/test_example.py", "assert True\n")

    result = run_wave3_cli(
        (
            "--workspace-root",
            str(workspace),
            "--artifact-root",
            str(workspace),
            "--task-id",
            "task-review",
            "--run-id",
            "run-review",
            "--objective",
            "Add test coverage.",
            "--include-path",
            "tests",
            "--proposal-json",
            _proposal_json(
                path="tests/test_example.py",
                before_text="assert True",
                after_text="assert True\nassert 1 == 1",
            ),
            "--raw-test-output-file",
            str(_write_return_path(workspace, "pytest-output.txt", _authoring_failure_text())),
            "--test-command",
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests",
            "--allowed-test-executable",
            sys.executable,
        )
    )

    assert result.exit_code == 10
    assert result.payload["wave3_acceptance_report"]["status"] == "requires_review"


def test_wave3_cli_returns_error_when_no_proposal_supplied(tmp_path) -> None:
    workspace = tmp_path
    _make_workspace_marker(workspace)

    result = run_wave3_cli(
        (
            "--workspace-root",
            str(workspace),
            "--task-id",
            "task-missing",
            "--run-id",
            "run-missing",
            "--objective",
            "Repair missing proposal.",
            "--include-path",
            ".",
        )
    )

    assert result.exit_code == 2
    assert result.errors
    assert "proposal" in result.errors[0].lower()


def test_wave3_cli_parser_has_required_arguments() -> None:
    parser = build_parser()
    help_text = parser.format_help()

    assert "--workspace-root" in help_text
    assert "--proposal-json" in help_text
    assert "--proposal-file" in help_text
    assert "--raw-test-output-file" in help_text
    assert "--output-path" in help_text


def _make_workspace_marker(workspace) -> None:
    (workspace / ".blackfox-workspace").write_text(
        "reserved IX-BlackFox test workspace\n",
        encoding="utf-8",
    )


def _write(workspace, path: str, text: str) -> None:
    file_path = workspace / path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(text, encoding="utf-8")


def _write_return_path(workspace, path: str, text: str):
    file_path = workspace / path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(text, encoding="utf-8")
    return file_path


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
