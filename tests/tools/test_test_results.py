from __future__ import annotations

from ix_blackfox.tools import (
    ParsedTestRunStatus,
    PytestTextResultParser,
    TestCommandResult,
)


def test_pytest_text_result_parser_parses_passing_summary() -> None:
    text = """
============================= test session starts =============================
collected 3 items

tests/test_alpha.py ...                                                 [100%]

============================== 3 passed in 0.12s ==============================
""".strip()

    result = PytestTextResultParser().parse_text(
        text=text,
        command=("python", "-m", "pytest", "-q"),
        return_code=0,
    )

    assert result.status is ParsedTestRunStatus.PASSED
    assert result.succeeded is True
    assert result.passed == 3
    assert result.failed == 0
    assert result.errors == 0
    assert result.duration_seconds == 0.12
    assert result.raw_summary_line == "============================== 3 passed in 0.12s =============================="
    assert result.total_outcomes == 3
    assert result.failing_outcomes == 0


def test_pytest_text_result_parser_parses_failure_summary_targets() -> None:
    text = """
=================================== FAILURES ===================================
______________________________ test_runtime_path _______________________________

    assert False
E   assert False

tests/runtime/test_orchestrator.py:17: AssertionError
=========================== short test summary info ============================
FAILED tests/runtime/test_orchestrator.py::test_runtime_path - assert False
FAILED tests/tools/test_gateway.py::test_policy_blocks - RuntimeError: blocked
========================= 2 failed, 4 passed in 1.45s =========================
""".strip()

    result = PytestTextResultParser().parse_text(
        text=text,
        command=("python", "-m", "pytest", "-q"),
        return_code=1,
    )

    assert result.status is ParsedTestRunStatus.FAILED
    assert result.failed_or_errored is True
    assert result.failed == 2
    assert result.passed == 4
    assert result.duration_seconds == 1.45
    assert len(result.test_cases) == 2
    assert result.test_cases[0].node_id == "tests/runtime/test_orchestrator.py::test_runtime_path"
    assert result.test_cases[0].status == "failed"
    assert result.test_cases[0].file_path == "tests/runtime/test_orchestrator.py"
    assert result.test_cases[0].message == "assert False"
    assert result.test_cases[1].node_id == "tests/tools/test_gateway.py::test_policy_blocks"
    assert result.test_cases[1].message == "RuntimeError: blocked"


def test_pytest_text_result_parser_parses_collection_error_signals() -> None:
    text = """
==================================== ERRORS ====================================
___________ ERROR collecting tests/runtime/test_runtime_default.py ___________
ImportError while importing test module '/repo/tests/runtime/test_runtime_default.py'.
Traceback:
E   ModuleNotFoundError: No module named 'ix_blackfox.sentinel.checks'
=========================== short test summary info ============================
ERROR tests/runtime/test_runtime_default.py
!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!
=============================== 1 error in 0.31s ===============================
""".strip()

    result = PytestTextResultParser().parse_text(
        text=text,
        command=("python", "-m", "pytest", "-q"),
        return_code=2,
    )

    assert result.status is ParsedTestRunStatus.ERRORED
    assert result.errors == 1
    assert result.has_finding("pytest.import_error") is True
    assert result.has_finding("pytest.module_not_found") is True
    assert result.has_finding("pytest.collection_interrupted") is True
    assert len(result.test_cases) == 1
    assert result.test_cases[0].node_id == "tests/runtime/test_runtime_default.py"
    assert result.test_cases[0].status == "error"
    assert result.test_cases[0].file_path == "tests/runtime/test_runtime_default.py"


def test_pytest_text_result_parser_parses_warnings_skips_and_deselection() -> None:
    text = """
============================= test session starts =============================
collected 12 items / 2 deselected / 10 selected

tests/test_alpha.py ..s                                                [ 30%]
tests/test_beta.py ....                                                [100%]

================ 6 passed, 1 skipped, 2 deselected, 3 warnings in 0.42s ================
""".strip()

    result = PytestTextResultParser().parse_text(
        text=text,
        command=("python", "-m", "pytest"),
        return_code=0,
    )

    assert result.status is ParsedTestRunStatus.PASSED
    assert result.passed == 6
    assert result.skipped == 1
    assert result.deselected == 2
    assert result.warnings == 3
    assert result.duration_seconds == 0.42
    assert result.has_finding("pytest.warnings_present") is True


def test_pytest_text_result_parser_marks_no_tests() -> None:
    text = """
============================ no tests ran in 0.01s =============================
""".strip()

    result = PytestTextResultParser().parse_text(
        text=text,
        command=("python", "-m", "pytest", "-q"),
        return_code=5,
    )

    assert result.status is ParsedTestRunStatus.NO_TESTS
    assert result.total_outcomes == 0
    assert result.duration_seconds == 0.01


def test_pytest_text_result_parser_marks_missing_summary_as_unknown_when_return_code_zero() -> None:
    result = PytestTextResultParser().parse_text(
        text="custom test command produced no pytest summary",
        command=("python", "custom_runner.py"),
        return_code=0,
    )

    assert result.status is ParsedTestRunStatus.UNKNOWN
    assert result.has_finding("pytest.summary_missing") is True


def test_pytest_text_result_parser_wraps_governed_test_command_result() -> None:
    command_result = TestCommandResult(
        command=("python", "-m", "pytest", "-q"),
        cwd="/repo",
        return_code=1,
        stdout="""
=========================== short test summary info ============================
FAILED tests/test_alpha.py::test_alpha - AssertionError: nope
========================= 1 failed, 2 passed in 0.20s =========================
""".strip(),
        stderr="",
        timed_out=False,
        timeout_seconds=60.0,
    )

    parsed = PytestTextResultParser().parse_command_result(command_result)

    assert parsed.status is ParsedTestRunStatus.FAILED
    assert parsed.command == ("python", "-m", "pytest", "-q")
    assert parsed.return_code == 1
    assert parsed.timed_out is False
    assert parsed.metadata["cwd"] == "/repo"
    assert parsed.failed == 1
    assert parsed.passed == 2
    assert parsed.test_cases[0].node_id == "tests/test_alpha.py::test_alpha"


def test_pytest_text_result_parser_marks_timeout_from_command_result() -> None:
    command_result = TestCommandResult(
        command=("python", "-m", "pytest", "-q"),
        cwd="/repo",
        return_code=124,
        stdout="",
        stderr="partial output before timeout",
        timed_out=True,
        timeout_seconds=0.01,
    )

    parsed = PytestTextResultParser().parse_command_result(command_result)

    assert parsed.status is ParsedTestRunStatus.TIMED_OUT
    assert parsed.timed_out is True
    assert parsed.failed_or_errored is True
    assert parsed.has_finding("pytest.command_timed_out") is True
    assert parsed.has_finding("pytest.summary_missing") is True
