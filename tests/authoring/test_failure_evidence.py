from __future__ import annotations

import hashlib

from ix_blackfox.authoring import (
    AuthoringEvidenceStrength,
    AuthoringFindingSeverity,
    FailureEvidenceExtractor,
    FailureEvidenceExtractorConfig,
    FailureEvidenceKind,
    FailureEvidenceReport,
)
from ix_blackfox.tools.test_results import (
    ParsedTestCase,
    ParsedTestFinding,
    ParsedTestFindingSeverity,
    ParsedTestRun,
    ParsedTestRunStatus,
)


def test_extracts_direct_evidence_from_failed_parsed_test_run() -> None:
    parsed = ParsedTestRun(
        status=ParsedTestRunStatus.FAILED,
        command=("python", "-m", "pytest", "-q"),
        return_code=1,
        timed_out=False,
        failed=1,
        passed=2,
        test_cases=(
            ParsedTestCase(
                node_id="tests/test_math.py::test_add",
                status="failed",
                message="assert 3 == 4",
                file_path="tests/test_math.py",
                line_number=12,
            ),
        ),
        raw_summary_line="==================== 1 failed, 2 passed in 0.11s ====================",
    )

    report = FailureEvidenceExtractor().from_parsed_test_run(
        parsed_test_run=parsed,
        raw_text="FAILED tests/test_math.py::test_add - assert 3 == 4",
    )

    assert report.has_direct_failure_evidence
    assert report.evidence.strength is AuthoringEvidenceStrength.DIRECT
    assert report.related_paths == ("tests/test_math.py",)
    assert report.failing_node_ids == ("tests/test_math.py::test_add",)
    assert report.snippets[0].kind is FailureEvidenceKind.PYTEST_FAILURE
    assert report.snippets[0].path == "tests/test_math.py"
    assert report.snippets[0].line_number == 12
    assert "assert 3 == 4" in report.snippets[0].text
    assert "pytest.failures_detected" in tuple(
        finding.code for finding in report.evidence.findings
    )


def test_extracts_error_and_parser_findings_from_parsed_test_run() -> None:
    parsed = ParsedTestRun(
        status=ParsedTestRunStatus.ERRORED,
        command=("python", "-m", "pytest"),
        return_code=2,
        timed_out=False,
        errors=1,
        test_cases=(
            ParsedTestCase(
                node_id="tests/test_import.py",
                status="error",
                message="ModuleNotFoundError: No module named 'missing'",
                file_path="tests/test_import.py",
            ),
        ),
        findings=(
            ParsedTestFinding(
                code="pytest.module_not_found",
                severity=ParsedTestFindingSeverity.ERROR,
                summary="Pytest output contains a missing module error.",
            ),
        ),
        raw_summary_line="==================== 1 error in 0.05s ====================",
    )

    report = FailureEvidenceExtractor().from_parsed_test_run(
        parsed_test_run=parsed,
        raw_text="ModuleNotFoundError: No module named 'missing'",
    )

    finding_codes = tuple(finding.code for finding in report.evidence.findings)

    assert report.evidence.strength is AuthoringEvidenceStrength.DIRECT
    assert report.snippets[0].kind is FailureEvidenceKind.PYTEST_ERROR
    assert "pytest.errors_detected" in finding_codes
    assert "pytest.module_not_found" in finding_codes


def test_extracts_timeout_evidence() -> None:
    parsed = ParsedTestRun(
        status=ParsedTestRunStatus.TIMED_OUT,
        command=("python", "-m", "pytest"),
        return_code=124,
        timed_out=True,
    )

    report = FailureEvidenceExtractor().from_parsed_test_run(
        parsed_test_run=parsed,
        raw_text="",
    )

    assert report.evidence.strength is AuthoringEvidenceStrength.DIRECT
    assert report.snippets[0].kind is FailureEvidenceKind.PYTEST_TIMEOUT
    assert report.evidence.findings[0].severity is AuthoringFindingSeverity.ERROR
    assert "pytest.timeout_detected" in tuple(
        finding.code for finding in report.evidence.findings
    )


def test_passed_run_produces_missing_failure_evidence() -> None:
    parsed = ParsedTestRun(
        status=ParsedTestRunStatus.PASSED,
        command=("python", "-m", "pytest"),
        return_code=0,
        timed_out=False,
        passed=3,
        raw_summary_line="==================== 3 passed in 0.07s ====================",
    )

    report = FailureEvidenceExtractor().from_parsed_test_run(
        parsed_test_run=parsed,
        raw_text="==================== 3 passed in 0.07s ====================",
    )

    assert report.evidence.strength is AuthoringEvidenceStrength.MISSING
    assert not report.has_direct_failure_evidence
    assert report.snippets[0].kind is FailureEvidenceKind.PYTEST_SUMMARY
    assert "pytest status was passed" in report.evidence.summary


def test_from_pytest_text_uses_existing_pytest_parser() -> None:
    raw_text = """
============================= FAILURES =============================
____________________________ test_add ____________________________

    def test_add():
>       assert 3 == 4
E       assert 3 == 4

tests/test_math.py:12: AssertionError
====================== short test summary info ======================
FAILED tests/test_math.py::test_add - assert 3 == 4
=========================== 1 failed in 0.09s =======================
"""

    report = FailureEvidenceExtractor().from_pytest_text(
        text=raw_text,
        command=("python", "-m", "pytest", "-q"),
        return_code=1,
    )

    assert report.evidence.strength is AuthoringEvidenceStrength.DIRECT
    assert report.related_paths == ("tests/test_math.py",)
    assert report.raw_digest == hashlib.sha256(raw_text.strip().encode("utf-8")).hexdigest()
    assert "tests/test_math.py::test_add" in report.failing_node_ids
    assert "assert 3 == 4" in report.snippets[0].text


def test_objective_only_report_is_weak_evidence() -> None:
    report = FailureEvidenceExtractor().from_objective_only(
        objective="Repair the failing import test."
    )

    assert report.evidence.strength is AuthoringEvidenceStrength.WEAK
    assert report.snippets[0].kind is FailureEvidenceKind.OBJECTIVE_ONLY
    assert "Objective-only evidence" in report.evidence.summary
    assert "authoring.objective_only_evidence" in tuple(
        finding.code for finding in report.evidence.findings
    )


def test_report_round_trip_preserves_evidence_payload() -> None:
    parsed = ParsedTestRun(
        status=ParsedTestRunStatus.FAILED,
        command=("python", "-m", "pytest"),
        return_code=1,
        timed_out=False,
        failed=1,
        test_cases=(
            ParsedTestCase(
                node_id="tests/test_example.py::test_example",
                status="failed",
                message="AssertionError",
                file_path="tests/test_example.py",
            ),
        ),
    )
    report = FailureEvidenceExtractor().from_parsed_test_run(
        parsed_test_run=parsed,
        raw_text="FAILED tests/test_example.py::test_example - AssertionError",
    )

    restored = FailureEvidenceReport.from_dict(report.to_dict())

    assert restored.evidence.summary == report.evidence.summary
    assert restored.snippets[0].node_id == "tests/test_example.py::test_example"
    assert restored.related_paths == ("tests/test_example.py",)
    assert restored.raw_digest == report.raw_digest


def test_snippet_text_is_bounded() -> None:
    parsed = ParsedTestRun(
        status=ParsedTestRunStatus.FAILED,
        command=("python", "-m", "pytest"),
        return_code=1,
        timed_out=False,
        failed=1,
        test_cases=(
            ParsedTestCase(
                node_id="tests/test_long.py::test_long",
                status="failed",
                message="x" * 500,
                file_path="tests/test_long.py",
            ),
        ),
    )
    extractor = FailureEvidenceExtractor(
        config=FailureEvidenceExtractorConfig(max_snippet_chars=80)
    )

    report = extractor.from_parsed_test_run(
        parsed_test_run=parsed,
        raw_text="FAILED tests/test_long.py::test_long - " + ("x" * 500),
    )

    assert len(report.snippets[0].text) <= 80
    assert report.snippets[0].text.endswith("[truncated]")
