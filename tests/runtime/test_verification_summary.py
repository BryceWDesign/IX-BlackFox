from __future__ import annotations

from pathlib import Path

from ix_blackfox.runtime import (
    ProgrammingRepairRunReport,
    RepairLoopConfig,
    RepairLoopReceiptLedger,
    RepairLoopStatus,
    RepairLoopTerminalReason,
    RunBundleArtifactKind,
    RunBundleLayout,
    RunBundleWriter,
    VerificationSummary,
    VerificationSummaryRenderer,
    VerificationSummaryStatus,
)
from ix_blackfox.tools import (
    ParsedTestRun,
    ParsedTestRunStatus,
    PatchDiff,
    PatchFileChange,
    ToolCapability,
    ToolFailure,
    ToolFailureKind,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolInvocationStatus,
)


def test_verification_summary_marks_successful_repair_report_verified() -> None:
    report = _make_verified_programming_repair_report()

    summary = VerificationSummaryRenderer().from_programming_repair_report(report)

    assert summary.status is VerificationSummaryStatus.VERIFIED
    assert summary.run_id == "run-verify"
    assert summary.task_id == "task-verify"
    assert summary.objective == "Verify governed repair evidence."
    assert summary.evidence_count >= 5
    assert summary.error_count == 0
    assert summary.warning_count == 0
    assert summary.metadata["summary_type"] == "programming_repair"
    assert summary.metadata["terminal_reason"] == "tests_passed"
    assert len(summary.digest) == 64

    payload = summary.to_dict()

    assert payload["status"] == "verified"
    assert payload["evidence_count"] == summary.evidence_count
    assert payload["finding_count"] == summary.finding_count
    assert payload["digest"] == summary.digest
    assert any(
        finding["code"] == "repair.terminal_success"
        for finding in payload["findings"]
    )
    assert any(
        finding["code"] == "tests.latest_passed"
        for finding in payload["findings"]
    )


def test_verification_summary_marks_failed_repair_report_failed() -> None:
    report = _make_failed_programming_repair_report()

    summary = VerificationSummaryRenderer().from_programming_repair_report(report)

    assert summary.status is VerificationSummaryStatus.FAILED
    assert summary.error_count >= 2
    assert summary.warning_count >= 1
    assert "failed or errored" in summary.conclusion
    assert any(finding.code == "repair.not_verified" for finding in summary.findings)
    assert any(finding.code == "tests.latest_not_passing" for finding in summary.findings)
    assert any(finding.code == "receipts.repair_missing" for finding in summary.findings)


def test_verification_summary_marks_blocked_repair_report_blocked() -> None:
    report = _make_blocked_programming_repair_report()

    summary = VerificationSummaryRenderer().from_programming_repair_report(report)

    assert summary.status is VerificationSummaryStatus.BLOCKED
    assert summary.error_count >= 2
    assert "blocked before verification could complete" in summary.conclusion
    assert any(finding.code == "tests.no_parsed_test_run" for finding in summary.findings)


def test_verification_summary_round_trips_serialized_payload() -> None:
    summary = VerificationSummaryRenderer().from_programming_repair_report(
        _make_verified_programming_repair_report()
    )

    restored = VerificationSummary.from_dict(summary.to_dict())

    assert restored.summary_id == summary.summary_id
    assert restored.run_id == summary.run_id
    assert restored.task_id == summary.task_id
    assert restored.status is VerificationSummaryStatus.VERIFIED
    assert restored.objective == summary.objective
    assert restored.conclusion == summary.conclusion
    assert restored.evidence_count == summary.evidence_count
    assert restored.finding_count == summary.finding_count
    assert restored.digest == summary.digest


def test_verification_summary_from_run_bundle_manifest_reports_partial_evidence(
    tmp_path: Path,
) -> None:
    writer = RunBundleWriter(
        layout=RunBundleLayout(root_dir=tmp_path, run_id="run-bundle-verify"),
        task_id="task-bundle-verify",
    )
    writer.write_json(
        kind=RunBundleArtifactKind.RUN_REPORT,
        filename="run-report.json",
        payload={"status": "passed"},
    )
    writer.write_json(
        kind=RunBundleArtifactKind.VERIFICATION_SUMMARY,
        filename="verification-summary.json",
        payload={"status": "verified"},
    )

    summary = VerificationSummaryRenderer().from_run_bundle_manifest(writer.manifest)

    assert summary.status is VerificationSummaryStatus.PARTIAL
    assert summary.run_id == "run-bundle-verify"
    assert summary.task_id == "task-bundle-verify"
    assert summary.evidence_count == 2
    assert summary.warning_count == 0
    assert summary.metadata["artifact_count"] == 2
    assert "manifest alone does not prove" in summary.conclusion
    assert any(
        evidence.reference == "reports/run-report.json"
        for evidence in summary.evidence
    )
    assert any(
        evidence.reference == "verification/verification-summary.json"
        for evidence in summary.evidence
    )


def _make_verified_programming_repair_report() -> ProgrammingRepairRunReport:
    loop_state = _base_loop_state()
    patch = _patch()
    repair_receipt_ledger = RepairLoopReceiptLedger()
    repair_receipt_ledger.record_loop_started(state=loop_state)

    loop_state = loop_state.start_attempt(patch_diff=patch)
    repair_receipt_ledger.record_attempt_started(state=loop_state, patch_diff=patch)

    attempt = loop_state.latest_attempt
    assert attempt is not None

    patch_result = ToolInvocationResult.succeeded(
        request=_patch_request(),
        output={
            "patch_id": patch.patch_id,
            "changed_paths": ["tests/test_smoke.py"],
        },
    )
    loop_state = loop_state.attach_patch_result(
        attempt_id=attempt.attempt_id,
        result=patch_result,
    )
    repair_receipt_ledger.record_patch_result(state=loop_state, result=patch_result)

    parsed_test_run = ParsedTestRun(
        status=ParsedTestRunStatus.PASSED,
        command=("python", "-m", "pytest", "-q"),
        return_code=0,
        timed_out=False,
        duration_seconds=0.12,
        passed=1,
        raw_summary_line="============================== 1 passed in 0.12s ==============================",
    )
    test_result = ToolInvocationResult.succeeded(
        request=_test_request(),
        output={
            "command": ["python", "-m", "pytest", "-q"],
            "cwd": "/workspace",
            "return_code": 0,
            "stdout": "1 passed",
            "stderr": "",
            "timed_out": False,
            "timeout_seconds": 60.0,
        },
    )
    loop_state = loop_state.attach_test_result(
        attempt_id=attempt.attempt_id,
        result=test_result,
        parsed_test_run=parsed_test_run,
    )
    repair_receipt_ledger.record_test_result(
        state=loop_state,
        result=test_result,
        parsed_test_run=parsed_test_run,
    )
    repair_receipt_ledger.record_loop_terminated(state=loop_state)

    assert loop_state.status is RepairLoopStatus.SUCCEEDED
    assert loop_state.terminal_reason is RepairLoopTerminalReason.TESTS_PASSED

    return ProgrammingRepairRunReport(
        loop_state=loop_state,
        patch_results=(patch_result,),
        test_results=(test_result,),
        parsed_test_runs=(parsed_test_run,),
        repair_receipts=tuple(
            receipt.to_dict()
            for receipt in repair_receipt_ledger.snapshot().receipts
        ),
    )


def _make_failed_programming_repair_report() -> ProgrammingRepairRunReport:
    loop_state = _base_loop_state(config=RepairLoopConfig(max_attempts=1))
    patch = _patch()
    loop_state = loop_state.start_attempt(patch_diff=patch)
    attempt = loop_state.latest_attempt
    assert attempt is not None

    patch_result = ToolInvocationResult.succeeded(
        request=_patch_request(),
        output={
            "patch_id": patch.patch_id,
            "changed_paths": ["tests/test_smoke.py"],
        },
    )
    loop_state = loop_state.attach_patch_result(
        attempt_id=attempt.attempt_id,
        result=patch_result,
    )

    parsed_test_run = ParsedTestRun(
        status=ParsedTestRunStatus.FAILED,
        command=("python", "-m", "pytest", "-q"),
        return_code=1,
        timed_out=False,
        duration_seconds=0.13,
        failed=1,
        raw_summary_line="============================== 1 failed in 0.13s ==============================",
    )
    test_result = ToolInvocationResult.succeeded(
        request=_test_request(),
        output={
            "command": ["python", "-m", "pytest", "-q"],
            "cwd": "/workspace",
            "return_code": 1,
            "stdout": "1 failed",
            "stderr": "",
            "timed_out": False,
            "timeout_seconds": 60.0,
        },
    )
    loop_state = loop_state.attach_test_result(
        attempt_id=attempt.attempt_id,
        result=test_result,
        parsed_test_run=parsed_test_run,
    )

    return ProgrammingRepairRunReport(
        loop_state=loop_state,
        patch_results=(patch_result,),
        test_results=(test_result,),
        parsed_test_runs=(parsed_test_run,),
        repair_receipts=(),
    )


def _make_blocked_programming_repair_report() -> ProgrammingRepairRunReport:
    loop_state = _base_loop_state()
    patch = _patch(path="secrets/token.txt")
    loop_state = loop_state.start_attempt(patch_diff=patch)
    attempt = loop_state.latest_attempt
    assert attempt is not None

    patch_result = ToolInvocationResult.failed(
        request=_patch_request(),
        status=ToolInvocationStatus.BLOCKED,
        failure=ToolFailure(
            kind=ToolFailureKind.PATH_VIOLATION,
            message="Path is blocked by workspace policy.",
        ),
    )
    loop_state = loop_state.attach_patch_result(
        attempt_id=attempt.attempt_id,
        result=patch_result,
    )

    return ProgrammingRepairRunReport(
        loop_state=loop_state,
        patch_results=(patch_result,),
        test_results=(),
        parsed_test_runs=(),
        repair_receipts=(),
    )


def _base_loop_state(config: RepairLoopConfig | None = None):
    from ix_blackfox.runtime import RepairLoopState

    return RepairLoopState.create(
        task_id="task-verify",
        run_id="run-verify",
        objective="Verify governed repair evidence.",
        config=config,
    )


def _patch(*, path: str = "tests/test_smoke.py") -> PatchDiff:
    return PatchDiff.create(
        summary="Repair smoke test.",
        file_changes=(
            PatchFileChange.modify(
                path=path,
                before_text="def test_smoke() -> None:\n    assert False\n",
                after_text="def test_smoke() -> None:\n    assert True\n",
            ),
        ),
        created_by="blackfox-test",
    )


def _patch_request() -> ToolInvocationRequest:
    return ToolInvocationRequest.create(
        tool_id="blackfox.workspace.apply_patch",
        capability=ToolCapability.PATCH_APPLY,
        task_id="task-verify",
        run_id="run-verify",
    )


def _test_request() -> ToolInvocationRequest:
    return ToolInvocationRequest.create(
        tool_id="blackfox.workspace.run_tests",
        capability=ToolCapability.TEST_EXECUTION,
        task_id="task-verify",
        run_id="run-verify",
    )
