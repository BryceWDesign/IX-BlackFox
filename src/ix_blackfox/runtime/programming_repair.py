from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ix_blackfox.runtime.repair_loop import (
    RepairLoopConfig,
    RepairLoopState,
)
from ix_blackfox.runtime.repair_receipts import RepairLoopReceiptLedger
from ix_blackfox.tools import (
    ParsedTestRun,
    ParsedTestRunStatus,
    PatchApplyTool,
    PatchDiff,
    PytestTextResultParser,
    TestCommandResult,
    TestRunnerTool,
    ToolCapability,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolInvocationStatus,
)


@dataclass(frozen=True, slots=True)
class ProgrammingRepairRunReport:
    """
    Operator-readable report for one governed programming repair run.

    The report records the bounded loop state plus every patch/test tool result.
    It deliberately separates candidate patch generation from execution. BlackFox
    may later generate patch candidates through model/tool planning, but this
    runtime only applies supplied candidates through governed tools.
    """

    loop_state: RepairLoopState
    patch_results: tuple[ToolInvocationResult, ...] = field(default_factory=tuple)
    test_results: tuple[ToolInvocationResult, ...] = field(default_factory=tuple)
    parsed_test_runs: tuple[ParsedTestRun, ...] = field(default_factory=tuple)
    repair_receipts: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "patch_results", tuple(self.patch_results))
        object.__setattr__(self, "test_results", tuple(self.test_results))
        object.__setattr__(self, "parsed_test_runs", tuple(self.parsed_test_runs))
        object.__setattr__(self, "repair_receipts", tuple(self.repair_receipts))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def succeeded(self) -> bool:
        return self.loop_state.status.value == "succeeded"

    @property
    def terminal_reason(self) -> str | None:
        if self.loop_state.terminal_reason is None:
            return None
        return self.loop_state.terminal_reason.value

    @property
    def attempts_used(self) -> int:
        return self.loop_state.attempts_used

    @property
    def attempts_remaining(self) -> int:
        return self.loop_state.attempts_remaining

    @property
    def latest_test_run(self) -> ParsedTestRun | None:
        if not self.parsed_test_runs:
            return None
        return self.parsed_test_runs[-1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "succeeded": self.succeeded,
            "terminal_reason": self.terminal_reason,
            "attempts_used": self.attempts_used,
            "attempts_remaining": self.attempts_remaining,
            "loop_state": self.loop_state.to_dict(),
            "patch_results": [result.to_dict() for result in self.patch_results],
            "test_results": [result.to_dict() for result in self.test_results],
            "parsed_test_runs": [
                parsed_test_run.to_dict()
                for parsed_test_run in self.parsed_test_runs
            ],
            "repair_receipts": list(self.repair_receipts),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ProgrammingRepairRuntime:
    """
    Governed patch-test-repair coordinator.

    This class is the first concrete Wave 2 integration point between:
    - PatchDiff candidates
    - PatchApplyTool
    - TestRunnerTool
    - PytestTextResultParser
    - RepairLoopState
    - RepairLoopReceiptLedger

    It does not invent patches and it does not bypass approval policy. It
    executes already-supplied patch candidates through governed tool wrappers,
    parses test results, advances the repair-loop state, and stops once tests
    pass, a safety block occurs, or the configured attempt budget is exhausted.
    """

    patch_tool: PatchApplyTool
    test_runner: TestRunnerTool
    test_result_parser: PytestTextResultParser = field(
        default_factory=PytestTextResultParser
    )
    config: RepairLoopConfig = field(default_factory=RepairLoopConfig)
    repair_receipt_ledger: RepairLoopReceiptLedger | None = None

    def run(
        self,
        *,
        task_id: str,
        run_id: str,
        objective: str,
        candidate_patches: Iterable[PatchDiff],
        test_command: tuple[str, ...] | None = None,
        test_working_directory: str = ".",
        metadata: Mapping[str, Any] | None = None,
    ) -> ProgrammingRepairRunReport:
        """
        Run a bounded governed programming repair loop.

        Parameters
        ----------
        task_id:
            Stable task identifier.
        run_id:
            Stable run identifier.
        objective:
            Human-readable repair objective.
        candidate_patches:
            Ordered patch candidates. Each candidate consumes one attempt.
        test_command:
            Optional argv-style test command. If omitted, the test runner uses
            its configured default command.
        test_working_directory:
            Workspace-relative directory where the test command should run.
        metadata:
            Optional report metadata.
        """
        patch_candidates = tuple(candidate_patches)
        loop_state = RepairLoopState.create(
            task_id=task_id,
            run_id=run_id,
            objective=objective,
            config=self.config,
            metadata=dict(metadata or {}),
        )
        patch_results: list[ToolInvocationResult] = []
        test_results: list[ToolInvocationResult] = []
        parsed_test_runs: list[ParsedTestRun] = []

        self._record_loop_started(loop_state)

        for patch_diff in patch_candidates:
            if not loop_state.can_start_attempt:
                break

            loop_state = loop_state.start_attempt(
                patch_diff=patch_diff,
                notes=("Candidate patch entered governed repair loop.",),
            )
            self._record_attempt_started(loop_state, patch_diff)

            attempt = loop_state.latest_attempt
            if attempt is None:
                raise RuntimeError("Repair loop failed to create an attempt.")

            patch_request = ToolInvocationRequest.create(
                tool_id=self.patch_tool.tool_id,
                capability=ToolCapability.PATCH_APPLY,
                arguments={"patch": patch_diff},
                task_id=task_id,
                run_id=run_id,
                requested_by="runtime.programming_repair",
                labels=("programming", "patch", "repair-loop"),
                metadata={
                    "attempt_id": attempt.attempt_id,
                    "attempt_index": attempt.attempt_index,
                    "patch_id": patch_diff.patch_id,
                },
            )
            patch_result = self.patch_tool.invoke(patch_request)
            patch_results.append(patch_result)

            loop_state = loop_state.attach_patch_result(
                attempt_id=attempt.attempt_id,
                result=patch_result,
            )
            self._record_patch_result(loop_state, patch_result)

            if loop_state.is_terminal:
                self._record_loop_terminated(loop_state)
                break

            if patch_result.status is not ToolInvocationStatus.SUCCEEDED:
                continue

            test_request = ToolInvocationRequest.create(
                tool_id=self.test_runner.tool_id,
                capability=ToolCapability.TEST_EXECUTION,
                arguments=_test_arguments(
                    test_command=test_command,
                    test_working_directory=test_working_directory,
                ),
                task_id=task_id,
                run_id=run_id,
                requested_by="runtime.programming_repair",
                labels=("programming", "tests", "repair-loop"),
                metadata={
                    "attempt_id": attempt.attempt_id,
                    "attempt_index": attempt.attempt_index,
                    "patch_id": patch_diff.patch_id,
                },
            )
            test_result = self.test_runner.invoke(test_request)
            parsed_test_run = self._parse_test_result(test_result)

            test_results.append(test_result)
            parsed_test_runs.append(parsed_test_run)

            loop_state = loop_state.attach_test_result(
                attempt_id=attempt.attempt_id,
                result=test_result,
                parsed_test_run=parsed_test_run,
            )
            self._record_test_result(loop_state, test_result, parsed_test_run)

            if loop_state.is_terminal:
                self._record_loop_terminated(loop_state)
                break

        if not loop_state.is_terminal and not loop_state.should_continue:
            loop_state = loop_state.stop_by_operator(
                reason=(
                    "Programming repair runtime stopped because no additional "
                    "candidate patches were available."
                )
            )
            self._record_loop_terminated(loop_state)

        return ProgrammingRepairRunReport(
            loop_state=loop_state,
            patch_results=tuple(patch_results),
            test_results=tuple(test_results),
            parsed_test_runs=tuple(parsed_test_runs),
            repair_receipts=self._receipt_payloads(loop_state.loop_id),
            metadata={
                "runtime": "programming_repair",
                "candidate_patch_count": len(patch_candidates),
                **dict(metadata or {}),
            },
        )

    def _parse_test_result(self, result: ToolInvocationResult) -> ParsedTestRun:
        output = dict(result.output)

        required_keys = {
            "command",
            "cwd",
            "return_code",
            "stdout",
            "stderr",
            "timed_out",
            "timeout_seconds",
        }
        if required_keys.issubset(output.keys()):
            command_result = TestCommandResult(
                command=tuple(str(item) for item in output["command"]),
                cwd=str(output["cwd"]),
                return_code=int(output["return_code"]),
                stdout=str(output.get("stdout", "")),
                stderr=str(output.get("stderr", "")),
                timed_out=bool(output.get("timed_out", False)),
                timeout_seconds=float(output.get("timeout_seconds", 0)),
                stdout_truncated=bool(output.get("stdout_truncated", False)),
                stderr_truncated=bool(output.get("stderr_truncated", False)),
            )
            return self.test_result_parser.parse_command_result(command_result)

        if result.status is ToolInvocationStatus.TIMED_OUT:
            return ParsedTestRun(
                status=ParsedTestRunStatus.TIMED_OUT,
                command=(),
                return_code=124,
                timed_out=True,
                metadata={"source": "tool_result_without_command_output"},
            )

        if result.status is ToolInvocationStatus.BLOCKED:
            return ParsedTestRun(
                status=ParsedTestRunStatus.ERRORED,
                command=(),
                return_code=1,
                timed_out=False,
                metadata={
                    "source": "blocked_tool_result_without_command_output",
                    "tool_status": result.status.value,
                },
            )

        if result.status is not ToolInvocationStatus.SUCCEEDED:
            return ParsedTestRun(
                status=ParsedTestRunStatus.FAILED,
                command=(),
                return_code=1,
                timed_out=False,
                metadata={
                    "source": "failed_tool_result_without_command_output",
                    "tool_status": result.status.value,
                },
            )

        return ParsedTestRun(
            status=ParsedTestRunStatus.UNKNOWN,
            command=(),
            return_code=0,
            timed_out=False,
            metadata={"source": "successful_tool_result_without_command_output"},
        )

    def _record_loop_started(self, state: RepairLoopState) -> None:
        if self.repair_receipt_ledger is None:
            return
        self.repair_receipt_ledger.record_loop_started(state=state)

    def _record_attempt_started(
        self,
        state: RepairLoopState,
        patch_diff: PatchDiff,
    ) -> None:
        if self.repair_receipt_ledger is None:
            return
        self.repair_receipt_ledger.record_attempt_started(
            state=state,
            patch_diff=patch_diff,
        )

    def _record_patch_result(
        self,
        state: RepairLoopState,
        result: ToolInvocationResult,
    ) -> None:
        if self.repair_receipt_ledger is None:
            return
        self.repair_receipt_ledger.record_patch_result(
            state=state,
            result=result,
        )

    def _record_test_result(
        self,
        state: RepairLoopState,
        result: ToolInvocationResult,
        parsed_test_run: ParsedTestRun,
    ) -> None:
        if self.repair_receipt_ledger is None:
            return
        self.repair_receipt_ledger.record_test_result(
            state=state,
            result=result,
            parsed_test_run=parsed_test_run,
        )

    def _record_loop_terminated(self, state: RepairLoopState) -> None:
        if self.repair_receipt_ledger is None:
            return
        self.repair_receipt_ledger.record_loop_terminated(state=state)

    def _receipt_payloads(self, loop_id: str) -> tuple[dict[str, Any], ...]:
        if self.repair_receipt_ledger is None:
            return ()

        snapshot = self.repair_receipt_ledger.snapshot()
        return tuple(
            receipt.to_dict()
            for receipt in snapshot.filter_by_loop(loop_id)
        )


def _test_arguments(
    *,
    test_command: tuple[str, ...] | None,
    test_working_directory: str,
) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "working_directory": test_working_directory,
    }

    if test_command is not None:
        arguments["command"] = list(test_command)

    return arguments
