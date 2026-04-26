from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ix_blackfox.tools.artifacts import ToolArtifactStore
from ix_blackfox.tools.contracts import (
    ToolFailure,
    ToolFailureKind,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolInvocationStatus,
    ToolOutputArtifact,
)
from ix_blackfox.tools.manifest import (
    ToolApprovalMode,
    ToolCapability,
    ToolManifest,
    ToolPathPolicy,
    ToolSideEffect,
)
from ix_blackfox.tools.receipts import ToolInvocationReceiptLedger
from ix_blackfox.tools.workspace import WorkspacePathResolver, WorkspacePathViolation


class TestRunnerWorkspaceError(RuntimeError):
    """
    Raised when governed test execution cannot be safely started.
    """


@dataclass(frozen=True, slots=True)
class TestCommandResult:
    """
    Normalized subprocess result from a governed test command.
    """

    command: tuple[str, ...]
    cwd: str
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool
    timeout_seconds: float
    stdout_truncated: bool = False
    stderr_truncated: bool = False

    @property
    def passed(self) -> bool:
        return self.return_code == 0 and not self.timed_out

    @property
    def failed(self) -> bool:
        return not self.passed

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": list(self.command),
            "cwd": self.cwd,
            "return_code": self.return_code,
            "passed": self.passed,
            "failed": self.failed,
            "timed_out": self.timed_out,
            "timeout_seconds": self.timeout_seconds,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
        }


@dataclass(frozen=True, slots=True)
class TestRunnerTool:
    """
    Governed local test runner for reserved BlackFox workspaces.

    The runner deliberately avoids shell execution. Commands are passed as argv
    lists and must match an allowlist. This prevents accidental shell expansion
    and keeps test execution auditable.

    The tool still does not authorize itself. A gateway/policy layer must decide
    whether the invocation is allowed, requires review, or is blocked before this
    wrapper is called.
    """

    workspace_root: Path
    path_policy: ToolPathPolicy | None = None
    require_workspace_marker: bool = True
    workspace_marker_name: str = ".blackfox-workspace"
    default_command: tuple[str, ...] = ("python", "-m", "pytest", "-q")
    allowed_executables: tuple[str, ...] = ("python", "python3", "py", "pytest")
    timeout_seconds: float = 60.0
    output_limit_chars: int = 120_000
    artifact_store: ToolArtifactStore | None = None
    receipt_ledger: ToolInvocationReceiptLedger | None = None

    tool_id: str = "blackfox.workspace.run_tests"

    def __post_init__(self) -> None:
        if not self.workspace_marker_name.strip():
            raise ValueError("workspace_marker_name must not be empty.")
        if self.timeout_seconds <= 0:
            raise ValueError("TestRunnerTool timeout_seconds must be positive.")
        if self.output_limit_chars <= 0:
            raise ValueError("TestRunnerTool output_limit_chars must be positive.")
        if not self.default_command:
            raise ValueError("TestRunnerTool default_command must not be empty.")
        if not self.allowed_executables:
            raise ValueError("TestRunnerTool allowed_executables must not be empty.")

    @property
    def manifest(self) -> ToolManifest:
        return build_test_runner_manifest(
            path_policy=self.path_policy or _default_test_runner_path_policy(),
        )

    def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        if request.tool_id != self.tool_id:
            return _failed_result(
                request=request,
                status=ToolInvocationStatus.FAILED,
                kind=ToolFailureKind.INVALID_REQUEST,
                message=(
                    f"TestRunnerTool expected tool_id {self.tool_id!r}; "
                    f"got {request.tool_id!r}."
                ),
            )

        if request.capability is not ToolCapability.TEST_EXECUTION:
            return _failed_result(
                request=request,
                status=ToolInvocationStatus.FAILED,
                kind=ToolFailureKind.UNSUPPORTED_CAPABILITY,
                message="TestRunnerTool only supports TEST_EXECUTION capability.",
            )

        self._record_started(request)

        try:
            workspace_root = self._validated_workspace_root()
            resolver = WorkspacePathResolver(
                workspace_root=workspace_root,
                path_policy=self.path_policy or _default_test_runner_path_policy(),
            )
            working_directory = resolver.resolve(
                str(request.arguments.get("working_directory", "."))
            )
            if not working_directory.is_dir():
                raise TestRunnerWorkspaceError(
                    f"Test runner working_directory is not a directory: "
                    f"{working_directory}"
                )

            command = _command_from_arguments(
                arguments=request.arguments,
                default_command=self.default_command,
            )
            self._validate_command(command)
            timeout = _timeout_from_arguments(
                arguments=request.arguments,
                default_timeout=self.timeout_seconds,
            )
            environment = self._build_environment(request.arguments)

            command_result = self._run_command(
                command=command,
                cwd=working_directory,
                timeout=timeout,
                environment=environment,
            )
            artifacts = self._persist_command_artifacts(
                request=request,
                command_result=command_result,
            )

            status = (
                ToolInvocationStatus.SUCCEEDED
                if command_result.passed
                else ToolInvocationStatus.FAILED
            )
            failure = None
            if status is ToolInvocationStatus.FAILED:
                failure = ToolFailure(
                    kind=(
                        ToolFailureKind.TIMEOUT
                        if command_result.timed_out
                        else ToolFailureKind.EXECUTION_ERROR
                    ),
                    message=(
                        "Governed test command timed out."
                        if command_result.timed_out
                        else "Governed test command returned a non-zero exit code."
                    ),
                    retryable=True,
                    metadata={
                        "return_code": command_result.return_code,
                        "timed_out": command_result.timed_out,
                    },
                )

            if status is ToolInvocationStatus.SUCCEEDED:
                result = ToolInvocationResult.succeeded(
                    request=request,
                    output=command_result.to_dict(),
                    artifacts=artifacts,
                    metadata={
                        "workspace_root": str(workspace_root),
                        "working_directory": command_result.cwd,
                        "tool_id": self.tool_id,
                    },
                )
            else:
                result = ToolInvocationResult.failed(
                    request=request,
                    status=(
                        ToolInvocationStatus.TIMED_OUT
                        if command_result.timed_out
                        else ToolInvocationStatus.FAILED
                    ),
                    failure=failure,
                    output=command_result.to_dict(),
                    started_at=None,
                    finished_at=None,
                    metadata={
                        "workspace_root": str(workspace_root),
                        "working_directory": command_result.cwd,
                        "tool_id": self.tool_id,
                        "artifact_uris": [artifact.uri for artifact in artifacts],
                    },
                )

            self._record_result(request=request, result=result)
            self._record_artifacts(result=result)
            return result

        except WorkspacePathViolation as exc:
            result = _failed_result(
                request=request,
                status=ToolInvocationStatus.BLOCKED,
                kind=ToolFailureKind.PATH_VIOLATION,
                message=str(exc),
            )
            self._record_result(request=request, result=result)
            return result
        except TestRunnerWorkspaceError as exc:
            result = _failed_result(
                request=request,
                status=ToolInvocationStatus.BLOCKED,
                kind=ToolFailureKind.EXECUTION_ERROR,
                message=str(exc),
            )
            self._record_result(request=request, result=result)
            return result
        except Exception as exc:
            result = _failed_result(
                request=request,
                status=ToolInvocationStatus.FAILED,
                kind=ToolFailureKind.EXECUTION_ERROR,
                message=f"Governed test execution failed: {exc}",
            )
            self._record_result(request=request, result=result)
            return result

    def _validated_workspace_root(self) -> Path:
        root = self.workspace_root.expanduser().resolve()

        if not root.exists():
            raise TestRunnerWorkspaceError(f"Workspace root does not exist: {root}")
        if not root.is_dir():
            raise TestRunnerWorkspaceError(f"Workspace root is not a directory: {root}")

        if self.require_workspace_marker:
            marker_path = root / self.workspace_marker_name
            if not marker_path.exists() or not marker_path.is_file():
                raise TestRunnerWorkspaceError(
                    "Test execution requires a reserved BlackFox workspace marker: "
                    f"{marker_path}"
                )

        return root

    def _validate_command(self, command: tuple[str, ...]) -> None:
        if not command:
            raise TestRunnerWorkspaceError("Test command must not be empty.")

        executable = Path(command[0]).name.lower()
        allowed = {item.lower() for item in self.allowed_executables}

        if executable not in allowed:
            raise TestRunnerWorkspaceError(
                f"Test command executable is not allowed: {command[0]!r}. "
                f"Allowed executables: {', '.join(sorted(allowed))}."
            )

        for argument in command:
            if "\x00" in argument:
                raise TestRunnerWorkspaceError("Test command contains a NUL byte.")
            if any(separator in argument for separator in ("\n", "\r")):
                raise TestRunnerWorkspaceError(
                    "Test command arguments must not contain line breaks."
                )

    def _build_environment(self, arguments: Mapping[str, Any]) -> dict[str, str]:
        allowed_env = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "WINDIR": os.environ.get("WINDIR", ""),
            "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": os.environ.get(
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
                "1",
            ),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }

        raw_extra_env = arguments.get("environment", {})
        if raw_extra_env is None:
            raw_extra_env = {}
        if not isinstance(raw_extra_env, Mapping):
            raise TestRunnerWorkspaceError("environment argument must be a mapping.")

        for key, value in raw_extra_env.items():
            key_text = str(key).strip()
            if not key_text:
                raise TestRunnerWorkspaceError("environment variable names must not be empty.")
            if _looks_sensitive_env_key(key_text):
                raise TestRunnerWorkspaceError(
                    f"Sensitive environment variable is not allowed: {key_text}"
                )
            allowed_env[key_text] = str(value)

        return allowed_env

    def _run_command(
        self,
        *,
        command: tuple[str, ...],
        cwd: Path,
        timeout: float,
        environment: Mapping[str, str],
    ) -> TestCommandResult:
        try:
            completed = subprocess.run(
                list(command),
                cwd=str(cwd),
                env=dict(environment),
                text=True,
                capture_output=True,
                timeout=timeout,
                shell=False,
                check=False,
            )
            stdout, stdout_truncated = _truncate_output(
                completed.stdout,
                self.output_limit_chars,
            )
            stderr, stderr_truncated = _truncate_output(
                completed.stderr,
                self.output_limit_chars,
            )

            return TestCommandResult(
                command=command,
                cwd=str(cwd),
                return_code=completed.returncode,
                stdout=stdout,
                stderr=stderr,
                timed_out=False,
                timeout_seconds=timeout,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
            )

        except subprocess.TimeoutExpired as exc:
            stdout = _decode_timeout_output(exc.stdout)
            stderr = _decode_timeout_output(exc.stderr)
            stdout, stdout_truncated = _truncate_output(stdout, self.output_limit_chars)
            stderr, stderr_truncated = _truncate_output(stderr, self.output_limit_chars)

            return TestCommandResult(
                command=command,
                cwd=str(cwd),
                return_code=124,
                stdout=stdout,
                stderr=stderr,
                timed_out=True,
                timeout_seconds=timeout,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
            )

    def _persist_command_artifacts(
        self,
        *,
        request: ToolInvocationRequest,
        command_result: TestCommandResult,
    ) -> tuple[ToolOutputArtifact, ...]:
        store = self.artifact_store
        if store is None:
            return ()

        run_segment = request.run_id or request.invocation_id
        base_path = f"test-runs/{run_segment}/{request.invocation_id}"

        summary_artifact = store.write_json(
            relative_path=f"{base_path}/test-result.json",
            payload=command_result.to_dict(),
            metadata={
                "source_tool": self.tool_id,
                "artifact_kind": "test_result",
                "invocation_id": request.invocation_id,
                "run_id": request.run_id,
            },
        )
        stdout_artifact = store.write_text(
            relative_path=f"{base_path}/stdout.txt",
            text=command_result.stdout,
            media_type="text/plain",
            metadata={
                "source_tool": self.tool_id,
                "artifact_kind": "stdout",
                "invocation_id": request.invocation_id,
                "truncated": command_result.stdout_truncated,
            },
        )
        stderr_artifact = store.write_text(
            relative_path=f"{base_path}/stderr.txt",
            text=command_result.stderr,
            media_type="text/plain",
            metadata={
                "source_tool": self.tool_id,
                "artifact_kind": "stderr",
                "invocation_id": request.invocation_id,
                "truncated": command_result.stderr_truncated,
            },
        )

        return (summary_artifact, stdout_artifact, stderr_artifact)

    def _record_started(self, request: ToolInvocationRequest) -> None:
        if self.receipt_ledger is None:
            return
        self.receipt_ledger.record_invocation_started(
            request=request,
            actor="tools.test_runner",
        )

    def _record_result(
        self,
        *,
        request: ToolInvocationRequest,
        result: ToolInvocationResult,
    ) -> None:
        if self.receipt_ledger is None:
            return
        self.receipt_ledger.record_invocation_result(
            result=result,
            request=request,
            actor="tools.test_runner",
        )

    def _record_artifacts(self, *, result: ToolInvocationResult) -> None:
        if self.receipt_ledger is None:
            return

        for artifact in result.artifacts:
            self.receipt_ledger.record_artifact_emitted(
                result=result,
                artifact_name=artifact.name,
                artifact_uri=artifact.uri,
                actor="tools.test_runner",
                metadata={
                    "artifact_id": artifact.artifact_id,
                    "sha256": artifact.sha256,
                    "media_type": artifact.media_type,
                },
            )


def build_test_runner_manifest(
    *,
    path_policy: ToolPathPolicy | None = None,
) -> ToolManifest:
    return ToolManifest(
        tool_id="blackfox.workspace.run_tests",
        name="Workspace Run Tests",
        version="0.1.0",
        summary=(
            "Run an allowlisted local test command inside a reserved BlackFox "
            "workspace."
        ),
        capabilities=(ToolCapability.TEST_EXECUTION, ToolCapability.COMMAND_EXECUTION),
        side_effects=(
            ToolSideEffect.READ_WORKSPACE,
            ToolSideEffect.WRITE_WORKSPACE,
            ToolSideEffect.RUN_PROCESS,
        ),
        approval_mode=ToolApprovalMode.ALWAYS,
        input_schema={
            "type": "object",
            "properties": {
                "command": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["python", "-m", "pytest", "-q"],
                },
                "working_directory": {"type": "string", "default": "."},
                "timeout_seconds": {"type": "number", "minimum": 1},
                "environment": {"type": "object"},
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "required": [
                "command",
                "cwd",
                "return_code",
                "passed",
                "failed",
                "timed_out",
                "timeout_seconds",
                "stdout",
                "stderr",
                "stdout_truncated",
                "stderr_truncated",
            ],
        },
        default_timeout_seconds=60.0,
        path_policy=path_policy or _default_test_runner_path_policy(),
        tags=("workspace", "tests", "process", "approval-required"),
        metadata={
            "wave": "2",
            "tool_family": "workspace",
            "side_effect_class": "run-process",
            "requires_reserved_workspace": True,
            "shell": False,
        },
    )


def _default_test_runner_path_policy() -> ToolPathPolicy:
    return ToolPathPolicy(
        allowed_roots=(
            ".",
            "src",
            "tests",
            "scripts",
            "examples",
        ),
        blocked_roots=(
            ".git",
            ".env",
            ".ssh",
            "secrets",
            "credentials",
            "dist",
            "build",
        ),
        allow_absolute_paths=False,
    )


def _command_from_arguments(
    *,
    arguments: Mapping[str, Any],
    default_command: tuple[str, ...],
) -> tuple[str, ...]:
    raw_command = arguments.get("command", default_command)

    if isinstance(raw_command, str):
        raise TestRunnerWorkspaceError(
            "command must be an argv list, not a shell command string."
        )

    if not isinstance(raw_command, Sequence):
        raise TestRunnerWorkspaceError("command must be a sequence of strings.")

    command: list[str] = []
    for item in raw_command:
        if not isinstance(item, str):
            raise TestRunnerWorkspaceError("command must contain only strings.")
        cleaned = item.strip()
        if not cleaned:
            raise TestRunnerWorkspaceError("command arguments must not be empty.")
        command.append(cleaned)

    return tuple(command)


def _timeout_from_arguments(
    *,
    arguments: Mapping[str, Any],
    default_timeout: float,
) -> float:
    raw_timeout = arguments.get("timeout_seconds", default_timeout)
    timeout = float(raw_timeout)

    if timeout <= 0:
        raise TestRunnerWorkspaceError("timeout_seconds must be positive.")
    if timeout > 900:
        raise TestRunnerWorkspaceError("timeout_seconds must not exceed 900 seconds.")

    return timeout


def _truncate_output(value: str, limit: int) -> tuple[str, bool]:
    if len(value) <= limit:
        return value, False
    return value[:limit] + "\n[blackfox: output truncated]\n", True


def _decode_timeout_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _looks_sensitive_env_key(key: str) -> bool:
    normalized = key.strip().lower()
    sensitive_fragments = (
        "secret",
        "token",
        "credential",
        "password",
        "passwd",
        "api_key",
        "apikey",
        "private_key",
        "access_key",
    )
    return any(fragment in normalized for fragment in sensitive_fragments)


def _failed_result(
    *,
    request: ToolInvocationRequest,
    status: ToolInvocationStatus,
    kind: ToolFailureKind,
    message: str,
    retryable: bool = False,
    metadata: Mapping[str, Any] | None = None,
) -> ToolInvocationResult:
    return ToolInvocationResult.failed(
        request=request,
        status=status,
        failure=ToolFailure(
            kind=kind,
            message=message,
            retryable=retryable,
            metadata=dict(metadata or {}),
        ),
    )
