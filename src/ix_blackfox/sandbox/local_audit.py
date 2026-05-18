from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ix_blackfox.sandbox.contracts import (
    SandboxBackendKind,
    SandboxCommandRequest,
    SandboxCommandResult,
    SandboxExecutionStatus,
    SandboxNetworkMode,
)

_LOCAL_AUDIT_WARNING = (
    "local-audit backend validates policy and records evidence, but it does not "
    "provide hardened process, filesystem, kernel, or network isolation"
)


@dataclass(frozen=True, slots=True)
class LocalAuditSandboxRun:
    request: SandboxCommandRequest
    result: SandboxCommandResult
    stdout_text: str
    stderr_text: str
    executed_cwd: str
    local_audit_warning: str = _LOCAL_AUDIT_WARNING

    @property
    def passed(self) -> bool:
        return self.result.passed

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request.to_dict(),
            "result": self.result.to_dict(),
            "stdout_text": self.stdout_text,
            "stderr_text": self.stderr_text,
            "executed_cwd": self.executed_cwd,
            "local_audit_warning": self.local_audit_warning,
        }


@dataclass(frozen=True, slots=True)
class LocalAuditSandboxBackend:
    def run(
        self,
        request: SandboxCommandRequest,
        *,
        repo_root: Path | None = None,
    ) -> LocalAuditSandboxRun:
        start = time.monotonic()
        root = (repo_root if repo_root is not None else Path.cwd()).resolve()
        policy_issue = self._preflight_issue(request)
        if policy_issue is not None:
            return _blocked_run(
                request,
                policy_issue=policy_issue,
                duration_ms=_elapsed_ms(start),
            )

        working_directory, path_issue = _resolve_working_directory(request, root)
        if path_issue is not None:
            return _blocked_run(
                request,
                policy_issue=path_issue,
                duration_ms=_elapsed_ms(start),
            )
        if working_directory is None or not working_directory.exists():
            return _backend_unavailable_run(
                request,
                stderr_text=f"mapped working directory does not exist: {working_directory}",
                duration_ms=_elapsed_ms(start),
                executed_cwd=str(working_directory) if working_directory is not None else str(root),
            )

        env = _build_environment(request)
        executable_argv, executable_issue = _resolve_executable(request.argv)
        if executable_issue is not None:
            return _backend_unavailable_run(
                request,
                stderr_text=executable_issue,
                duration_ms=_elapsed_ms(start),
                executed_cwd=str(working_directory),
            )

        try:
            completed = subprocess.run(
                executable_argv,
                cwd=working_directory,
                input=request.stdin_text,
                capture_output=True,
                text=True,
                timeout=request.profile.resources.timeout_seconds,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout_text = _coerce_text(exc.stdout)
            stderr_text = _coerce_text(exc.stderr)
            return LocalAuditSandboxRun(
                request=request,
                result=SandboxCommandResult(
                    request_id=request.request_id,
                    status=SandboxExecutionStatus.TIMED_OUT,
                    exit_code=None,
                    duration_ms=_elapsed_ms(start),
                    stdout_sha256=_sha256_text(stdout_text),
                    stderr_sha256=_sha256_text(stderr_text),
                    policy_issue=None,
                    metadata=_result_metadata(request, working_directory),
                ),
                stdout_text=stdout_text,
                stderr_text=stderr_text,
                executed_cwd=str(working_directory),
            )

        stdout_text = completed.stdout
        stderr_text = completed.stderr
        output_size = len(stdout_text.encode("utf-8")) + len(stderr_text.encode("utf-8"))
        metadata = _result_metadata(request, working_directory)
        metadata["raw_exit_code"] = str(completed.returncode)

        if output_size > request.profile.resources.max_output_bytes:
            return LocalAuditSandboxRun(
                request=request,
                result=SandboxCommandResult(
                    request_id=request.request_id,
                    status=SandboxExecutionStatus.POLICY_BLOCKED,
                    exit_code=None,
                    duration_ms=_elapsed_ms(start),
                    stdout_sha256=_sha256_text(stdout_text),
                    stderr_sha256=_sha256_text(stderr_text),
                    policy_issue="combined stdout and stderr exceeded max_output_bytes",
                    metadata=metadata,
                ),
                stdout_text=stdout_text,
                stderr_text=stderr_text,
                executed_cwd=str(working_directory),
            )

        status = (
            SandboxExecutionStatus.SUCCEEDED
            if completed.returncode == 0
            else SandboxExecutionStatus.FAILED
        )
        return LocalAuditSandboxRun(
            request=request,
            result=SandboxCommandResult(
                request_id=request.request_id,
                status=status,
                exit_code=completed.returncode,
                duration_ms=_elapsed_ms(start),
                stdout_sha256=_sha256_text(stdout_text),
                stderr_sha256=_sha256_text(stderr_text),
                policy_issue=None,
                metadata=metadata,
            ),
            stdout_text=stdout_text,
            stderr_text=stderr_text,
            executed_cwd=str(working_directory),
        )

    def _preflight_issue(self, request: SandboxCommandRequest) -> str | None:
        if request.profile.backend is not SandboxBackendKind.LOCAL_AUDIT:
            raise ValueError("LocalAuditSandboxBackend only accepts local_audit profiles.")
        if request.profile.network.mode is not SandboxNetworkMode.DENY_ALL:
            return "local-audit backend requires deny_all network mode"
        if not request.profile.network.blocks_all_egress:
            return "local-audit backend requires empty egress allowlist"
        if not request.profile.allows_command(request.argv):
            return "command is not allowed by sandbox profile command policy"
        return None


def _blocked_run(
    request: SandboxCommandRequest,
    *,
    policy_issue: str,
    duration_ms: int,
) -> LocalAuditSandboxRun:
    return LocalAuditSandboxRun(
        request=request,
        result=SandboxCommandResult(
            request_id=request.request_id,
            status=SandboxExecutionStatus.POLICY_BLOCKED,
            exit_code=None,
            duration_ms=duration_ms,
            stdout_sha256=_sha256_text(""),
            stderr_sha256=_sha256_text(""),
            policy_issue=policy_issue,
            metadata={
                "backend": SandboxBackendKind.LOCAL_AUDIT.value,
                "profile_id": request.profile.profile_id,
                "profile_digest": request.profile.digest,
                "request_digest": request.digest,
                "isolation_claim": "none-local-audit-only",
            },
        ),
        stdout_text="",
        stderr_text="",
        executed_cwd="",
    )


def _backend_unavailable_run(
    request: SandboxCommandRequest,
    *,
    stderr_text: str,
    duration_ms: int,
    executed_cwd: str,
) -> LocalAuditSandboxRun:
    return LocalAuditSandboxRun(
        request=request,
        result=SandboxCommandResult(
            request_id=request.request_id,
            status=SandboxExecutionStatus.BACKEND_UNAVAILABLE,
            exit_code=None,
            duration_ms=duration_ms,
            stdout_sha256=_sha256_text(""),
            stderr_sha256=_sha256_text(stderr_text),
            policy_issue=None,
            metadata={
                "backend": SandboxBackendKind.LOCAL_AUDIT.value,
                "profile_id": request.profile.profile_id,
                "profile_digest": request.profile.digest,
                "request_digest": request.digest,
                "isolation_claim": "none-local-audit-only",
            },
        ),
        stdout_text="",
        stderr_text=stderr_text,
        executed_cwd=executed_cwd,
    )


def _resolve_working_directory(
    request: SandboxCommandRequest,
    repo_root: Path,
) -> tuple[Path | None, str | None]:
    working_directory = request.working_directory.rstrip("/") or "/"
    for mount in request.profile.filesystem.mounts:
        target = mount.target.rstrip("/") or "/"
        if working_directory == target or working_directory.startswith(f"{target}/"):
            suffix = working_directory.removeprefix(target).lstrip("/")
            host_base = (repo_root / mount.source).resolve()
            host_working_directory = (host_base / suffix).resolve()
            if not _is_relative_to(host_working_directory, host_base):
                return None, "working directory escapes declared sandbox mount"
            return host_working_directory, None
    return None, "working directory is not covered by any sandbox mount"


def _build_environment(request: SandboxCommandRequest) -> dict[str, str]:
    policy = request.profile.environment
    env: dict[str, str] = {}
    if policy.inherit_host_environment:
        for name in policy.allowed_variables:
            value = os.environ.get(name)
            if value is not None:
                env[name] = value
    env.update(policy.injected_variables)
    return env


def _resolve_executable(argv: tuple[str, ...]) -> tuple[list[str], str | None]:
    executable = shutil.which(argv[0])
    if executable is None:
        return [], f"executable not found on local PATH: {argv[0]}"
    return [executable, *argv[1:]], None


def _result_metadata(
    request: SandboxCommandRequest,
    working_directory: Path,
) -> dict[str, str]:
    return {
        "backend": SandboxBackendKind.LOCAL_AUDIT.value,
        "profile_id": request.profile.profile_id,
        "profile_digest": request.profile.digest,
        "request_digest": request.digest,
        "network_mode": request.profile.network.mode.value,
        "executed_cwd": str(working_directory),
        "isolation_claim": "none-local-audit-only",
        "resource_enforcement": "timeout-and-output-size-only",
    }


def _coerce_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _elapsed_ms(start: float) -> int:
    return max(0, int((time.monotonic() - start) * 1000))


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
    except ValueError:
        return False
    return True
