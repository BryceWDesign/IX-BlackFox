from __future__ import annotations

import hashlib
import os
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ix_blackfox.sandbox.contracts import (
    SandboxBackendKind,
    SandboxCommandRequest,
    SandboxCommandResult,
    SandboxEnvironmentPolicy,
    SandboxExecutionStatus,
    SandboxFilesystemPolicy,
    SandboxMount,
    SandboxMountAccess,
    SandboxNetworkMode,
    SandboxNetworkPolicy,
    SandboxProfile,
    SandboxResourceLimits,
)
from ix_blackfox.sandbox.workspace import (
    SandboxArtifactManifest,
    SandboxWorkspace,
    SandboxWorkspaceManager,
)

_CONTAINER_WARNING = (
    "container backend applies Docker sandbox flags and deny-all network policy, "
    "but it is not a certification, production security boundary, or defense-approved runtime"
)

ContainerExecutor = Callable[[list[str], int], subprocess.CompletedProcess[str]]


@dataclass(frozen=True, slots=True)
class ContainerSandboxRun:
    request: SandboxCommandRequest
    result: SandboxCommandResult
    stdout_text: str
    stderr_text: str
    docker_command: tuple[str, ...]
    artifact_manifest: SandboxArtifactManifest | None
    workspace: SandboxWorkspace | None
    container_warning: str = _CONTAINER_WARNING

    @property
    def passed(self) -> bool:
        return self.result.passed

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request.to_dict(),
            "result": self.result.to_dict(),
            "stdout_text": self.stdout_text,
            "stderr_text": self.stderr_text,
            "docker_command": list(self.docker_command),
            "artifact_manifest": self.artifact_manifest.to_dict()
            if self.artifact_manifest is not None
            else None,
            "workspace": self.workspace.to_dict() if self.workspace is not None else None,
            "container_warning": self.container_warning,
        }


@dataclass(frozen=True, slots=True)
class ContainerSandboxBackend:
    workspace_base_dir: Path = Path(".blackfox-sandbox/workspaces")
    keep_workspaces: bool = False
    executor: ContainerExecutor | None = None

    def run(
        self,
        request: SandboxCommandRequest,
        *,
        repo_root: Path | None = None,
    ) -> ContainerSandboxRun:
        start = time.monotonic()
        root = (repo_root if repo_root is not None else Path.cwd()).resolve()
        if request.profile.backend is not SandboxBackendKind.CONTAINER:
            raise ValueError("ContainerSandboxBackend only accepts container profiles.")

        policy_issue = self._preflight_issue(request)
        if policy_issue is not None:
            return _blocked_run(
                request,
                policy_issue=policy_issue,
                duration_ms=_elapsed_ms(start),
                docker_command=(),
                workspace=None,
                artifact_manifest=None,
            )

        manager = SandboxWorkspaceManager(
            self.workspace_base_dir,
            keep_workspaces=self.keep_workspaces,
        )
        workspace: SandboxWorkspace | None = None
        docker_command: list[str] = []
        try:
            workspace = manager.create_workspace(request.profile, repo_root=root)
            docker_command = _build_docker_command(request, workspace)
            completed = _execute_docker_command(
                docker_command,
                timeout_seconds=request.profile.resources.timeout_seconds,
                executor=self.executor,
            )
        except subprocess.TimeoutExpired as exc:
            stdout_text = _coerce_text(exc.stdout)
            stderr_text = _coerce_text(exc.stderr)
            return ContainerSandboxRun(
                request=request,
                result=SandboxCommandResult(
                    request_id=request.request_id,
                    status=SandboxExecutionStatus.TIMED_OUT,
                    exit_code=None,
                    duration_ms=_elapsed_ms(start),
                    stdout_sha256=_sha256_text(stdout_text),
                    stderr_sha256=_sha256_text(stderr_text),
                    policy_issue=None,
                    metadata=_metadata(
                        request,
                        workspace=workspace,
                        artifact_manifest=None,
                    ),
                ),
                stdout_text=stdout_text,
                stderr_text=stderr_text,
                docker_command=tuple(docker_command),
                artifact_manifest=None,
                workspace=workspace,
            )
        except FileNotFoundError as exc:
            return _backend_unavailable_run(
                request,
                stderr_text=str(exc),
                duration_ms=_elapsed_ms(start),
                docker_command=tuple(docker_command),
                workspace=workspace,
            )
        except OSError as exc:
            return _backend_unavailable_run(
                request,
                stderr_text=str(exc),
                duration_ms=_elapsed_ms(start),
                docker_command=tuple(docker_command),
                workspace=workspace,
            )
        stdout_text = completed.stdout
        stderr_text = completed.stderr
        output_size = len(stdout_text.encode("utf-8")) + len(stderr_text.encode("utf-8"))
        if output_size > request.profile.resources.max_output_bytes:
            run = ContainerSandboxRun(
                request=request,
                result=SandboxCommandResult(
                    request_id=request.request_id,
                    status=SandboxExecutionStatus.POLICY_BLOCKED,
                    exit_code=None,
                    duration_ms=_elapsed_ms(start),
                    stdout_sha256=_sha256_text(stdout_text),
                    stderr_sha256=_sha256_text(stderr_text),
                    policy_issue="combined stdout and stderr exceeded max_output_bytes",
                    metadata=_metadata(
                        request,
                        workspace=workspace,
                        artifact_manifest=None,
                    )
                    | {"raw_exit_code": str(completed.returncode)},
                ),
                stdout_text=stdout_text,
                stderr_text=stderr_text,
                docker_command=tuple(docker_command),
                artifact_manifest=None,
                workspace=workspace,
            )
            self._cleanup(manager, workspace)
            return run

        artifact_manifest: SandboxArtifactManifest | None = None
        try:
            if workspace is not None:
                artifact_manifest = manager.collect_artifacts(workspace)
        except ValueError as exc:
            run = ContainerSandboxRun(
                request=request,
                result=SandboxCommandResult(
                    request_id=request.request_id,
                    status=SandboxExecutionStatus.POLICY_BLOCKED,
                    exit_code=None,
                    duration_ms=_elapsed_ms(start),
                    stdout_sha256=_sha256_text(stdout_text),
                    stderr_sha256=_sha256_text(stderr_text),
                    policy_issue=str(exc),
                    metadata=_metadata(
                        request,
                        workspace=workspace,
                        artifact_manifest=None,
                    )
                    | {"raw_exit_code": str(completed.returncode)},
                ),
                stdout_text=stdout_text,
                stderr_text=stderr_text,
                docker_command=tuple(docker_command),
                artifact_manifest=None,
                workspace=workspace,
            )
            self._cleanup(manager, workspace)
            return run

        status = (
            SandboxExecutionStatus.SUCCEEDED
            if completed.returncode == 0
            else SandboxExecutionStatus.FAILED
        )
        run = ContainerSandboxRun(
            request=request,
            result=SandboxCommandResult(
                request_id=request.request_id,
                status=status,
                exit_code=completed.returncode,
                duration_ms=_elapsed_ms(start),
                stdout_sha256=_sha256_text(stdout_text),
                stderr_sha256=_sha256_text(stderr_text),
                artifact_manifest_sha256=artifact_manifest.digest
                if artifact_manifest is not None
                else None,
                policy_issue=None,
                metadata=_metadata(
                    request,
                    workspace=workspace,
                    artifact_manifest=artifact_manifest,
                )
                | {"raw_exit_code": str(completed.returncode)},
            ),
            stdout_text=stdout_text,
            stderr_text=stderr_text,
            docker_command=tuple(docker_command),
            artifact_manifest=artifact_manifest,
            workspace=workspace,
        )
        self._cleanup(manager, workspace)
        return run

    def _preflight_issue(self, request: SandboxCommandRequest) -> str | None:
        if request.profile.network.mode is not SandboxNetworkMode.DENY_ALL:
            return "container backend currently requires deny_all network mode"
        if not request.profile.network.blocks_all_egress:
            return "container backend currently requires empty egress allowlist"
        if not request.profile.filesystem.read_only_root:
            return "container backend requires read_only_root filesystem policy"
        return None

    def _cleanup(
        self,
        manager: SandboxWorkspaceManager,
        workspace: SandboxWorkspace | None,
    ) -> None:
        if workspace is not None and not self.keep_workspaces:
            manager.cleanup_workspace(workspace)


def default_wave6_container_profile(
    *,
    container_image: str = "python:3.11-slim",
) -> SandboxProfile:
    return SandboxProfile(
        profile_id="wave6.container.default",
        backend=SandboxBackendKind.CONTAINER,
        filesystem=SandboxFilesystemPolicy(
            mounts=(
                SandboxMount(
                    source=".",
                    target="/workspace/src",
                    access=SandboxMountAccess.READ_ONLY,
                ),
                SandboxMount(
                    source=".blackfox-workspace/out",
                    target="/workspace/out",
                    access=SandboxMountAccess.READ_WRITE,
                    required=False,
                ),
                SandboxMount(
                    source=".blackfox-workspace/tmp",
                    target="/workspace/tmp",
                    access=SandboxMountAccess.READ_WRITE,
                    required=False,
                ),
            )
        ),
        resources=SandboxResourceLimits(
            timeout_seconds=300,
            max_memory_mb=1024,
            max_processes=64,
            max_output_bytes=1_048_576,
            max_artifact_bytes=10_485_760,
            cpu_count=1,
        ),
        network=SandboxNetworkPolicy(),
        environment=SandboxEnvironmentPolicy(),
        allowed_commands=("python", "python3", "pytest"),
        metadata={
            "wave": "6",
            "container_image": container_image,
            "claim": "container-sandbox-deny-all-egress-not-production-certification",
        },
    )


def _build_docker_command(
    request: SandboxCommandRequest,
    workspace: SandboxWorkspace,
) -> list[str]:
    image = request.profile.metadata.get("container_image", "python:3.11-slim")
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        str(request.profile.resources.max_processes),
        "--memory",
        f"{request.profile.resources.max_memory_mb}m",
        "--cpus",
        str(request.profile.resources.cpu_count),
        "--workdir",
        request.working_directory,
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
    ]
    for name, value in _build_environment(request).items():
        command.extend(("--env", f"{name}={value}"))
    for mount in request.profile.filesystem.mounts:
        source = workspace.target_map[mount.target]
        mount_spec = f"type=bind,source={source},target={mount.target}"
        if mount.access is SandboxMountAccess.READ_ONLY:
            mount_spec = f"{mount_spec},readonly"
        command.extend(("--mount", mount_spec))
    command.append(image)
    command.extend(request.argv)
    return command


def _execute_docker_command(
    command: list[str],
    *,
    timeout_seconds: int,
    executor: ContainerExecutor | None,
) -> subprocess.CompletedProcess[str]:
    if executor is not None:
        return executor(command, timeout_seconds)
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )


def _build_environment(request: SandboxCommandRequest) -> dict[str, str]:
    policy = request.profile.environment
    env: dict[str, str] = {}
    if policy.inherit_host_environment:
        for name in policy.allowed_variables:
            value = os.environ.get(name)
            if value is not None:
                env[name] = value
    env.update(policy.injected_variables)
    return dict(sorted(env.items()))


def _blocked_run(
    request: SandboxCommandRequest,
    *,
    policy_issue: str,
    duration_ms: int,
    docker_command: tuple[str, ...],
    workspace: SandboxWorkspace | None,
    artifact_manifest: SandboxArtifactManifest | None,
) -> ContainerSandboxRun:
    return ContainerSandboxRun(
        request=request,
        result=SandboxCommandResult(
            request_id=request.request_id,
            status=SandboxExecutionStatus.POLICY_BLOCKED,
            exit_code=None,
            duration_ms=duration_ms,
            stdout_sha256=_sha256_text(""),
            stderr_sha256=_sha256_text(""),
            policy_issue=policy_issue,
            metadata=_metadata(
                request,
                workspace=workspace,
                artifact_manifest=artifact_manifest,
            ),
        ),
        stdout_text="",
        stderr_text="",
        docker_command=docker_command,
        artifact_manifest=artifact_manifest,
        workspace=workspace,
    )


def _backend_unavailable_run(
    request: SandboxCommandRequest,
    *,
    stderr_text: str,
    duration_ms: int,
    docker_command: tuple[str, ...],
    workspace: SandboxWorkspace | None,
) -> ContainerSandboxRun:
    return ContainerSandboxRun(
        request=request,
        result=SandboxCommandResult(
            request_id=request.request_id,
            status=SandboxExecutionStatus.BACKEND_UNAVAILABLE,
            exit_code=None,
            duration_ms=duration_ms,
            stdout_sha256=_sha256_text(""),
            stderr_sha256=_sha256_text(stderr_text),
            policy_issue=None,
            metadata=_metadata(
                request,
                workspace=workspace,
                artifact_manifest=None,
            ),
        ),
        stdout_text="",
        stderr_text=stderr_text,
        docker_command=docker_command,
        artifact_manifest=None,
        workspace=workspace,
    )


def _metadata(
    request: SandboxCommandRequest,
    *,
    workspace: SandboxWorkspace | None,
    artifact_manifest: SandboxArtifactManifest | None,
) -> dict[str, str]:
    metadata = {
        "backend": SandboxBackendKind.CONTAINER.value,
        "profile_id": request.profile.profile_id,
        "profile_digest": request.profile.digest,
        "request_digest": request.digest,
        "network_mode": request.profile.network.mode.value,
        "container_image": request.profile.metadata.get("container_image", "python:3.11-slim"),
        "security_opt_no_new_privileges": "true",
        "cap_drop": "ALL",
        "read_only_root": str(request.profile.filesystem.read_only_root).lower(),
        "isolation_claim": "docker-container-flags-not-certification",
    }
    if workspace is not None:
        metadata["workspace_id"] = workspace.workspace_id
    if artifact_manifest is not None:
        metadata["artifact_manifest_digest"] = artifact_manifest.digest
        metadata["artifact_count"] = str(artifact_manifest.artifact_count)
        metadata["artifact_total_size_bytes"] = str(artifact_manifest.total_size_bytes)
    return metadata


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _coerce_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _elapsed_ms(start: float) -> int:
    return max(0, int((time.monotonic() - start) * 1000))
