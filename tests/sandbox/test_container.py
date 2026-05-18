from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from ix_blackfox.sandbox import (
    ContainerSandboxBackend,
    SandboxBackendKind,
    SandboxCommandRequest,
    SandboxEnvironmentPolicy,
    SandboxExecutionStatus,
    SandboxFilesystemPolicy,
    SandboxMount,
    SandboxMountAccess,
    SandboxNetworkAllowRule,
    SandboxNetworkMode,
    SandboxNetworkPolicy,
    SandboxProfile,
    SandboxResourceLimits,
    default_wave6_container_profile,
    default_wave6_local_audit_profile,
)


class FakeDockerExecutor:
    def __init__(self, *, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.commands: list[list[str]] = []

    def __call__(
        self,
        command: list[str],
        timeout_seconds: int,
    ) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        out_dir = _mount_source_for_target(command, "/workspace/out")
        if out_dir is not None:
            out_path = Path(out_dir)
            out_path.mkdir(parents=True, exist_ok=True)
            (out_path / "summary.txt").write_text("container artifact\n", encoding="utf-8")
        return subprocess.CompletedProcess(
            args=command,
            returncode=self.returncode,
            stdout=self.stdout,
            stderr=self.stderr,
        )


def test_wave6_container_backend_builds_hardened_deny_all_docker_command(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    executor = FakeDockerExecutor(stdout="container-ok\n")
    profile = default_wave6_container_profile(container_image="python:3.11-slim")
    request = SandboxCommandRequest(
        request_id="container-success",
        profile=profile,
        argv=("python", "-c", "print('container-ok')"),
        expected_head_sha="abc1234",
    )

    run = ContainerSandboxBackend(
        workspace_base_dir=tmp_path / "workspaces",
        executor=executor,
    ).run(request, repo_root=repo)

    command = executor.commands[0]
    assert run.result.status is SandboxExecutionStatus.SUCCEEDED
    assert run.result.exit_code == 0
    assert run.stdout_text == "container-ok\n"
    assert run.artifact_manifest is not None
    assert run.artifact_manifest.artifact_count == 1
    assert run.result.artifact_manifest_sha256 == run.artifact_manifest.digest
    assert "--network" in command
    assert command[command.index("--network") + 1] == "none"
    assert "--read-only" in command
    assert "--cap-drop" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert "--security-opt" in command
    assert command[command.index("--security-opt") + 1] == "no-new-privileges:true"
    assert "--privileged" not in command
    assert "docker-container-flags-not-certification" == run.result.metadata["isolation_claim"]


def test_wave6_container_backend_mounts_source_ro_and_out_tmp_rw(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    executor = FakeDockerExecutor()
    request = SandboxCommandRequest(
        request_id="container-mounts",
        profile=default_wave6_container_profile(),
        argv=("python", "-c", "print('mounts')"),
    )

    ContainerSandboxBackend(
        workspace_base_dir=tmp_path / "workspaces",
        executor=executor,
    ).run(request, repo_root=repo)

    mount_specs = _mount_specs(executor.commands[0])
    assert any("target=/workspace/src" in spec and "readonly" in spec for spec in mount_specs)
    assert any("target=/workspace/out" in spec and "readonly" not in spec for spec in mount_specs)
    assert any("target=/workspace/tmp" in spec and "readonly" not in spec for spec in mount_specs)


def test_wave6_container_backend_passes_only_explicit_environment(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    executor = FakeDockerExecutor()
    profile = default_wave6_container_profile()
    profile = SandboxProfile(
        profile_id=profile.profile_id,
        backend=profile.backend,
        filesystem=profile.filesystem,
        resources=profile.resources,
        network=profile.network,
        environment=SandboxEnvironmentPolicy(
            injected_variables={"BLACKFOX_VISIBLE": "allowed-value"}
        ),
        allowed_commands=profile.allowed_commands,
        metadata=profile.metadata,
    )
    request = SandboxCommandRequest(
        request_id="container-env",
        profile=profile,
        argv=("python", "-c", "print('env')"),
    )

    ContainerSandboxBackend(
        workspace_base_dir=tmp_path / "workspaces",
        executor=executor,
    ).run(request, repo_root=repo)

    command = executor.commands[0]
    assert "--env" in command
    assert "BLACKFOX_VISIBLE=allowed-value" in command
    assert not any(item.startswith("BLACKFOX_SECRET=") for item in command)


def test_wave6_container_backend_blocks_allowlist_network_until_egress_proxy_exists(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    profile = SandboxProfile(
        profile_id="wave6.container.allowlist-not-yet-supported",
        backend=SandboxBackendKind.CONTAINER,
        filesystem=_filesystem(),
        resources=_resources(),
        network=SandboxNetworkPolicy(
            mode=SandboxNetworkMode.ALLOWLIST,
            allowlist=(SandboxNetworkAllowRule(host="example.test", port=443),),
        ),
        allowed_commands=("python",),
        metadata={"container_image": "python:3.11-slim"},
    )
    request = SandboxCommandRequest(
        request_id="container-allowlist-blocked",
        profile=profile,
        argv=("python", "-c", "print('no egress yet')"),
    )

    run = ContainerSandboxBackend(
        workspace_base_dir=tmp_path / "workspaces",
        executor=FakeDockerExecutor(),
    ).run(request, repo_root=repo)

    assert run.result.status is SandboxExecutionStatus.POLICY_BLOCKED
    assert run.result.policy_issue == "container backend currently requires deny_all network mode"
    assert run.docker_command == ()


def test_wave6_container_backend_rejects_non_container_profile(tmp_path: Path) -> None:
    request = SandboxCommandRequest(
        request_id="container-wrong-profile",
        profile=default_wave6_local_audit_profile(),
        argv=("python", "-c", "print('wrong profile')"),
    )

    with pytest.raises(ValueError, match="only accepts container profiles"):
        ContainerSandboxBackend(
            workspace_base_dir=tmp_path / "workspaces",
            executor=FakeDockerExecutor(),
        ).run(request, repo_root=_repo(tmp_path))


def test_wave6_container_backend_reports_missing_docker_runtime(tmp_path: Path) -> None:
    repo = _repo(tmp_path)

    def missing_docker(
        command: list[str],
        timeout_seconds: int,
    ) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("docker executable not found")

    request = SandboxCommandRequest(
        request_id="container-missing-docker",
        profile=default_wave6_container_profile(),
        argv=("python", "-c", "print('missing docker')"),
    )

    run = ContainerSandboxBackend(
        workspace_base_dir=tmp_path / "workspaces",
        executor=missing_docker,
    ).run(request, repo_root=repo)

    assert run.result.status is SandboxExecutionStatus.BACKEND_UNAVAILABLE
    assert "docker executable not found" in run.stderr_text


def test_wave6_container_backend_reports_timeout(tmp_path: Path) -> None:
    repo = _repo(tmp_path)

    def timeout(
        command: list[str],
        timeout_seconds: int,
    ) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(
            cmd=command,
            timeout=timeout_seconds,
            output="started\n",
            stderr="timeout\n",
        )

    request = SandboxCommandRequest(
        request_id="container-timeout",
        profile=default_wave6_container_profile(),
        argv=("python", "-c", "import time; time.sleep(30)"),
    )

    run = ContainerSandboxBackend(
        workspace_base_dir=tmp_path / "workspaces",
        executor=timeout,
    ).run(request, repo_root=repo)

    assert run.result.status is SandboxExecutionStatus.TIMED_OUT
    assert run.stdout_text == "started\n"
    assert run.stderr_text == "timeout\n"


def test_wave6_container_backend_blocks_excessive_output(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    profile = default_wave6_container_profile()
    profile = SandboxProfile(
        profile_id=profile.profile_id,
        backend=profile.backend,
        filesystem=profile.filesystem,
        resources=SandboxResourceLimits(
            timeout_seconds=30,
            max_memory_mb=256,
            max_processes=16,
            max_output_bytes=4,
            max_artifact_bytes=1_048_576,
        ),
        network=profile.network,
        environment=profile.environment,
        allowed_commands=profile.allowed_commands,
        metadata=profile.metadata,
    )
    request = SandboxCommandRequest(
        request_id="container-output-limit",
        profile=profile,
        argv=("python", "-c", "print('too much')"),
    )

    run = ContainerSandboxBackend(
        workspace_base_dir=tmp_path / "workspaces",
        executor=FakeDockerExecutor(stdout="too much output\n"),
    ).run(request, repo_root=repo)

    assert run.result.status is SandboxExecutionStatus.POLICY_BLOCKED
    assert run.result.policy_issue == "combined stdout and stderr exceeded max_output_bytes"


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "main.py").write_text("print('hello')\n", encoding="utf-8")
    return repo


def _filesystem() -> SandboxFilesystemPolicy:
    return SandboxFilesystemPolicy(
        mounts=(
            SandboxMount(
                source="src",
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
    )


def _resources() -> SandboxResourceLimits:
    return SandboxResourceLimits(
        timeout_seconds=30,
        max_memory_mb=256,
        max_processes=16,
        max_output_bytes=65_536,
        max_artifact_bytes=1_048_576,
    )


def _mount_specs(command: list[str]) -> tuple[str, ...]:
    specs: list[str] = []
    for index, value in enumerate(command):
        if value == "--mount":
            specs.append(command[index + 1])
    return tuple(specs)


def _mount_source_for_target(command: list[str], target: str) -> str | None:
    for spec in _mount_specs(command):
        parts = dict(part.split("=", 1) for part in spec.split(",") if "=" in part)
        if parts.get("target") == target:
            return parts.get("source")
    return None
