from __future__ import annotations

import sys
from pathlib import Path

import pytest

from ix_blackfox.sandbox import (
    LocalAuditSandboxBackend,
    SandboxBackendKind,
    SandboxCommandRequest,
    SandboxEnvironmentPolicy,
    SandboxExecutionStatus,
    SandboxFilesystemPolicy,
    SandboxMount,
    SandboxMountAccess,
    SandboxNetworkPolicy,
    SandboxProfile,
    SandboxResourceLimits,
    default_wave6_local_audit_profile,
)


def test_wave6_local_audit_backend_executes_allowed_command(tmp_path: Path) -> None:
    request = SandboxCommandRequest(
        request_id="local-audit-success",
        profile=_profile(),
        argv=("python", "-c", "print('wave6-local-audit')"),
        expected_head_sha="abc1234",
    )

    run = LocalAuditSandboxBackend().run(request, repo_root=tmp_path)

    assert run.passed is True
    assert run.result.status is SandboxExecutionStatus.SUCCEEDED
    assert run.result.exit_code == 0
    assert run.stdout_text == "wave6-local-audit\n"
    assert run.stderr_text == ""
    assert run.result.stdout_sha256 is not None
    assert run.result.metadata["backend"] == "local_audit"
    assert run.result.metadata["isolation_claim"] == "none-local-audit-only"
    assert "does not provide hardened" in run.local_audit_warning


def test_wave6_local_audit_backend_scrubs_host_environment_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BLACKFOX_SECRET_SHOULD_NOT_LEAK", "secret-value")
    request = SandboxCommandRequest(
        request_id="local-audit-scrub-env",
        profile=_profile(),
        argv=(
            "python",
            "-c",
            "import os; print(os.getenv('BLACKFOX_SECRET_SHOULD_NOT_LEAK', 'missing'))",
        ),
    )

    run = LocalAuditSandboxBackend().run(request, repo_root=tmp_path)

    assert run.result.status is SandboxExecutionStatus.SUCCEEDED
    assert run.stdout_text == "missing\n"


def test_wave6_local_audit_backend_injects_explicit_environment(tmp_path: Path) -> None:
    profile = _profile(
        environment=SandboxEnvironmentPolicy(
            injected_variables={"BLACKFOX_VISIBLE": "allowed-value"}
        )
    )
    request = SandboxCommandRequest(
        request_id="local-audit-injected-env",
        profile=profile,
        argv=("python", "-c", "import os; print(os.environ['BLACKFOX_VISIBLE'])"),
    )

    run = LocalAuditSandboxBackend().run(request, repo_root=tmp_path)

    assert run.result.status is SandboxExecutionStatus.SUCCEEDED
    assert run.stdout_text == "allowed-value\n"


def test_wave6_local_audit_backend_blocks_unmapped_working_directory(tmp_path: Path) -> None:
    request = SandboxCommandRequest(
        request_id="local-audit-unmapped-cwd",
        profile=_profile(),
        argv=("python", "-c", "print('should-not-run')"),
        working_directory="/unmounted",
    )

    run = LocalAuditSandboxBackend().run(request, repo_root=tmp_path)

    assert run.result.status is SandboxExecutionStatus.POLICY_BLOCKED
    assert run.result.exit_code is None
    assert run.result.policy_issue == "working directory is not covered by any sandbox mount"
    assert run.stdout_text == ""


def test_wave6_local_audit_backend_blocks_excessive_output(tmp_path: Path) -> None:
    profile = _profile(
        resources=SandboxResourceLimits(
            timeout_seconds=30,
            max_memory_mb=256,
            max_processes=16,
            max_output_bytes=8,
            max_artifact_bytes=1_048_576,
        )
    )
    request = SandboxCommandRequest(
        request_id="local-audit-output-limit",
        profile=profile,
        argv=("python", "-c", "print('this output is too long')"),
    )

    run = LocalAuditSandboxBackend().run(request, repo_root=tmp_path)

    assert run.result.status is SandboxExecutionStatus.POLICY_BLOCKED
    assert run.result.policy_issue == "combined stdout and stderr exceeded max_output_bytes"
    assert run.result.metadata["raw_exit_code"] == "0"


def test_wave6_local_audit_backend_reports_timeout(tmp_path: Path) -> None:
    profile = _profile(
        resources=SandboxResourceLimits(
            timeout_seconds=1,
            max_memory_mb=256,
            max_processes=16,
            max_output_bytes=65_536,
            max_artifact_bytes=1_048_576,
        )
    )
    request = SandboxCommandRequest(
        request_id="local-audit-timeout",
        profile=profile,
        argv=("python", "-c", "import time; time.sleep(3)"),
    )

    run = LocalAuditSandboxBackend().run(request, repo_root=tmp_path)

    assert run.result.status is SandboxExecutionStatus.TIMED_OUT
    assert run.result.exit_code is None


def test_wave6_local_audit_backend_rejects_non_local_audit_profile(tmp_path: Path) -> None:
    profile = SandboxProfile(
        profile_id="wave6.container-shaped-profile",
        backend=SandboxBackendKind.CONTAINER,
        filesystem=_filesystem_policy(),
        resources=_resources(),
        network=SandboxNetworkPolicy(),
        allowed_commands=("python",),
    )
    request = SandboxCommandRequest(
        request_id="local-audit-wrong-backend",
        profile=profile,
        argv=("python", "-c", "print('wrong backend')"),
    )

    with pytest.raises(ValueError, match="only accepts local_audit"):
        LocalAuditSandboxBackend().run(request, repo_root=tmp_path)


def test_wave6_local_audit_backend_reports_missing_executable(tmp_path: Path) -> None:
    profile = SandboxProfile(
        profile_id="wave6.local-audit.missing-executable",
        backend=SandboxBackendKind.LOCAL_AUDIT,
        filesystem=_filesystem_policy(),
        resources=_resources(),
        network=SandboxNetworkPolicy(),
        allowed_commands=("blackfox-command-that-does-not-exist",),
    )
    request = SandboxCommandRequest(
        request_id="local-audit-missing-executable",
        profile=profile,
        argv=("blackfox-command-that-does-not-exist", "--version"),
    )

    run = LocalAuditSandboxBackend().run(request, repo_root=tmp_path)

    assert run.result.status is SandboxExecutionStatus.BACKEND_UNAVAILABLE
    assert "executable not found" in run.stderr_text


def test_wave6_default_local_audit_profile_can_run_pytest_style_command(
    tmp_path: Path,
) -> None:
    request = SandboxCommandRequest(
        request_id="local-audit-default-profile",
        profile=default_wave6_local_audit_profile(),
        argv=("python", "-c", "print('default-profile-ok')"),
    )

    run = LocalAuditSandboxBackend().run(request, repo_root=tmp_path)

    assert run.result.status is SandboxExecutionStatus.SUCCEEDED
    assert run.stdout_text == "default-profile-ok\n"


def _profile(
    *,
    resources: SandboxResourceLimits | None = None,
    environment: SandboxEnvironmentPolicy | None = None,
) -> SandboxProfile:
    return SandboxProfile(
        profile_id="wave6.local-audit.test",
        backend=SandboxBackendKind.LOCAL_AUDIT,
        filesystem=_filesystem_policy(),
        resources=resources if resources is not None else _resources(),
        network=SandboxNetworkPolicy(),
        environment=environment if environment is not None else SandboxEnvironmentPolicy(),
        allowed_commands=("python",),
        metadata={
            "python_executable": sys.executable,
            "claim": "local-audit-tests-do-not-claim-hardening",
        },
    )


def _filesystem_policy() -> SandboxFilesystemPolicy:
    return SandboxFilesystemPolicy(
        mounts=(
            SandboxMount(
                source=".",
                target="/workspace/src",
                access=SandboxMountAccess.READ_ONLY,
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
