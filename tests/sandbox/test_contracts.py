from __future__ import annotations

import pytest

from ix_blackfox.sandbox import (
    SandboxBackendKind,
    SandboxCommandRequest,
    SandboxCommandResult,
    SandboxExecutionStatus,
    SandboxFilesystemPolicy,
    SandboxMount,
    SandboxMountAccess,
    SandboxNetworkAllowRule,
    SandboxNetworkMode,
    SandboxNetworkPolicy,
    SandboxProfile,
    SandboxResourceLimits,
    default_wave6_local_audit_profile,
)

_SHA256 = "a" * 64


def test_wave6_default_local_audit_profile_is_deny_all_and_digest_stable() -> None:
    profile = default_wave6_local_audit_profile()

    assert profile.backend is SandboxBackendKind.LOCAL_AUDIT
    assert profile.network.mode is SandboxNetworkMode.DENY_ALL
    assert profile.network.blocks_all_egress is True
    assert len(profile.digest) == 64
    assert profile.digest == default_wave6_local_audit_profile().digest
    assert profile.to_dict()["digest"] == profile.digest
    assert profile.to_dict()["metadata"]["claim"] == "contracts-only-local-audit-is-not-isolation"


def test_wave6_sandbox_command_request_binds_profile_digest_and_head_sha() -> None:
    profile = default_wave6_local_audit_profile()
    request = SandboxCommandRequest(
        request_id="sandbox-request-1",
        profile=profile,
        argv=("python", "-m", "pytest", "tests/sandbox"),
        expected_head_sha="abc1234",
        metadata={"wave": "6"},
    )

    payload = request.to_dict()

    assert payload["profile_digest"] == profile.digest
    assert payload["expected_head_sha"] == "abc1234"
    assert len(request.digest) == 64
    assert request.digest == SandboxCommandRequest(
        request_id="sandbox-request-1",
        profile=profile,
        argv=("python", "-m", "pytest", "tests/sandbox"),
        expected_head_sha="abc1234",
        metadata={"wave": "6"},
    ).digest


def test_wave6_sandbox_command_request_rejects_denied_command_fragments() -> None:
    profile = default_wave6_local_audit_profile()

    with pytest.raises(ValueError, match="not allowed"):
        SandboxCommandRequest(
            request_id="sandbox-request-curl",
            profile=profile,
            argv=("python", "-c", "import os; os.system('curl https://example.test')"),
        )


def test_wave6_network_policy_defaults_to_deny_all_without_allowlist() -> None:
    policy = SandboxNetworkPolicy()

    assert policy.mode is SandboxNetworkMode.DENY_ALL
    assert policy.blocks_all_egress is True
    assert policy.to_dict() == {"mode": "deny_all", "allowlist": []}


def test_wave6_network_policy_rejects_allowlist_on_deny_all() -> None:
    with pytest.raises(ValueError, match="deny_all"):
        SandboxNetworkPolicy(
            mode=SandboxNetworkMode.DENY_ALL,
            allowlist=(SandboxNetworkAllowRule(host="example.test", port=443),),
        )


def test_wave6_network_policy_requires_allowlist_for_allowlist_mode() -> None:
    with pytest.raises(ValueError, match="requires allowlist"):
        SandboxNetworkPolicy(mode=SandboxNetworkMode.ALLOWLIST)


def test_wave6_network_policy_accepts_explicit_allowlist_rule() -> None:
    policy = SandboxNetworkPolicy(
        mode=SandboxNetworkMode.ALLOWLIST,
        allowlist=(
            SandboxNetworkAllowRule(
                host="packages.example.test",
                port=443,
                protocol="https",
                reason="approved offline dependency mirror",
            ),
        ),
    )

    assert policy.blocks_all_egress is False
    assert policy.to_dict()["allowlist"][0]["host"] == "packages.example.test"


def test_wave6_local_audit_profile_cannot_declare_egress() -> None:
    with pytest.raises(ValueError, match="local_audit"):
        SandboxProfile(
            profile_id="wave6.bad-local-egress",
            backend=SandboxBackendKind.LOCAL_AUDIT,
            filesystem=_filesystem_policy(),
            resources=_resource_limits(),
            network=SandboxNetworkPolicy(
                mode=SandboxNetworkMode.ALLOWLIST,
                allowlist=(SandboxNetworkAllowRule(host="example.test", port=443),),
            ),
        )


def test_wave6_filesystem_policy_requires_rw_mounts_to_be_declared_writable() -> None:
    with pytest.raises(ValueError, match="read-write mount targets"):
        SandboxFilesystemPolicy(
            mounts=(
                SandboxMount(
                    source="out",
                    target="/workspace/out",
                    access=SandboxMountAccess.READ_WRITE,
                ),
            ),
            writable_paths=("/workspace/tmp",),
        )


def test_wave6_filesystem_policy_rejects_path_escape() -> None:
    with pytest.raises(ValueError, match="must not contain"):
        SandboxMount(
            source="../outside",
            target="/workspace/src",
            access=SandboxMountAccess.READ_ONLY,
        )


def test_wave6_command_result_requires_policy_issue_when_blocked() -> None:
    with pytest.raises(ValueError, match="policy_issue"):
        SandboxCommandResult(
            request_id="sandbox-result-1",
            status=SandboxExecutionStatus.POLICY_BLOCKED,
            exit_code=None,
            duration_ms=10,
        )


def test_wave6_command_result_reports_passed_only_for_zero_exit_success() -> None:
    result = SandboxCommandResult(
        request_id="sandbox-result-2",
        status=SandboxExecutionStatus.SUCCEEDED,
        exit_code=0,
        duration_ms=25,
        stdout_sha256=_SHA256,
        stderr_sha256="b" * 64,
        artifact_manifest_sha256="c" * 64,
    )

    assert result.passed is True
    assert result.to_dict()["passed"] is True
    assert result.to_dict()["artifact_manifest_sha256"] == "c" * 64


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


def _resource_limits() -> SandboxResourceLimits:
    return SandboxResourceLimits(
        timeout_seconds=60,
        max_memory_mb=256,
        max_processes=16,
        max_output_bytes=65_536,
        max_artifact_bytes=1_048_576,
    )
