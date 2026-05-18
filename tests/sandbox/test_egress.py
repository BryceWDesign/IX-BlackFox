from __future__ import annotations

import pytest

from ix_blackfox.sandbox import (
    SandboxBackendKind,
    SandboxCommandRequest,
    SandboxEgressDecisionStatus,
    SandboxEgressGuard,
    SandboxEgressRequest,
    SandboxFilesystemPolicy,
    SandboxMount,
    SandboxMountAccess,
    SandboxNetworkAllowRule,
    SandboxNetworkMode,
    SandboxNetworkPolicy,
    SandboxProfile,
    SandboxResourceLimits,
    network_policy_digest,
)


def test_wave6_egress_guard_denies_all_by_default() -> None:
    profile = _profile(network=SandboxNetworkPolicy())
    request = SandboxEgressRequest(
        request_id="egress-pypi",
        host="pypi.org",
        port=443,
        protocol="https",
        purpose="attempted package fetch",
    )

    decision = SandboxEgressGuard().evaluate(profile, request)

    assert decision.allowed is False
    assert decision.status is SandboxEgressDecisionStatus.DENIED
    assert decision.network_mode is SandboxNetworkMode.DENY_ALL
    assert decision.matched_rule is None
    assert decision.network_policy_digest == network_policy_digest(profile.network)
    assert len(decision.digest) == 64
    assert decision.to_dict()["allowed"] is False


def test_wave6_egress_guard_allows_exact_allowlist_match() -> None:
    profile = _profile(
        network=SandboxNetworkPolicy(
            mode=SandboxNetworkMode.ALLOWLIST,
            allowlist=(
                SandboxNetworkAllowRule(
                    host="packages.example.test",
                    port=443,
                    protocol="https",
                    reason="approved test dependency mirror",
                ),
            ),
        )
    )
    request = SandboxEgressRequest(
        request_id="egress-mirror",
        host="packages.example.test",
        port=443,
        protocol="https",
        purpose="approved mirror access",
    )

    decision = SandboxEgressGuard().evaluate(profile, request)

    assert decision.allowed is True
    assert decision.status is SandboxEgressDecisionStatus.ALLOWED
    assert decision.matched_rule is not None
    assert decision.matched_rule.host == "packages.example.test"


def test_wave6_egress_guard_denies_allowlist_port_mismatch() -> None:
    profile = _profile(
        network=SandboxNetworkPolicy(
            mode=SandboxNetworkMode.ALLOWLIST,
            allowlist=(SandboxNetworkAllowRule(host="packages.example.test", port=443),),
        )
    )
    request = SandboxEgressRequest(
        request_id="egress-wrong-port",
        host="packages.example.test",
        port=80,
        protocol="tcp",
        purpose="wrong port should not match",
    )

    decision = SandboxEgressGuard().evaluate(profile, request)

    assert decision.allowed is False
    assert decision.status is SandboxEgressDecisionStatus.DENIED
    assert decision.matched_rule is None
    assert "not present" in decision.reason


def test_wave6_egress_guard_marks_proxy_logged_match_as_proxy_only() -> None:
    profile = _profile(
        network=SandboxNetworkPolicy(
            mode=SandboxNetworkMode.PROXY_LOGGED,
            allowlist=(
                SandboxNetworkAllowRule(
                    host="audit-proxy.example.test",
                    port=443,
                    protocol="https",
                    reason="approved audited proxy path",
                ),
            ),
        )
    )
    request = SandboxEgressRequest(
        request_id="egress-proxy",
        host="audit-proxy.example.test",
        port=443,
        protocol="https",
        purpose="audited proxy-only egress",
    )

    decision = SandboxEgressGuard().evaluate(profile, request)

    assert decision.allowed is True
    assert decision.status is SandboxEgressDecisionStatus.ALLOWED_VIA_PROXY
    assert decision.matched_rule is not None
    assert "auditable proxy" in decision.reason


def test_wave6_egress_guard_denies_direct_egress_in_offline_cache_mode() -> None:
    profile = _profile(
        network=SandboxNetworkPolicy(mode=SandboxNetworkMode.OFFLINE_PACKAGE_CACHE)
    )
    request = SandboxEgressRequest(
        request_id="egress-offline-cache",
        host="pypi.org",
        port=443,
        protocol="https",
        purpose="direct package fetch should be denied",
    )

    decision = SandboxEgressGuard().evaluate(profile, request)

    assert decision.allowed is False
    assert decision.status is SandboxEgressDecisionStatus.OFFLINE_CACHE_ONLY
    assert "denies direct network egress" in decision.reason


def test_wave6_egress_guard_audit_bundle_counts_allowed_and_denied() -> None:
    profile = _profile(
        network=SandboxNetworkPolicy(
            mode=SandboxNetworkMode.ALLOWLIST,
            allowlist=(SandboxNetworkAllowRule(host="packages.example.test", port=443),),
        )
    )

    bundle = SandboxEgressGuard().audit_bundle(
        profile,
        (
            SandboxEgressRequest(
                request_id="egress-allowed",
                host="packages.example.test",
                port=443,
                purpose="allowed dependency mirror",
            ),
            SandboxEgressRequest(
                request_id="egress-denied",
                host="evil.example.test",
                port=443,
                purpose="unapproved host",
            ),
        ),
        bundle_id="egress-audit-1",
    )

    assert bundle.allowed_count == 1
    assert bundle.denied_count == 1
    assert len(bundle.digest) == 64
    assert bundle.to_dict()["decisions"][0]["network_policy_digest"] == bundle.network_policy_digest


def test_wave6_egress_guard_can_evaluate_command_request_profile() -> None:
    profile = _profile(network=SandboxNetworkPolicy())
    command_request = SandboxCommandRequest(
        request_id="sandbox-command-1",
        profile=profile,
        argv=("python", "-c", "print('no network')"),
    )
    egress_request = SandboxEgressRequest(
        request_id="egress-from-command",
        host="example.test",
        port=443,
        purpose="command-level egress probe",
    )

    decision = SandboxEgressGuard().evaluate_command_request(command_request, egress_request)

    assert decision.profile_digest == command_request.profile.digest
    assert decision.allowed is False
    assert decision.status is SandboxEgressDecisionStatus.DENIED


def test_wave6_egress_request_rejects_url_as_host() -> None:
    with pytest.raises(ValueError, match="hostname"):
        SandboxEgressRequest(
            request_id="bad-host",
            host="https://example.test/path",
            port=443,
        )


def test_wave6_network_policy_digest_is_stable() -> None:
    policy = SandboxNetworkPolicy(
        mode=SandboxNetworkMode.ALLOWLIST,
        allowlist=(
            SandboxNetworkAllowRule(host="packages.example.test", port=443),
        ),
    )

    assert network_policy_digest(policy) == network_policy_digest(policy)
    assert len(network_policy_digest(policy)) == 64


def _profile(*, network: SandboxNetworkPolicy) -> SandboxProfile:
    return SandboxProfile(
        profile_id="wave6.egress.test",
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
            timeout_seconds=30,
            max_memory_mb=256,
            max_processes=16,
            max_output_bytes=65_536,
            max_artifact_bytes=1_048_576,
        ),
        network=network,
        allowed_commands=("python",),
        metadata={"claim": "egress-policy-decision-tests"},
    )
