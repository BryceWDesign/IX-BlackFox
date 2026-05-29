from __future__ import annotations

import pytest

from ix_blackfox.audit import (
    DEFAULT_WAVE9_POLICY_PACK_ID,
    DEFAULT_WAVE9_POLICY_PACK_TITLE,
    DEFAULT_WAVE9_POLICY_PACK_VERSION,
    AuditControlRequirement,
    AuditControlSeverity,
    AuditPolicyPack,
    default_wave9_policy_pack,
)


def test_default_wave9_policy_pack_has_expected_identity_and_control_set() -> None:
    pack = default_wave9_policy_pack()

    assert pack.pack_id == DEFAULT_WAVE9_POLICY_PACK_ID
    assert pack.version == DEFAULT_WAVE9_POLICY_PACK_VERSION
    assert pack.title == DEFAULT_WAVE9_POLICY_PACK_TITLE
    assert pack.control_count == 15
    assert pack.control_ids == tuple(f"BF-W9-{index:03d}" for index in range(1, 16))
    assert pack.digest == default_wave9_policy_pack().digest


def test_default_wave9_policy_pack_is_deterministic_and_digest_bound() -> None:
    pack = default_wave9_policy_pack()
    payload_without_digest = pack.to_dict(include_digest=False)
    payload_with_digest = pack.to_dict()

    assert "digest" not in payload_without_digest
    assert payload_with_digest["digest"] == pack.digest
    assert payload_with_digest["control_count"] == len(payload_with_digest["controls"])


def test_default_wave9_policy_pack_preserves_required_non_claims() -> None:
    pack = default_wave9_policy_pack()
    text = " ".join(pack.non_claims.items).lower()

    for phrase in (
        "production readiness",
        "ato",
        "cato",
        "procurement",
        "dod",
        "autonomous",
        "model confidence",
    ):
        assert phrase in text


def test_default_wave9_policy_pack_has_no_false_compliance_claims() -> None:
    pack = default_wave9_policy_pack()

    for control in pack.controls:
        for mapping in control.standards_mappings:
            assert mapping.claim == "alignment_reference_only"


def test_control_lookup_returns_specific_control() -> None:
    pack = default_wave9_policy_pack()

    control = pack.control_by_id("BF-W9-011")

    assert control.control_id == "BF-W9-011"
    assert "Human signoff" in control.title
    assert control.severity is AuditControlSeverity.BLOCKING


def test_control_lookup_rejects_unknown_control() -> None:
    pack = default_wave9_policy_pack()

    with pytest.raises(KeyError):
        pack.control_by_id("BF-W9-999")


def test_policy_pack_requires_unique_controls() -> None:
    control = AuditControlRequirement(
        control_id="BF-W9-100",
        title="Unique control",
        objective="Validate unique control handling.",
        severity=AuditControlSeverity.BLOCKING,
    )

    with pytest.raises(ValueError):
        AuditPolicyPack(
            pack_id="ix-blackfox.wave9.duplicate-test",
            version="1.0.0",
            title="Duplicate control test",
            description="Policy pack used to test duplicate controls.",
            controls=(control, control),
        )


def test_policy_pack_requires_at_least_one_control() -> None:
    with pytest.raises(ValueError):
        AuditPolicyPack(
            pack_id="ix-blackfox.wave9.empty-test",
            version="1.0.0",
            title="Empty control test",
            description="Policy pack used to test empty controls.",
            controls=(),
        )
