from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ix_blackfox.live_gateway.evidence import (
    EvidencePolicy,
    EvidenceStore,
    issue_signed_evidence,
)
from ix_blackfox.live_gateway.models import AuthoritySubject


def _subject() -> AuthoritySubject:
    return AuthoritySubject(
        agent_id="coding-agent-07",
        tool_name="filesystem.write_file",
        capability="file_write",
        repository_id="ix-blackfox",
        revision="abc123",
        path="docs/readme.md",
        arguments_digest="a" * 64,
        authority_context_digest="c" * 64,
        protocol="mcp/2026-07-28",
    )


def _policy() -> EvidencePolicy:
    return EvidencePolicy(
        policy_id="protected-write",
        required_kinds=("test_result",),
        human_approval_kind="human_approval",
        target_bound_kinds=("human_approval",),
        single_use_kinds=("human_approval",),
        accepted_statuses=("passed", "approved"),
        allowed_issuers=("ci", "human"),
        human_approval_issuers=("human",),
        max_age_seconds=3600,
    )


def test_valid_signed_revision_and_target_bound_evidence_passes(tmp_path: Path) -> None:
    subject = _subject()
    store = EvidenceStore(
        tmp_path,
        {("ci", "ci-key"): b"ci-secret", ("human", "human-key"): b"human-secret"},
    )
    ci = issue_signed_evidence(
        evidence_id="ci-tests-1",
        kind="test_result",
        issuer="ci",
        key_id="ci-key",
        secret=b"ci-secret",
        status="passed",
        repository_id="ix-blackfox",
        revision="abc123",
    )
    approval = issue_signed_evidence(
        evidence_id="human-approval-1",
        kind="human_approval",
        issuer="human",
        key_id="human-key",
        secret=b"human-secret",
        status="approved",
        repository_id="ix-blackfox",
        revision="abc123",
        target_digest=subject.digest,
        payload={
            "decision": "approve",
            "reviewer_kind": "human",
            "reviewer_id": "maintainer.one",
        },
    )
    store.write(ci)
    store.write(approval)

    result = store.verify_many(
        (ci.evidence_id, approval.evidence_id),
        subject=subject,
        policy=_policy(),
    )

    assert result.passed is True
    assert result.human_approval_satisfied is True
    assert result.missing_kinds == ()


def test_tampered_evidence_fails_digest_and_signature_verification(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path, {("ci", "ci-key"): b"ci-secret"})
    artifact = issue_signed_evidence(
        evidence_id="ci-tests-tamper",
        kind="test_result",
        issuer="ci",
        key_id="ci-key",
        secret=b"ci-secret",
        status="passed",
        repository_id="ix-blackfox",
        revision="abc123",
    )
    path = store.write(artifact)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["status"] = "approved"
    path.write_text(json.dumps(payload), encoding="utf-8")

    verification, _ = store.verify_one(
        artifact.evidence_id,
        subject=_subject(),
        policy=_policy(),
        now=datetime.now(tz=UTC),
    )

    assert verification.passed is False
    codes = {issue.code for issue in verification.issues}
    assert "evidence_digest_mismatch" in codes


def test_target_bound_human_approval_cannot_be_replayed_to_different_action(tmp_path: Path) -> None:
    subject = _subject()
    other = AuthoritySubject(
        agent_id=subject.agent_id,
        tool_name=subject.tool_name,
        capability=subject.capability,
        repository_id=subject.repository_id,
        revision=subject.revision,
        path="docs/other.md",
        arguments_digest="b" * 64,
        authority_context_digest=subject.authority_context_digest,
        protocol=subject.protocol,
    )
    store = EvidenceStore(tmp_path, {("human", "human-key"): b"human-secret"})
    approval = issue_signed_evidence(
        evidence_id="human-approval-replay",
        kind="human_approval",
        issuer="human",
        key_id="human-key",
        secret=b"human-secret",
        status="approved",
        repository_id="ix-blackfox",
        revision="abc123",
        target_digest=subject.digest,
        payload={
            "decision": "approve",
            "reviewer_kind": "human",
            "reviewer_id": "maintainer.one",
        },
    )
    store.write(approval)
    verification, _ = store.verify_one(
        approval.evidence_id,
        subject=other,
        policy=_policy(),
        now=datetime.now(tz=UTC),
    )
    assert verification.passed is False
    assert "evidence_target_mismatch" in {issue.code for issue in verification.issues}


def test_stale_evidence_fails_closed(tmp_path: Path) -> None:
    old = (datetime.now(tz=UTC) - timedelta(hours=2)).isoformat()
    store = EvidenceStore(tmp_path, {("ci", "ci-key"): b"ci-secret"})
    artifact = issue_signed_evidence(
        evidence_id="ci-tests-stale",
        kind="test_result",
        issuer="ci",
        key_id="ci-key",
        secret=b"ci-secret",
        status="passed",
        repository_id="ix-blackfox",
        revision="abc123",
        produced_at=old,
    )
    store.write(artifact)
    verification, _ = store.verify_one(
        artifact.evidence_id,
        subject=_subject(),
        policy=EvidencePolicy(
            policy_id="short-lived",
            accepted_statuses=("passed",),
            max_age_seconds=60,
        ),
        now=datetime.now(tz=UTC),
    )
    assert verification.passed is False
    assert "evidence_stale" in {issue.code for issue in verification.issues}


def test_ci_issuer_cannot_masquerade_as_human_approval_issuer(tmp_path: Path) -> None:
    subject = _subject()
    store = EvidenceStore(
        tmp_path,
        {("ci", "ci-key"): b"ci-secret", ("human", "human-key"): b"human-secret"},
        trusted_issuer_kinds={
            ("ci", "ci-key"): ("test_result",),
            ("human", "human-key"): ("human_approval",),
        },
    )
    forged_role = issue_signed_evidence(
        evidence_id="ci-fake-human-approval",
        kind="human_approval",
        issuer="ci",
        key_id="ci-key",
        secret=b"ci-secret",
        status="approved",
        repository_id="ix-blackfox",
        revision="abc123",
        target_digest=subject.digest,
        payload={
            "decision": "approve",
            "reviewer_kind": "human",
            "reviewer_id": "claimed-human",
        },
    )
    store.write(forged_role)
    verification, _ = store.verify_one(
        forged_role.evidence_id,
        subject=subject,
        policy=_policy(),
        now=datetime.now(tz=UTC),
    )
    assert verification.passed is False
    codes = {issue.code for issue in verification.issues}
    assert "evidence_kind_not_allowed_for_issuer" in codes
    assert "human_approval_issuer_not_allowed" in codes


def test_human_issuer_cannot_masquerade_as_ci_test_issuer(tmp_path: Path) -> None:
    store = EvidenceStore(
        tmp_path,
        {("ci", "ci-key"): b"ci-secret", ("human", "human-key"): b"human-secret"},
        trusted_issuer_kinds={
            ("ci", "ci-key"): ("test_result",),
            ("human", "human-key"): ("human_approval",),
        },
    )
    forged_test = issue_signed_evidence(
        evidence_id="human-fake-ci-test",
        kind="test_result",
        issuer="human",
        key_id="human-key",
        secret=b"human-secret",
        status="passed",
        repository_id="ix-blackfox",
        revision="abc123",
    )
    store.write(forged_test)
    verification, _ = store.verify_one(
        forged_test.evidence_id,
        subject=_subject(),
        policy=_policy(),
        now=datetime.now(tz=UTC),
    )
    assert verification.passed is False
    assert "evidence_kind_not_allowed_for_issuer" in {
        issue.code for issue in verification.issues
    }


def test_oversized_evidence_artifact_fails_closed(tmp_path: Path) -> None:
    store = EvidenceStore(
        tmp_path,
        {("ci", "ci-key"): b"ci-secret"},
        max_evidence_bytes=128,
    )
    path = tmp_path / "ci-tests-large.json"
    path.write_text("{" + '"padding":"' + ("x" * 512) + '"}', encoding="utf-8")

    verification, artifact = store.verify_one(
        "ci-tests-large",
        subject=_subject(),
        policy=_policy(),
        now=datetime.now(tz=UTC),
    )

    assert artifact is None
    assert verification.passed is False
    assert "evidence_load_failed" in {issue.code for issue in verification.issues}
    assert "size limit" in verification.issues[0].summary
