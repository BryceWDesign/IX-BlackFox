from __future__ import annotations

import hashlib

import pytest

from ix_blackfox.operating import (
    EvidenceFreshnessState,
    EvidenceIntegrityState,
    EvidenceTrustEvaluator,
    EvidenceTrustLevel,
    EvidenceTrustRecord,
    EvidenceTrustTransition,
    OperatingArtifactKind,
    OperatingArtifactRef,
    OperatingDisposition,
    OperatingSourceWave,
)


def test_evidence_trust_evaluator_is_ready_for_verified_review_bound_evidence() -> None:
    record = _record("wave9-governance-report")
    evaluator = EvidenceTrustEvaluator(
        evaluator_id=" Wave 10 Trust ",
        records=(record,),
        required_artifact_ids=("Wave9 Governance Report",),
        transitions=(
            EvidenceTrustTransition(
                transition_id="promote-to-trusted",
                artifact_id="wave9-governance-report",
                from_level=EvidenceTrustLevel.WATCH,
                to_level=EvidenceTrustLevel.TRUSTED,
                rationale="Digest, schema, producer, freshness, and human review were validated.",
                authorized_by="security-reviewer",
                evidence_artifact_ids=("wave9-governance-report",),
                human_review_ids=("human-review",),
            ),
        ),
    )
    same_evaluator = EvidenceTrustEvaluator(
        evaluator_id="wave-10-trust",
        records=(record,),
        required_artifact_ids=("wave9-governance-report",),
        transitions=(
            EvidenceTrustTransition(
                transition_id="promote-to-trusted",
                artifact_id="wave9-governance-report",
                from_level=EvidenceTrustLevel.WATCH,
                to_level=EvidenceTrustLevel.TRUSTED,
                rationale="Digest, schema, producer, freshness, and human review were validated.",
                authorized_by="security-reviewer",
                evidence_artifact_ids=("wave9-governance-report",),
                human_review_ids=("human-review",),
            ),
        ),
    )

    assert evaluator.evaluator_id == "wave-10-trust"
    assert evaluator.artifact_ids == ("wave9-governance-report",)
    assert evaluator.trusted_artifact_ids == ("wave9-governance-report",)
    assert evaluator.blocking_artifact_ids == ()
    assert evaluator.missing_required_artifact_ids == ()
    assert evaluator.trusted_transition_gap_ids == ()
    assert evaluator.average_trust_score == 100.0
    assert evaluator.findings == ()
    assert evaluator.disposition is OperatingDisposition.READY
    assert evaluator.to_envelope().disposition is OperatingDisposition.READY
    assert evaluator.to_dict()["digest"] == same_evaluator.to_dict()["digest"]


def test_evidence_trust_record_blocks_bad_required_evidence() -> None:
    record = _record(
        "bad-report",
        freshness_state=EvidenceFreshnessState.STALE,
        integrity_state=EvidenceIntegrityState.DIGEST_MISMATCH,
        schema_valid=False,
        producer_trusted=False,
        human_review_bound=False,
    )

    assert record.blocking_gap is True
    assert record.trust_level is EvidenceTrustLevel.UNTRUSTED
    assert record.trust_score == 0
    assert {finding.code for finding in record.findings} == {
        "operating.trust.freshness-blocking-gap",
        "operating.trust.integrity-blocking-gap",
        "operating.trust.invalid-schema",
        "operating.trust.missing-human-review-binding",
        "operating.trust.untrusted-producer",
    }


def test_evidence_trust_record_warns_for_aging_or_unverified_nonblocking_evidence() -> None:
    aging = _record(
        "aging-report",
        freshness_state=EvidenceFreshnessState.AGING,
        integrity_state=EvidenceIntegrityState.VERIFIED,
    )
    unverified_optional = _record(
        "optional-report",
        integrity_state=EvidenceIntegrityState.UNVERIFIED,
        required=False,
    )

    assert aging.warning_gap is True
    assert aging.blocking_gap is False
    assert aging.trust_level is EvidenceTrustLevel.WATCH
    assert {finding.code for finding in aging.findings} == {
        "operating.trust.freshness-warning",
    }
    assert unverified_optional.warning_gap is True
    assert unverified_optional.blocking_gap is False
    assert {finding.code for finding in unverified_optional.findings} == {
        "operating.trust.integrity-warning",
    }


def test_evidence_trust_evaluator_blocks_missing_required_artifact_and_transition_gap() -> None:
    record = _record("wave9-governance-report")
    evaluator = EvidenceTrustEvaluator(
        evaluator_id="blocked-trust",
        records=(record,),
        required_artifact_ids=("wave9-governance-report", "replay-manifest"),
        transitions=(
            EvidenceTrustTransition(
                transition_id="bad-promotion",
                artifact_id="wave9-governance-report",
                from_level=EvidenceTrustLevel.DEGRADED,
                to_level=EvidenceTrustLevel.TRUSTED,
                rationale="This promotion lacks required human review binding.",
                authorized_by="security-reviewer",
                evidence_artifact_ids=("wave9-governance-report",),
                human_review_ids=(),
            ),
        ),
    )

    finding_codes = {finding.code for finding in evaluator.findings}
    assert finding_codes == {
        "operating.trust.missing-required-artifact",
        "operating.trust.trusted-transition-not-review-bound",
    }
    assert evaluator.missing_required_artifact_ids == ("replay-manifest",)
    assert evaluator.trusted_transition_gap_ids == ("bad-promotion",)
    assert evaluator.disposition is OperatingDisposition.BLOCKED


def test_evidence_trust_evaluator_blocks_untrusted_records() -> None:
    good = _record("good-report")
    bad = _record(
        "bad-report",
        freshness_state=EvidenceFreshnessState.EXPIRED,
        integrity_state=EvidenceIntegrityState.MISSING_ARTIFACT,
    )
    evaluator = EvidenceTrustEvaluator(
        evaluator_id="untrusted-records",
        records=(bad, good),
        required_artifact_ids=("good-report", "bad-report"),
    )

    assert evaluator.trusted_artifact_ids == ("good-report",)
    assert evaluator.untrusted_artifact_ids == ("bad-report",)
    assert evaluator.blocking_artifact_ids == ("bad-report",)
    assert evaluator.disposition is OperatingDisposition.BLOCKED
    assert "operating.trust.integrity-blocking-gap" in {
        finding.code for finding in evaluator.findings
    }


def test_evidence_trust_rejects_duplicate_records_and_unknown_transition_artifact() -> None:
    record = _record("duplicate")

    with pytest.raises(ValueError, match="artifact_id values must be unique"):
        EvidenceTrustEvaluator(
            evaluator_id="duplicate-records",
            records=(record, record),
            required_artifact_ids=("duplicate",),
        )

    with pytest.raises(ValueError, match="unknown artifact"):
        EvidenceTrustEvaluator(
            evaluator_id="unknown-transition",
            records=(record,),
            required_artifact_ids=("duplicate",),
            transitions=(
                EvidenceTrustTransition(
                    transition_id="bad-transition",
                    artifact_id="missing",
                    from_level=EvidenceTrustLevel.WATCH,
                    to_level=EvidenceTrustLevel.TRUSTED,
                    rationale="Unknown transition artifact should fail.",
                    authorized_by="security-reviewer",
                    evidence_artifact_ids=("duplicate",),
                    human_review_ids=("human-review",),
                ),
            ),
        )


def test_trust_transition_requires_actual_level_change() -> None:
    with pytest.raises(ValueError, match="must change trust level"):
        EvidenceTrustTransition(
            transition_id="same-level",
            artifact_id="artifact",
            from_level=EvidenceTrustLevel.TRUSTED,
            to_level=EvidenceTrustLevel.TRUSTED,
            rationale="Same-level transitions are not useful trust evidence.",
            authorized_by="security-reviewer",
        )


def _record(
    artifact_id: str,
    *,
    freshness_state: EvidenceFreshnessState = EvidenceFreshnessState.CURRENT,
    integrity_state: EvidenceIntegrityState = EvidenceIntegrityState.VERIFIED,
    schema_valid: bool = True,
    producer_trusted: bool = True,
    human_review_bound: bool = True,
    required: bool = True,
) -> EvidenceTrustRecord:
    return EvidenceTrustRecord(
        artifact=_artifact(artifact_id),
        freshness_state=freshness_state,
        integrity_state=integrity_state,
        schema_valid=schema_valid,
        producer_trusted=producer_trusted,
        human_review_bound=human_review_bound,
        required=required,
    )


def _artifact(artifact_id: str) -> OperatingArtifactRef:
    normalized = artifact_id.strip().lower().replace(" ", "-")
    return OperatingArtifactRef(
        artifact_id=artifact_id,
        kind=OperatingArtifactKind.EVIDENCE_MANIFEST,
        source_wave=OperatingSourceWave.WAVE10,
        path=f".blackfox-artifacts/wave10/{normalized}.json",
        sha256=hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        producer="IX-BlackFox Wave 10 trust tests",
    )
