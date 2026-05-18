from __future__ import annotations

from ix_blackfox.workflow import (
    ArtifactAttestationKind,
    EvidenceArtifactKind,
    PullRequestEvidencePackNormalizer,
)


def test_wave5_pr_evidence_normalizer_loads_artifact_attestations() -> None:
    artifact = PullRequestEvidencePackNormalizer().artifact_from_mapping(
        {
            "artifact_id": "run-bundle",
            "kind": "run_bundle",
            "uri": "artifacts/run-bundle.json",
            "produced_by": "blackfox-runtime",
            "sha256": "a" * 64,
            "size_bytes": 512,
            "head_sha": "abc1234",
            "attestations": [
                {
                    "attestation_id": "attestation-run-bundle",
                    "kind": "local_manifest",
                    "uri": "artifacts/attestations/run-bundle.json",
                    "produced_by": "blackfox-workflow",
                    "predicate_type": "https://ix.blackfox.local/predicate/pr-evidence/v1",
                    "sha256": "b" * 64,
                    "size_bytes": 256,
                    "head_sha": "abc1234",
                    "subject_sha256": "a" * 64,
                    "verified": False,
                    "metadata": {"future_consumer": "wave6-sandbox-evidence"},
                }
            ],
        }
    )

    assert artifact.kind is EvidenceArtifactKind.RUN_BUNDLE
    assert len(artifact.attestations) == 1
    assert artifact.attestations[0].kind is ArtifactAttestationKind.LOCAL_MANIFEST
    assert artifact.attestations[0].subject_sha256 == artifact.sha256
    assert artifact.to_dict()["attestations"][0]["verified"] is False
