from __future__ import annotations

import json
from pathlib import Path

import pytest

from ix_blackfox.assurance.evidence import (
    CollectedEvidence,
    EvidenceInputSpec,
    collect_evidence,
    load_evidence_specs,
    normalize_evidence_specs,
    resolve_json_pointer,
)
from ix_blackfox.assurance.models import (
    AssuranceEvidenceArtifact,
    AssuranceEvidenceKind,
    AssuranceEvidenceSource,
    EvidenceVerificationState,
)
from tests.assurance.helpers import REVISION


def test_collect_evidence_hashes_bytes_and_verifies_revision(tmp_path: Path) -> None:
    root, spec = _json_fixture(tmp_path)
    collected = collect_evidence(root, (spec,), expected_revision=REVISION)
    assert len(collected) == 1
    artifact = collected[0].artifact
    assert artifact.integrity_verified
    assert artifact.metadata["revision_binding_verified"] is True
    assert artifact.metadata["revision_json_pointer"] == "/head_sha"
    assert artifact.size_bytes == len(collected[0].body)


def test_collect_evidence_rejects_stale_revision(tmp_path: Path) -> None:
    root, spec = _json_fixture(tmp_path, revision="stale")
    with pytest.raises(ValueError, match="not"):
        collect_evidence(root, (spec,), expected_revision=REVISION)


def test_collect_evidence_validates_json_even_without_pointer(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / "artifacts").mkdir()
    (root / "artifacts/result.json").write_text("{bad", encoding="utf-8")
    spec = _spec(revision_json_pointer="")
    with pytest.raises(ValueError, match="valid UTF-8 JSON"):
        collect_evidence(root, (spec,), expected_revision=REVISION)


def test_json_pointer_requires_json_media_type() -> None:
    with pytest.raises(ValueError, match="application/json"):
        _spec(media_type="text/plain")


@pytest.mark.parametrize(
    "source_path",
    [
        ".git/config",
        ".venv/state.json",
        "node_modules/log.json",
        "artifacts/.env",
        "artifacts/id_rsa",
        "artifacts/signing.key",
        "artifacts/certificate.p12",
    ],
)
def test_collect_evidence_rejects_sensitive_paths(
    tmp_path: Path,
    source_path: str,
) -> None:
    root = _root(tmp_path)
    path = root / source_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("evidence", encoding="utf-8")
    spec = _spec(source_path=source_path, revision_json_pointer="", media_type="text/plain")
    with pytest.raises(ValueError, match="denied|credential|key"):
        collect_evidence(root, (spec,), expected_revision=REVISION)


@pytest.mark.parametrize(
    "marker",
    [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ],
)
def test_collect_evidence_rejects_private_key_content(
    tmp_path: Path,
    marker: str,
) -> None:
    root = _root(tmp_path)
    (root / "artifacts").mkdir()
    (root / "artifacts/result.json").write_text(marker, encoding="utf-8")
    spec = _spec(revision_json_pointer="", media_type="text/plain")
    with pytest.raises(ValueError, match="private-key"):
        collect_evidence(root, (spec,), expected_revision=REVISION)


def test_collect_evidence_rejects_symlink_file(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / "artifacts").mkdir()
    target = root / "artifacts/target.json"
    target.write_text(json.dumps({"head_sha": REVISION}), encoding="utf-8")
    (root / "artifacts/result.json").symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        collect_evidence(root, (_spec(),), expected_revision=REVISION)


def test_collect_evidence_rejects_symlink_parent(tmp_path: Path) -> None:
    root = _root(tmp_path)
    real = root / "real"
    real.mkdir()
    (real / "result.json").write_text(
        json.dumps({"head_sha": REVISION}), encoding="utf-8"
    )
    (root / "artifacts").symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        collect_evidence(root, (_spec(),), expected_revision=REVISION)


def test_collect_evidence_rejects_missing_and_directory_sources(tmp_path: Path) -> None:
    root = _root(tmp_path)
    with pytest.raises(ValueError, match="does not exist"):
        collect_evidence(root, (_spec(),), expected_revision=REVISION)
    (root / "artifacts/result.json").mkdir(parents=True)
    with pytest.raises(ValueError, match="regular file"):
        collect_evidence(root, (_spec(),), expected_revision=REVISION)


def test_collect_evidence_enforces_per_file_and_total_limits(tmp_path: Path) -> None:
    root, spec = _json_fixture(tmp_path)
    with pytest.raises(ValueError, match="per-file"):
        collect_evidence(
            root,
            (spec,),
            expected_revision=REVISION,
            max_evidence_bytes=1,
        )
    with pytest.raises(ValueError, match="total"):
        collect_evidence(
            root,
            (spec,),
            expected_revision=REVISION,
            max_total_evidence_bytes=1,
        )


def test_normalize_specs_rejects_duplicate_ids_and_paths() -> None:
    spec = _spec()
    with pytest.raises(ValueError, match="artifact_id"):
        normalize_evidence_specs((spec, spec))
    other = _spec(artifact_id="other")
    with pytest.raises(ValueError, match="package_path"):
        normalize_evidence_specs((spec, other))


def test_load_evidence_specs_accepts_wrapped_list(tmp_path: Path) -> None:
    path = tmp_path / "spec.json"
    path.write_text(json.dumps({"evidence": [_spec().to_dict()]}), encoding="utf-8")
    specs = load_evidence_specs(path)
    assert specs == (_spec(),)


@pytest.mark.parametrize("field", ["schema_version", "revision_json_pointer"])
def test_load_evidence_specs_rejects_non_string_optional_fields(
    tmp_path: Path,
    field: str,
) -> None:
    path = tmp_path / "spec.json"
    payload = _spec().to_dict()
    payload[field] = {"not": "a string"}
    path.write_text(json.dumps({"evidence": [payload]}), encoding="utf-8")
    with pytest.raises(ValueError, match="must be a string"):
        load_evidence_specs(path)


@pytest.mark.parametrize(
    ("pointer", "expected"),
    [
        ("", {"a": {"b": [1, 2]}, "a/b": {"~key": "value"}}),
        ("/a/b/1", 2),
        ("/a~1b/~0key", "value"),
    ],
)
def test_resolve_json_pointer(pointer: str, expected: object) -> None:
    payload = {"a": {"b": [1, 2]}, "a/b": {"~key": "value"}}
    assert resolve_json_pointer(payload, pointer) == expected


@pytest.mark.parametrize("pointer", ["a", "/bad~2escape", "/bad~"])
def test_resolve_json_pointer_rejects_invalid_pointer(pointer: str) -> None:
    with pytest.raises(ValueError):
        resolve_json_pointer({}, pointer)


def test_collected_evidence_rejects_body_digest_mismatch() -> None:
    artifact = AssuranceEvidenceArtifact(
        artifact_id="artifact",
        source_wave=AssuranceEvidenceSource.WAVE12,
        evidence_kind=AssuranceEvidenceKind.TEST_RESULT,
        path="evidence/result.txt",
        sha256="a" * 64,
        size_bytes=4,
        media_type="text/plain",
        producer="test",
        verification_state=EvidenceVerificationState.INTEGRITY_VERIFIED,
    )
    with pytest.raises(ValueError, match="sha256"):
        CollectedEvidence(artifact=artifact, body=b"test")


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".blackfox-workspace").write_text("\n", encoding="utf-8")
    return root


def _json_fixture(
    tmp_path: Path,
    *,
    revision: str = REVISION,
) -> tuple[Path, EvidenceInputSpec]:
    root = _root(tmp_path)
    (root / "artifacts").mkdir()
    (root / "artifacts/result.json").write_text(
        json.dumps({"head_sha": revision, "passed": True}) + "\n",
        encoding="utf-8",
    )
    return root, _spec()


def _spec(
    *,
    artifact_id: str = "artifact",
    source_path: str = "artifacts/result.json",
    package_path: str = "evidence/result.json",
    media_type: str = "application/json",
    revision_json_pointer: str = "/head_sha",
) -> EvidenceInputSpec:
    return EvidenceInputSpec(
        artifact_id=artifact_id,
        source_wave=AssuranceEvidenceSource.WAVE12,
        evidence_kind=AssuranceEvidenceKind.TEST_RESULT,
        source_path=source_path,
        package_path=package_path,
        media_type=media_type,
        producer="test",
        revision_json_pointer=revision_json_pointer,
    )
