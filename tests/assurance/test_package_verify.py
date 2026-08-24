from __future__ import annotations

import hashlib
import json
import stat
import warnings
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from ix_blackfox.assurance.models import digest_payload
from ix_blackfox.assurance.package import (
    build_assurance_package,
    canonical_json_bytes,
)
from ix_blackfox.assurance.verify import (
    PackageVerificationIssueCode,
    verify_assurance_package,
    write_package_verification,
)
from tests.assurance.helpers import build_stack


def test_build_and_independently_verify_review_required_package(
    tmp_path: Path,
) -> None:
    stack, package = _build_package(tmp_path)
    verification = verify_assurance_package(package)
    assert verification.passed
    assert verification.readiness_status == "review_required"
    assert verification.manifest_digest == stack.manifest.digest
    assert verification.profile_digest == stack.manifest.profile.digest
    assert not verification.to_dict()["authenticated"]


def test_deterministic_builder_produces_identical_archives(tmp_path: Path) -> None:
    stack = build_stack(tmp_path)
    first = stack.root / "first.zip"
    second = stack.root / "second.zip"
    first_result = _build_from_stack(stack, first)
    second_result = _build_from_stack(stack, second)
    assert first.read_bytes() == second.read_bytes()
    assert first_result.archive_sha256 == second_result.archive_sha256
    assert first_result.bundle_index_digest == second_result.bundle_index_digest


def test_package_contains_unsigned_in_toto_statement_with_exact_subjects(
    tmp_path: Path,
) -> None:
    _, package = _build_package(tmp_path)
    with zipfile.ZipFile(package) as archive:
        statement = json.loads(archive.read("in-toto-statement.json"))
        names = set(archive.namelist()) - {
            "in-toto-statement.json",
            "bundle-index.json",
        }
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["predicate"]["authenticated"] is False
    assert {subject["name"] for subject in statement["subject"]} == names


def test_builder_rejects_crosswalk_subject_mismatch(tmp_path: Path) -> None:
    stack = build_stack(tmp_path)
    bad_crosswalk = replace(stack.crosswalk, subject_digest="a" * 64)
    with pytest.raises(ValueError, match="subject"):
        build_assurance_package(
            output_path=stack.root / "bad.zip",
            manifest=stack.manifest,
            crosswalk=bad_crosswalk,
            readiness=stack.readiness,
            evidence=stack.evidence,
            reviews=stack.reviews,
        )


def test_builder_rejects_evidence_inventory_mismatch(tmp_path: Path) -> None:
    stack = build_stack(tmp_path)
    with pytest.raises(ValueError, match="evidence"):
        build_assurance_package(
            output_path=stack.root / "bad.zip",
            manifest=stack.manifest,
            crosswalk=stack.crosswalk,
            readiness=stack.readiness,
            evidence=stack.evidence[:-1],
            reviews=stack.reviews,
        )


def test_verifier_detects_tampered_evidence_bytes(tmp_path: Path) -> None:
    _, package = _build_package(tmp_path)
    entries = _read_entries(package)
    evidence_name = next(name for name in entries if name.startswith("evidence/"))
    entries[evidence_name] += b"tampered"
    tampered = package.with_name("tampered-evidence.zip")
    _write_entries(tampered, entries)
    verification = verify_assurance_package(tampered)
    assert not verification.passed
    assert PackageVerificationIssueCode.DIGEST_MISMATCH in _issue_codes(verification)


def test_verifier_detects_missing_required_document(tmp_path: Path) -> None:
    _, package = _build_package(tmp_path)
    entries = _read_entries(package)
    del entries["crosswalk.json"]
    tampered = package.with_name("missing-crosswalk.zip")
    _write_entries(tampered, entries)
    verification = verify_assurance_package(tampered)
    assert PackageVerificationIssueCode.REQUIRED_ENTRY_MISSING in _issue_codes(
        verification
    )


def test_verifier_rejects_path_traversal_entry(tmp_path: Path) -> None:
    _, package = _build_package(tmp_path)
    entries = _read_entries(package)
    entries["../escape.txt"] = b"escape"
    tampered = package.with_name("traversal.zip")
    _write_entries(tampered, entries)
    verification = verify_assurance_package(tampered)
    assert PackageVerificationIssueCode.UNSAFE_ENTRY_PATH in _issue_codes(verification)


def test_verifier_rejects_windows_path_entry(tmp_path: Path) -> None:
    _, package = _build_package(tmp_path)
    entries = _read_entries(package)
    entries["C:/escape.txt"] = b"escape"
    tampered = package.with_name("windows-path.zip")
    _write_entries(tampered, entries)
    verification = verify_assurance_package(tampered)
    assert PackageVerificationIssueCode.UNSAFE_ENTRY_PATH in _issue_codes(verification)


def test_verifier_rejects_duplicate_entry_paths(tmp_path: Path) -> None:
    _, package = _build_package(tmp_path)
    duplicate = package.with_name("duplicate.zip")
    entries = _read_entries(package)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(duplicate, "w") as archive:
            for name, body in sorted(entries.items()):
                archive.writestr(name, body)
            archive.writestr("manifest.json", entries["manifest.json"])
    verification = verify_assurance_package(duplicate)
    assert PackageVerificationIssueCode.DUPLICATE_ENTRY_PATH in _issue_codes(
        verification
    )


def test_verifier_rejects_symlink_entry(tmp_path: Path) -> None:
    _, package = _build_package(tmp_path)
    symlink_package = package.with_name("symlink.zip")
    entries = _read_entries(package)
    with zipfile.ZipFile(symlink_package, "w") as archive:
        for name, body in sorted(entries.items()):
            archive.writestr(name, body)
        info = zipfile.ZipInfo("evidence/link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "target")
    verification = verify_assurance_package(symlink_package)
    assert PackageVerificationIssueCode.SYMLINK_ENTRY in _issue_codes(verification)


def test_verifier_enforces_entry_count_size_and_ratio_limits(tmp_path: Path) -> None:
    _, package = _build_package(tmp_path)
    count_result = verify_assurance_package(package, max_entries=1)
    size_result = verify_assurance_package(package, max_entry_bytes=1)
    ratio_result = verify_assurance_package(package, max_compression_ratio=1.0)
    assert PackageVerificationIssueCode.TOO_MANY_ENTRIES in _issue_codes(count_result)
    assert PackageVerificationIssueCode.ENTRY_TOO_LARGE in _issue_codes(size_result)
    assert PackageVerificationIssueCode.COMPRESSION_RATIO_EXCEEDED in _issue_codes(
        ratio_result
    )


def test_verifier_detects_semantic_crosswalk_subject_mismatch(
    tmp_path: Path,
) -> None:
    _, package = _build_package(tmp_path)
    entries = _read_entries(package)
    crosswalk = _json_entry(entries, "crosswalk.json")
    crosswalk["subject_digest"] = "a" * 64
    _set_digest(crosswalk, "digest")
    entries["crosswalk.json"] = canonical_json_bytes(crosswalk)
    readiness = _json_entry(entries, "readiness-report.json")
    readiness["crosswalk_digest"] = crosswalk["digest"]
    _set_digest(readiness, "digest")
    entries["readiness-report.json"] = canonical_json_bytes(readiness)
    _refresh_statement_and_index(entries)
    tampered = package.with_name("semantic-crosswalk.zip")
    _write_entries(tampered, entries)
    verification = verify_assurance_package(tampered)
    assert PackageVerificationIssueCode.SUBJECT_BINDING_MISMATCH in _issue_codes(
        verification
    )


def test_verifier_detects_semantic_readiness_binding_mismatch(
    tmp_path: Path,
) -> None:
    _, package = _build_package(tmp_path)
    entries = _read_entries(package)
    readiness = _json_entry(entries, "readiness-report.json")
    readiness["manifest_digest"] = "b" * 64
    _set_digest(readiness, "digest")
    entries["readiness-report.json"] = canonical_json_bytes(readiness)
    _refresh_statement_and_index(entries)
    tampered = package.with_name("semantic-readiness.zip")
    _write_entries(tampered, entries)
    verification = verify_assurance_package(tampered)
    assert PackageVerificationIssueCode.READINESS_BINDING_MISMATCH in _issue_codes(
        verification
    )


def test_verifier_recomputes_crosswalk_instead_of_trusting_its_digest(
    tmp_path: Path,
) -> None:
    _, package = _build_package(tmp_path)
    entries = _read_entries(package)
    crosswalk = _json_entry(entries, "crosswalk.json")
    crosswalk["evaluations"][0]["status"] = "missing"
    crosswalk["evaluations"][0]["blocking"] = True
    _set_digest(crosswalk, "digest")
    entries["crosswalk.json"] = canonical_json_bytes(crosswalk)
    readiness = _json_entry(entries, "readiness-report.json")
    readiness["crosswalk_digest"] = crosswalk["digest"]
    _set_digest(readiness, "digest")
    entries["readiness-report.json"] = canonical_json_bytes(readiness)
    _refresh_statement_and_index(entries)
    tampered = package.with_name("recomputed-crosswalk.zip")
    _write_entries(tampered, entries)

    verification = verify_assurance_package(tampered)

    assert (
        PackageVerificationIssueCode.CROSSWALK_EVALUATION_MISMATCH
        in _issue_codes(verification)
    )


def test_verifier_recomputes_readiness_instead_of_trusting_ready_status(
    tmp_path: Path,
) -> None:
    _, package = _build_package(tmp_path)
    entries = _read_entries(package)
    readiness = _json_entry(entries, "readiness-report.json")
    readiness["status"] = "ready_for_external_assessment"
    readiness["ready_for_external_assessment"] = True
    _set_digest(readiness, "digest")
    entries["readiness-report.json"] = canonical_json_bytes(readiness)
    _refresh_statement_and_index(entries)
    tampered = package.with_name("forged-readiness.zip")
    _write_entries(tampered, entries)

    verification = verify_assurance_package(tampered)

    assert (
        PackageVerificationIssueCode.READINESS_SEMANTICS_MISMATCH
        in _issue_codes(verification)
    )


def test_verifier_rejects_weakened_claim_policy_even_with_refreshed_hashes(
    tmp_path: Path,
) -> None:
    _, package = _build_package(tmp_path)
    entries = _read_entries(package)
    manifest = _json_entry(entries, "manifest.json")
    manifest["claims"]["asserted_claims"] = [
        "Certification granted for IX-BlackFox."
    ]
    manifest["claims"]["prohibited_asserted_terms"] = ["custom-only"]
    manifest["claims"]["prohibited_hits"] = []
    _set_digest(manifest, "manifest_digest")
    entries["manifest.json"] = canonical_json_bytes(manifest)

    readiness = _json_entry(entries, "readiness-report.json")
    readiness["manifest_digest"] = manifest["manifest_digest"]
    _set_digest(readiness, "digest")
    entries["readiness-report.json"] = canonical_json_bytes(readiness)
    reviews = _json_entry(entries, "authority-reviews.json")
    reviews["manifest_digest"] = manifest["manifest_digest"]
    _set_digest(reviews, "digest")
    entries["authority-reviews.json"] = canonical_json_bytes(reviews)
    statement = _json_entry(entries, "in-toto-statement.json")
    statement["predicate"]["manifestDigest"] = manifest["manifest_digest"]
    entries["in-toto-statement.json"] = canonical_json_bytes(statement)
    _refresh_statement_and_index(entries)
    tampered = package.with_name("weakened-claims.zip")
    _write_entries(tampered, entries)

    verification = verify_assurance_package(tampered)

    assert (
        PackageVerificationIssueCode.MANIFEST_SEMANTICS_MISMATCH
        in _issue_codes(verification)
    )


def test_verifier_detects_review_set_binding_mismatch(tmp_path: Path) -> None:
    _, package = _build_package(tmp_path)
    entries = _read_entries(package)
    reviews = _json_entry(entries, "authority-reviews.json")
    reviews["manifest_digest"] = "c" * 64
    _set_digest(reviews, "digest")
    entries["authority-reviews.json"] = canonical_json_bytes(reviews)
    _refresh_statement_and_index(entries)
    tampered = package.with_name("semantic-reviews.zip")
    _write_entries(tampered, entries)
    verification = verify_assurance_package(tampered)
    assert PackageVerificationIssueCode.REVIEW_BINDING_MISMATCH in _issue_codes(
        verification
    )


def test_verifier_detects_in_toto_binding_mismatch(tmp_path: Path) -> None:
    _, package = _build_package(tmp_path)
    entries = _read_entries(package)
    statement = _json_entry(entries, "in-toto-statement.json")
    statement["predicate"]["manifestDigest"] = "d" * 64
    entries["in-toto-statement.json"] = canonical_json_bytes(statement)
    _refresh_index(entries)
    tampered = package.with_name("semantic-statement.zip")
    _write_entries(tampered, entries)
    verification = verify_assurance_package(tampered)
    assert PackageVerificationIssueCode.IN_TOTO_STATEMENT_MISMATCH in _issue_codes(
        verification
    )


def test_write_verification_report_preserves_pass_result(tmp_path: Path) -> None:
    _, package = _build_package(tmp_path)
    verification = verify_assurance_package(package)
    output = tmp_path / "verification.json"
    assert write_package_verification(verification, output) == output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert payload["archive_sha256"] == hashlib.sha256(package.read_bytes()).hexdigest()


def test_verifier_reports_non_zip_input_without_claiming_pass(tmp_path: Path) -> None:
    path = tmp_path / "not-a-zip.zip"
    path.write_bytes(b"not a zip")
    verification = verify_assurance_package(path)
    assert not verification.passed
    assert PackageVerificationIssueCode.ARCHIVE_OPEN_FAILED in _issue_codes(
        verification
    )


def _build_package(tmp_path: Path):
    stack = build_stack(tmp_path)
    package = stack.root / "wave12.zip"
    _build_from_stack(stack, package)
    return stack, package


def _build_from_stack(stack, package: Path):
    return build_assurance_package(
        output_path=package,
        manifest=stack.manifest,
        crosswalk=stack.crosswalk,
        readiness=stack.readiness,
        evidence=stack.evidence,
        reviews=stack.reviews,
    )


def _read_entries(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def _write_entries(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, body in sorted(entries.items()):
            archive.writestr(name, body)


def _json_entry(entries: dict[str, bytes], name: str) -> dict:
    payload = json.loads(entries[name])
    assert isinstance(payload, dict)
    return payload


def _set_digest(payload: dict, field: str) -> None:
    payload.pop(field, None)
    payload[field] = digest_payload(payload)


def _refresh_statement_and_index(entries: dict[str, bytes]) -> None:
    statement = _json_entry(entries, "in-toto-statement.json")
    statement["subject"] = [
        {
            "name": name,
            "digest": {"sha256": hashlib.sha256(body).hexdigest()},
        }
        for name, body in sorted(entries.items())
        if name not in {"bundle-index.json", "in-toto-statement.json"}
    ]
    crosswalk = _json_entry(entries, "crosswalk.json")
    readiness = _json_entry(entries, "readiness-report.json")
    statement["predicate"]["crosswalkDigest"] = crosswalk["digest"]
    statement["predicate"]["readinessDigest"] = readiness["digest"]
    entries["in-toto-statement.json"] = canonical_json_bytes(statement)
    _refresh_index(entries)


def _refresh_index(entries: dict[str, bytes]) -> None:
    index = _json_entry(entries, "bundle-index.json")
    manifest = _json_entry(entries, "manifest.json")
    crosswalk = _json_entry(entries, "crosswalk.json")
    readiness = _json_entry(entries, "readiness-report.json")
    index["manifest_digest"] = manifest["manifest_digest"]
    index["subject_digest"] = manifest["subject"]["digest"]
    index["profile_digest"] = manifest["profile"]["digest"]
    index["crosswalk_digest"] = crosswalk["digest"]
    index["readiness_digest"] = readiness["digest"]
    index["readiness_status"] = readiness["status"]
    media_types = {
        item["path"]: item["media_type"] for item in manifest["evidence"]
    }
    index["entries"] = [
        {
            "path": name,
            "sha256": hashlib.sha256(body).hexdigest(),
            "size_bytes": len(body),
            "media_type": media_types.get(name, "application/json"),
        }
        for name, body in sorted(entries.items())
        if name != "bundle-index.json"
    ]
    index["entry_count_excluding_index"] = len(index["entries"])
    _set_digest(index, "bundle_index_digest")
    entries["bundle-index.json"] = canonical_json_bytes(index)


def _issue_codes(verification) -> set[PackageVerificationIssueCode]:
    return {issue.code for issue in verification.issues}
