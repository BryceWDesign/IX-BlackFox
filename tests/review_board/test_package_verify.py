from __future__ import annotations

import hashlib
import json
import stat
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from ix_blackfox.assurance.package import canonical_json_bytes
from ix_blackfox.operating.models import digest_payload
from ix_blackfox.review_board import ReviewBoardStatus
from ix_blackfox.review_board.package import (
    UPSTREAM_WAVE12_ENTRY,
    build_review_board_package,
)
from ix_blackfox.review_board.policy import (
    build_machine_advisory,
    default_wave13_review_policy,
)
from ix_blackfox.review_board.verify import (
    ReviewBoardVerificationIssueCode,
    verify_review_board_package,
)
from tests.review_board.helpers import (
    WAVE13_TIME,
    admit_fixture,
    external_verifications_for_reviews,
    full_human_approvals,
)

_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def test_review_board_package_is_deterministic_and_verifiable(tmp_path: Path) -> None:
    wave12, admission = admit_fixture(tmp_path)
    policy = default_wave13_review_policy()
    advisory = build_machine_advisory(
        advisory_id="wave13-ci-advisory",
        producer_agent_id="wave13-rule-engine",
        subject=admission.subject,
        policy=policy,
        produced_at=WAVE13_TIME,
        upstream_verification_passed=True,
        upstream_readiness_status=admission.verification.readiness_status,
    )
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"

    result_one = build_review_board_package(
        output_path=first,
        wave12_package_path=wave12,
        subject=admission.subject,
        policy=policy,
        machine_advisories=(advisory,),
        metadata={"fixture": True},
    )
    result_two = build_review_board_package(
        output_path=second,
        wave12_package_path=wave12,
        subject=admission.subject,
        policy=policy,
        machine_advisories=(advisory,),
        metadata={"fixture": True},
    )

    assert first.read_bytes() == second.read_bytes()
    assert result_one.archive_sha256 == result_two.archive_sha256
    assert result_one.status == ReviewBoardStatus.HUMAN_REVIEW_REQUIRED.value

    verification = verify_review_board_package(first)
    assert verification.passed is True
    assert verification.status == ReviewBoardStatus.HUMAN_REVIEW_REQUIRED.value
    assert verification.upstream_wave12_verification_passed is True
    assert verification.upstream_wave12_sha256 == admission.subject.wave12_archive_sha256


def test_full_human_board_package_verifies_as_approved_for_next_gate(tmp_path: Path) -> None:
    wave12, admission = admit_fixture(tmp_path)
    output = tmp_path / "approved.zip"
    reviews = full_human_approvals(admission)
    verifications = external_verifications_for_reviews(reviews)

    build_review_board_package(
        output_path=output,
        wave12_package_path=wave12,
        subject=admission.subject,
        policy=default_wave13_review_policy(),
        human_reviews=reviews,
        external_verifications=verifications,
    )

    verification = verify_review_board_package(
        output,
        external_verifications=verifications,
    )
    assert verification.passed is True
    assert verification.status == ReviewBoardStatus.APPROVED_FOR_NEXT_GATE.value
    assert verification.external_verification_count == 7


def test_approved_package_fails_verification_without_trusted_external_context(
    tmp_path: Path,
) -> None:
    wave12, admission = admit_fixture(tmp_path)
    output = tmp_path / "approved-requires-context.zip"
    reviews = full_human_approvals(admission)
    verifications = external_verifications_for_reviews(reviews)
    build_review_board_package(
        output_path=output,
        wave12_package_path=wave12,
        subject=admission.subject,
        policy=default_wave13_review_policy(),
        human_reviews=reviews,
        external_verifications=verifications,
    )

    verification = verify_review_board_package(output)

    assert verification.passed is False
    assert any(
        issue.code
        is ReviewBoardVerificationIssueCode.EXTERNAL_VERIFICATION_CONTEXT_MISMATCH
        for issue in verification.issues
    )
    assert verification.status == ReviewBoardStatus.HUMAN_REVIEW_REQUIRED.value


def test_self_asserted_external_review_records_do_not_approve_package(
    tmp_path: Path,
) -> None:
    wave12, admission = admit_fixture(tmp_path)
    output = tmp_path / "self-asserted-external.zip"
    reviews = full_human_approvals(admission)

    result = build_review_board_package(
        output_path=output,
        wave12_package_path=wave12,
        subject=admission.subject,
        policy=default_wave13_review_policy(),
        human_reviews=reviews,
    )

    assert result.status == ReviewBoardStatus.HUMAN_REVIEW_REQUIRED.value
    assert result.evaluation.external_verification_count == 0
    verification = verify_review_board_package(output)
    assert verification.passed is True
    assert verification.status == ReviewBoardStatus.HUMAN_REVIEW_REQUIRED.value


def test_package_builder_rejects_subject_not_matching_wave12_archive(tmp_path: Path) -> None:
    wave12, admission = admit_fixture(tmp_path)
    wrong_subject = replace(admission.subject, wave12_archive_sha256="b" * 64)

    with pytest.raises(ValueError, match="does not exactly match"):
        build_review_board_package(
            output_path=tmp_path / "bad.zip",
            wave12_package_path=wave12,
            subject=wrong_subject,
            policy=default_wave13_review_policy(),
        )


def test_verifier_rejects_semantic_status_forgery_even_with_refreshed_hashes(
    tmp_path: Path,
) -> None:
    wave12, admission = admit_fixture(tmp_path)
    source = tmp_path / "source.zip"
    build_review_board_package(
        output_path=source,
        wave12_package_path=wave12,
        subject=admission.subject,
        policy=default_wave13_review_policy(),
    )
    entries = _read_entries(source)
    evaluation = _json(entries["board-evaluation.json"])
    evaluation["status"] = ReviewBoardStatus.APPROVED_FOR_NEXT_GATE.value
    evaluation["approved_for_next_gate"] = True
    evaluation["digest"] = digest_payload(
        {key: value for key, value in evaluation.items() if key != "digest"}
    )
    entries["board-evaluation.json"] = canonical_json_bytes(evaluation)
    _refresh_bundle_index(entries)
    forged = tmp_path / "forged-status.zip"
    _write_entries(forged, entries)

    verification = verify_review_board_package(forged)

    assert verification.passed is False
    assert any(
        issue.code is ReviewBoardVerificationIssueCode.EVALUATION_SEMANTICS_MISMATCH
        for issue in verification.issues
    )


def test_verifier_rejects_corrupt_embedded_wave12_even_with_refreshed_outer_index(
    tmp_path: Path,
) -> None:
    wave12, admission = admit_fixture(tmp_path)
    source = tmp_path / "source.zip"
    build_review_board_package(
        output_path=source,
        wave12_package_path=wave12,
        subject=admission.subject,
        policy=default_wave13_review_policy(),
    )
    entries = _read_entries(source)
    body = bytearray(entries[UPSTREAM_WAVE12_ENTRY])
    body[len(body) // 2] ^= 0x01
    entries[UPSTREAM_WAVE12_ENTRY] = bytes(body)
    _refresh_bundle_index(entries)
    forged = tmp_path / "corrupt-upstream.zip"
    _write_entries(forged, entries)

    verification = verify_review_board_package(forged)

    assert verification.passed is False
    assert any(
        issue.code
        in {
            ReviewBoardVerificationIssueCode.UPSTREAM_DIGEST_MISMATCH,
            ReviewBoardVerificationIssueCode.UPSTREAM_VERIFICATION_FAILED,
        }
        for issue in verification.issues
    )


def test_verifier_rejects_ledger_mutation_even_with_refreshed_outer_index(
    tmp_path: Path,
) -> None:
    wave12, admission = admit_fixture(tmp_path)
    source = tmp_path / "source.zip"
    build_review_board_package(
        output_path=source,
        wave12_package_path=wave12,
        subject=admission.subject,
        policy=default_wave13_review_policy(),
    )
    entries = _read_entries(source)
    ledger = _json(entries["review-ledger.json"])
    events = ledger["events"]
    assert isinstance(events, list)
    first = events[0]
    assert isinstance(first, dict)
    first["object_id"] = "forged-subject-event"
    entries["review-ledger.json"] = canonical_json_bytes(ledger)
    _refresh_bundle_index(entries)
    forged = tmp_path / "forged-ledger.zip"
    _write_entries(forged, entries)

    verification = verify_review_board_package(forged)

    assert verification.passed is False
    assert any(
        issue.code is ReviewBoardVerificationIssueCode.LEDGER_MISMATCH
        for issue in verification.issues
    )


def test_verifier_rejects_path_traversal_entry(tmp_path: Path) -> None:
    wave12, admission = admit_fixture(tmp_path)
    source = tmp_path / "source.zip"
    build_review_board_package(
        output_path=source,
        wave12_package_path=wave12,
        subject=admission.subject,
        policy=default_wave13_review_policy(),
    )
    entries = _read_entries(source)
    entries["../escape.json"] = b"{}\n"
    bad = tmp_path / "unsafe.zip"
    _write_entries(bad, entries)

    verification = verify_review_board_package(bad)

    assert verification.passed is False
    assert any(
        issue.code is ReviewBoardVerificationIssueCode.UNSAFE_ENTRY_PATH
        for issue in verification.issues
    )


def test_verifier_rejects_unexpected_archive_entry(tmp_path: Path) -> None:
    wave12, admission = admit_fixture(tmp_path)
    source = tmp_path / "source.zip"
    build_review_board_package(
        output_path=source,
        wave12_package_path=wave12,
        subject=admission.subject,
        policy=default_wave13_review_policy(),
    )
    entries = _read_entries(source)
    entries["untrusted-extra.json"] = b"{}\n"
    forged = tmp_path / "unexpected-entry.zip"
    _write_entries(forged, entries)

    verification = verify_review_board_package(forged)

    assert verification.passed is False
    assert any(
        issue.code is ReviewBoardVerificationIssueCode.UNEXPECTED_ENTRY_PATH
        for issue in verification.issues
    )


def test_machine_advisories_cannot_change_human_quorum_by_package_tampering(
    tmp_path: Path,
) -> None:
    wave12, admission = admit_fixture(tmp_path)
    policy = default_wave13_review_policy()
    advisory = build_machine_advisory(
        advisory_id="model-advisory",
        producer_agent_id="model-brain",
        subject=admission.subject,
        policy=policy,
        produced_at=WAVE13_TIME,
        upstream_verification_passed=True,
        upstream_readiness_status=admission.verification.readiness_status,
    )
    source = tmp_path / "machine-only.zip"
    build_review_board_package(
        output_path=source,
        wave12_package_path=wave12,
        subject=admission.subject,
        policy=policy,
        machine_advisories=(advisory,),
    )

    verification = verify_review_board_package(source)

    assert verification.passed is True
    assert verification.status == ReviewBoardStatus.HUMAN_REVIEW_REQUIRED.value


def _read_entries(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path, mode="r") as archive:
        return {info.filename: archive.read(info.filename) for info in archive.infolist()}


def _write_entries(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(
        path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=_ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, entries[name])


def _refresh_bundle_index(entries: dict[str, bytes]) -> None:
    index = _json(entries["bundle-index.json"])
    indexed = []
    for name, body in sorted(entries.items()):
        if name == "bundle-index.json":
            continue
        indexed.append(
            {
                "path": name,
                "sha256": hashlib.sha256(body).hexdigest(),
                "size_bytes": len(body),
                "media_type": (
                    "application/zip"
                    if name == UPSTREAM_WAVE12_ENTRY
                    else "application/json"
                ),
            }
        )
    index["entries"] = indexed
    index["entry_count_excluding_index"] = len(indexed)
    if "board-evaluation.json" in entries:
        evaluation = _json(entries["board-evaluation.json"])
        index["evaluation_digest"] = evaluation.get("digest", "")
        index["status"] = evaluation.get("status", "")
    if "review-ledger.json" in entries:
        ledger = _json(entries["review-ledger.json"])
        index["ledger_digest"] = ledger.get("digest", "")
    index["upstream_wave12_sha256"] = hashlib.sha256(
        entries[UPSTREAM_WAVE12_ENTRY]
    ).hexdigest()
    index["bundle_index_digest"] = digest_payload(
        {key: value for key, value in index.items() if key != "bundle_index_digest"}
    )
    entries["bundle-index.json"] = canonical_json_bytes(index)


def _json(body: bytes) -> dict[str, Any]:
    payload = json.loads(body.decode("utf-8"))
    assert isinstance(payload, dict)
    return payload
