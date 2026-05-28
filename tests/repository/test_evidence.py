from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from ix_blackfox.repository import (
    WAVE8_REQUIRED_EVENT_SEQUENCE,
    RepositoryEvidenceEventType,
    RepositoryEvidenceLedger,
    RepositoryEvidenceReceipt,
    RepositoryEvidenceSnapshot,
    RepositoryImpactSeverity,
    RepositoryInventoryScanner,
    build_architecture_memory,
    build_coverage_map,
    build_dependency_map,
    build_repository_evidence_snapshot,
    receipt_id_for_event,
    repository_evidence_summary,
    validate_repository_evidence_snapshot,
)
from ix_blackfox.repository.models import digest_payload
from ix_blackfox.repository.python_graph import PythonCodeGraphBuilder

_FIXED_TIME = datetime(2026, 5, 27, 12, 0, 0, tzinfo=UTC)


def test_repository_evidence_ledger_chains_receipts() -> None:
    ledger = RepositoryEvidenceLedger(run_id="Wave 8 Test", generated_at=_FIXED_TIME)

    first = ledger.append(
        event_type=RepositoryEvidenceEventType.INVENTORY_SNAPSHOT,
        summary="Inventory built.",
        payload={"files": 1},
        generated_at=_FIXED_TIME,
    )
    second = ledger.append(
        event_type=RepositoryEvidenceEventType.CODE_GRAPH_BUILT,
        summary="Graph built.",
        payload={"modules": 1},
        generated_at=_FIXED_TIME,
    )
    evidence = ledger.snapshot()

    assert evidence.receipt_count == 2
    assert evidence.chain_valid is True
    assert first.previous_receipt_digest is None
    assert second.previous_receipt_digest == first.digest
    assert evidence.event_types == (
        RepositoryEvidenceEventType.INVENTORY_SNAPSHOT,
        RepositoryEvidenceEventType.CODE_GRAPH_BUILT,
    )
    assert evidence.to_dict()["receipts"][0]["event_type"] == "inventory_snapshot"
    assert evidence.digest == evidence.to_dict()["digest"]


def test_repository_evidence_receipt_requires_valid_payload_digest() -> None:
    with pytest.raises(ValueError, match="sha256"):
        RepositoryEvidenceReceipt(
            receipt_id="bad",
            event_type=RepositoryEvidenceEventType.INVENTORY_SNAPSHOT,
            summary="Bad digest.",
            payload_digest="not-a-digest",
            run_id="wave8",
            sequence_number=1,
            generated_at=_FIXED_TIME,
        )


def test_repository_evidence_receipt_requires_timezone_aware_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        RepositoryEvidenceReceipt(
            receipt_id="bad-time",
            event_type=RepositoryEvidenceEventType.INVENTORY_SNAPSHOT,
            summary="Bad timestamp.",
            payload_digest=digest_payload({"ok": True}),
            run_id="wave8",
            sequence_number=1,
            generated_at=datetime(2026, 5, 27, 12, 0, 0),
        )


def test_repository_evidence_snapshot_rejects_mismatched_run_id() -> None:
    receipt = RepositoryEvidenceReceipt(
        receipt_id="receipt",
        event_type=RepositoryEvidenceEventType.INVENTORY_SNAPSHOT,
        summary="Inventory built.",
        payload_digest=digest_payload({"files": 1}),
        run_id="wave8-a",
        sequence_number=1,
        generated_at=_FIXED_TIME,
    )

    with pytest.raises(ValueError, match="run_id"):
        RepositoryEvidenceSnapshot(
            run_id="wave8-b",
            receipts=(receipt,),
            generated_at=_FIXED_TIME,
        )


def test_repository_evidence_snapshot_rejects_non_contiguous_sequences() -> None:
    receipt = RepositoryEvidenceReceipt(
        receipt_id="receipt",
        event_type=RepositoryEvidenceEventType.INVENTORY_SNAPSHOT,
        summary="Inventory built.",
        payload_digest=digest_payload({"files": 1}),
        run_id="wave8",
        sequence_number=2,
        generated_at=_FIXED_TIME,
    )

    with pytest.raises(ValueError, match="contiguous"):
        RepositoryEvidenceSnapshot(
            run_id="wave8",
            receipts=(receipt,),
            generated_at=_FIXED_TIME,
        )


def test_repository_evidence_snapshot_validation_detects_required_sequence() -> None:
    ledger = RepositoryEvidenceLedger(run_id="wave8", generated_at=_FIXED_TIME)
    ledger.append(
        event_type=RepositoryEvidenceEventType.CODE_GRAPH_BUILT,
        summary="Graph built before inventory.",
        payload={"modules": 1},
        generated_at=_FIXED_TIME,
    )
    evidence = ledger.snapshot()

    validation = validate_repository_evidence_snapshot(evidence)

    assert validation["valid"] is False
    assert validation["chain_valid"] is True
    assert validation["warnings"] == [
        "Repository evidence snapshot does not begin with the required Wave 8 event sequence."
    ]


def test_build_repository_evidence_snapshot_binds_wave8_artifacts(
    tmp_path: Path,
) -> None:
    repo = _build_evidence_repo(tmp_path)
    snapshot = RepositoryInventoryScanner().scan(repo)
    graph = PythonCodeGraphBuilder().build(repo, snapshot)
    dependency_map = build_dependency_map(repo, snapshot, graph)
    coverage_map = build_coverage_map(snapshot, graph)
    architecture_memory = build_architecture_memory(snapshot, coverage_map)
    impact_report = _impact_report(
        snapshot=snapshot,
        dependency_map=dependency_map,
        coverage_map=coverage_map,
        architecture_memory=architecture_memory,
    )

    evidence = build_repository_evidence_snapshot(
        run_id="wave8-ci",
        snapshot=snapshot,
        graph=graph,
        dependency_map=dependency_map,
        coverage_map=coverage_map,
        architecture_memory=architecture_memory,
        impact_report=impact_report,
        generated_at=_FIXED_TIME,
    )
    validation = validate_repository_evidence_snapshot(evidence)
    summary = repository_evidence_summary(evidence)

    assert evidence.receipt_count == len(WAVE8_REQUIRED_EVENT_SEQUENCE)
    assert evidence.require_event_sequence(WAVE8_REQUIRED_EVENT_SEQUENCE)
    assert evidence.chain_valid is True
    assert validation["valid"] is True
    assert summary["valid"] is True
    assert summary["last_receipt_digest"] == evidence.receipts[-1].digest
    assert evidence.receipts[0].metadata["file_count"] == snapshot.file_count
    assert evidence.receipts[1].metadata["graph_digest"] == graph.digest
    assert evidence.receipts[2].metadata["dependency_map_digest"] == dependency_map.digest
    assert evidence.receipts[3].metadata["coverage_map_digest"] == coverage_map.digest
    assert evidence.receipts[4].metadata["architecture_memory_digest"] == architecture_memory.digest
    assert evidence.receipts[5].metadata["impact_report_digest"] == impact_report.digest
    assert evidence.receipts[5].metadata["max_severity"] == RepositoryImpactSeverity.HIGH.value


def test_receipt_id_for_event_is_stable_and_validates_sequence() -> None:
    assert (
        receipt_id_for_event(
            run_id="Wave 8 CI",
            sequence_number=3,
            event_type=RepositoryEvidenceEventType.DEPENDENCY_MAP_BUILT,
        )
        == "wave-8-ci-003-dependency-map-built"
    )

    with pytest.raises(ValueError, match="greater than zero"):
        receipt_id_for_event(
            run_id="wave8",
            sequence_number=0,
            event_type=RepositoryEvidenceEventType.DEPENDENCY_MAP_BUILT,
        )


def _impact_report(
    *,
    snapshot: object,
    dependency_map: object,
    coverage_map: object,
    architecture_memory: object,
) -> object:
    from ix_blackfox.repository import analyze_repository_impact

    return analyze_repository_impact(
        snapshot=snapshot,
        dependency_map=dependency_map,
        coverage_map=coverage_map,
        architecture_memory=architecture_memory,
        changed_paths=("src/ix_blackfox/runtime/brain_repair.py",),
    )


def _build_evidence_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "IX-BlackFox-main"

    _write_text(
        repo / "src" / "ix_blackfox" / "repository" / "__init__.py",
        "class RepositorySnapshot:\n    pass\n",
    )
    _write_text(
        repo / "src" / "ix_blackfox" / "runtime" / "evidence.py",
        "class EvidenceReceipt:\n    pass\n",
    )
    _write_text(
        repo / "src" / "ix_blackfox" / "runtime" / "brain_repair.py",
        "\n".join(
            [
                "from ix_blackfox.repository import RepositorySnapshot",
                "from .evidence import EvidenceReceipt",
                "",
                "def repair(snapshot: RepositorySnapshot) -> EvidenceReceipt:",
                "    return EvidenceReceipt()",
                "",
            ]
        ),
    )
    _write_text(
        repo / "tests" / "runtime" / "test_brain_repair.py",
        "\n".join(
            [
                "from ix_blackfox.runtime.brain_repair import repair",
                "",
                "def test_repair() -> None:",
                "    assert repair is not None",
                "",
            ]
        ),
    )
    _write_text(
        repo / "tests" / "repository" / "test_evidence.py",
        "def test_evidence() -> None:\n    assert True\n",
    )
    _write_text(repo / ".github" / "workflows" / "wave8.yml", "name: Wave 8\n")
    _write_text(repo / "scripts" / "run_wave8.py", "print('wave8')\n")
    _write_text(repo / "pyproject.toml", "[project]\nname = 'ix-blackfox'\n")
    _write_text(repo / "README.md", "# IX-BlackFox\n")
    _write_text(repo / "LICENSE", "source-available evaluation license\n")

    return repo


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{content.rstrip()}\n", encoding="utf-8")
