from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ix_blackfox.repository.architecture_memory import (
    ArchitectureMemorySnapshot,
    build_architecture_memory,
)
from ix_blackfox.repository.coverage_map import (
    RepositoryCoverageMap,
    build_coverage_map,
)
from ix_blackfox.repository.dependencies import build_dependency_map
from ix_blackfox.repository.evidence import (
    RepositoryEvidenceEventType,
    RepositoryEvidenceReceipt,
    RepositoryEvidenceSnapshot,
    build_repository_evidence_snapshot,
    receipt_id_for_event,
    validate_repository_evidence_snapshot,
)
from ix_blackfox.repository.impact import analyze_repository_impact
from ix_blackfox.repository.inventory import RepositoryInventoryScanner
from ix_blackfox.repository.models import (
    RepositoryCodeGraph,
    RepositoryDependencyMap,
    RepositoryFileRole,
    RepositoryImpactReport,
    RepositorySnapshot,
    digest_payload,
    normalize_identifier,
    normalize_text,
)
from ix_blackfox.repository.python_graph import build_python_code_graph


_REPOSITORY_INTELLIGENCE_SCHEMA_VERSION = "wave8.repository_intelligence.v1"


@dataclass(frozen=True, slots=True)
class RepositoryIntelligenceReport:
    """Top-level Wave 8 repository-intelligence evidence report."""

    run_id: str
    head_sha: str
    root_name: str
    snapshot: RepositorySnapshot
    code_graph: RepositoryCodeGraph
    dependency_map: RepositoryDependencyMap
    coverage_map: RepositoryCoverageMap
    architecture_memory: ArchitectureMemorySnapshot
    impact_report: RepositoryImpactReport
    evidence_snapshot: RepositoryEvidenceSnapshot
    generated_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "run_id",
            normalize_identifier(self.run_id, label="run_id"),
        )
        object.__setattr__(
            self,
            "head_sha",
            normalize_text(self.head_sha, label="head_sha"),
        )
        object.__setattr__(
            self,
            "root_name",
            normalize_text(self.root_name, label="root_name"),
        )
        if self.generated_at.tzinfo is None:
            raise ValueError("generated_at must be timezone-aware.")
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def passed(self) -> bool:
        validation = validate_repository_evidence_snapshot(self.evidence_snapshot)
        return (
            self.snapshot.file_count > 0
            and len(self.code_graph.syntax_error_paths) == 0
            and validation["valid"] is True
        )

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_full=False, include_digest=False))

    def to_dict(
        self,
        *,
        include_full: bool = True,
        include_digest: bool = True,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": _REPOSITORY_INTELLIGENCE_SCHEMA_VERSION,
            "wave": 8,
            "run_id": self.run_id,
            "head_sha": self.head_sha,
            "root_name": self.root_name,
            "generated_at": self.generated_at.isoformat(),
            "passed": self.passed,
            "digests": {
                "snapshot": self.snapshot.digest,
                "code_graph": self.code_graph.digest,
                "dependency_map": self.dependency_map.digest,
                "coverage_map": self.coverage_map.digest,
                "architecture_memory": self.architecture_memory.digest,
                "impact_report": self.impact_report.digest,
                "evidence_snapshot": self.evidence_snapshot.digest,
            },
            "summary": repository_intelligence_summary(
                snapshot=self.snapshot,
                code_graph=self.code_graph,
                dependency_map=self.dependency_map,
                coverage_map=self.coverage_map,
                architecture_memory=self.architecture_memory,
                impact_report=self.impact_report,
                evidence_snapshot=self.evidence_snapshot,
            ),
            "impact_report": self.impact_report.to_dict(),
            "evidence_snapshot": self.evidence_snapshot.to_dict(),
            "scope_note": (
                "Wave 8 repository intelligence is conservative static evidence "
                "for review. It does not certify code correctness, production "
                "readiness, compliance approval, defense approval, or autonomous "
                "execution authority."
            ),
            "metadata": dict(self.metadata),
        }
        if include_full:
            payload["snapshot"] = self.snapshot.to_dict()
            payload["code_graph"] = self.code_graph.to_dict()
            payload["dependency_map"] = self.dependency_map.to_dict()
            payload["coverage_map"] = self.coverage_map.to_dict()
            payload["architecture_memory"] = self.architecture_memory.to_dict()
        if include_digest:
            payload["digest"] = self.digest
        return payload

    def write_json(self, path: str | Path, *, include_full: bool = True) -> None:
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(
                self.to_dict(include_full=include_full),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )


@dataclass(frozen=True, slots=True)
class RepositoryIntelligenceRunner:
    """Run the complete Wave 8 repository-intelligence pipeline."""

    def run(
        self,
        *,
        root: str | Path,
        changed_paths: Sequence[str],
        head_sha: str,
        run_id: str,
        metadata: Mapping[str, Any] | None = None,
        generated_at: datetime | None = None,
    ) -> RepositoryIntelligenceReport:
        repo_root = Path(root).resolve()
        if not repo_root.is_dir():
            raise ValueError(f"Repository root does not exist: {repo_root}")

        report_time = generated_at or datetime.now(tz=UTC)
        normalized_run_id = normalize_identifier(run_id, label="run_id")

        snapshot = RepositoryInventoryScanner().scan(
            repo_root,
            snapshot_id=f"{normalized_run_id}-inventory",
            root_label=repo_root.name,
        )
        code_graph = build_python_code_graph(
            repo_root,
            snapshot,
            graph_id=f"{normalized_run_id}-python-code-graph",
        )
        dependency_map = build_dependency_map(
            repo_root,
            snapshot,
            code_graph,
            map_id=f"{normalized_run_id}-dependency-map",
        )
        coverage_map = build_coverage_map(
            snapshot,
            code_graph,
            map_id=f"{normalized_run_id}-coverage-map",
        )
        architecture_memory = build_architecture_memory(
            snapshot,
            coverage_map,
            memory_id=f"{normalized_run_id}-architecture-memory",
        )
        impact_report = analyze_repository_impact(
            snapshot=snapshot,
            dependency_map=dependency_map,
            coverage_map=coverage_map,
            architecture_memory=architecture_memory,
            changed_paths=changed_paths,
            report_id=f"{normalized_run_id}-impact-report",
        )
        preliminary_evidence = build_repository_evidence_snapshot(
            run_id=normalized_run_id,
            snapshot=snapshot,
            graph=code_graph,
            dependency_map=dependency_map,
            coverage_map=coverage_map,
            architecture_memory=architecture_memory,
            impact_report=impact_report,
            generated_at=report_time,
        )

        preliminary_report = RepositoryIntelligenceReport(
            run_id=normalized_run_id,
            head_sha=head_sha,
            root_name=repo_root.name,
            snapshot=snapshot,
            code_graph=code_graph,
            dependency_map=dependency_map,
            coverage_map=coverage_map,
            architecture_memory=architecture_memory,
            impact_report=impact_report,
            evidence_snapshot=preliminary_evidence,
            generated_at=report_time,
            metadata=dict(metadata or {}),
        )
        report_export_receipt = build_report_export_receipt(
            report=preliminary_report,
            previous_evidence=preliminary_evidence,
            generated_at=report_time,
        )
        final_evidence = RepositoryEvidenceSnapshot(
            run_id=normalized_run_id,
            receipts=preliminary_evidence.receipts + (report_export_receipt,),
            generated_at=preliminary_evidence.generated_at,
            metadata={
                "report_exported": True,
                "schema_version": _REPOSITORY_INTELLIGENCE_SCHEMA_VERSION,
            },
        )

        return RepositoryIntelligenceReport(
            run_id=normalized_run_id,
            head_sha=head_sha,
            root_name=repo_root.name,
            snapshot=snapshot,
            code_graph=code_graph,
            dependency_map=dependency_map,
            coverage_map=coverage_map,
            architecture_memory=architecture_memory,
            impact_report=impact_report,
            evidence_snapshot=final_evidence,
            generated_at=report_time,
            metadata=dict(metadata or {}),
        )


def build_repository_intelligence_report(
    *,
    root: str | Path,
    changed_paths: Sequence[str],
    head_sha: str,
    run_id: str,
    metadata: Mapping[str, Any] | None = None,
    generated_at: datetime | None = None,
) -> RepositoryIntelligenceReport:
    """Convenience wrapper for the default Wave 8 report runner."""
    return RepositoryIntelligenceRunner().run(
        root=root,
        changed_paths=changed_paths,
        head_sha=head_sha,
        run_id=run_id,
        metadata=metadata,
        generated_at=generated_at,
    )


def build_report_export_receipt(
    *,
    report: RepositoryIntelligenceReport,
    previous_evidence: RepositoryEvidenceSnapshot,
    generated_at: datetime,
) -> RepositoryEvidenceReceipt:
    previous_receipt_digest = (
        previous_evidence.receipts[-1].digest if previous_evidence.receipts else None
    )
    sequence_number = previous_evidence.receipt_count + 1
    report_payload = report.to_dict(include_full=False)
    return RepositoryEvidenceReceipt(
        receipt_id=receipt_id_for_event(
            run_id=report.run_id,
            sequence_number=sequence_number,
            event_type=RepositoryEvidenceEventType.REPORT_EXPORTED,
        ),
        event_type=RepositoryEvidenceEventType.REPORT_EXPORTED,
        summary="Wave 8 repository-intelligence report rendered for export.",
        payload_digest=digest_payload(report_payload),
        run_id=report.run_id,
        sequence_number=sequence_number,
        previous_receipt_digest=previous_receipt_digest,
        generated_at=generated_at,
        metadata={
            "schema_version": _REPOSITORY_INTELLIGENCE_SCHEMA_VERSION,
            "report_payload_digest": digest_payload(report_payload),
            "include_full": False,
        },
    )


def repository_intelligence_summary(
    *,
    snapshot: RepositorySnapshot,
    code_graph: RepositoryCodeGraph,
    dependency_map: RepositoryDependencyMap,
    coverage_map: RepositoryCoverageMap,
    architecture_memory: ArchitectureMemorySnapshot,
    impact_report: RepositoryImpactReport,
    evidence_snapshot: RepositoryEvidenceSnapshot,
) -> dict[str, Any]:
    return {
        "file_count": snapshot.file_count,
        "total_bytes": snapshot.total_bytes,
        "source_file_count": len(snapshot.paths_by_role(RepositoryFileRole.SOURCE)),
        "test_file_count": len(snapshot.paths_by_role(RepositoryFileRole.TEST)),
        "syntax_error_count": len(code_graph.syntax_error_paths),
        "symbol_count": code_graph.symbol_count,
        "graph_edge_count": code_graph.edge_count,
        "dependency_count": len(dependency_map.dependencies),
        "internal_import_edge_count": len(dependency_map.internal_edges),
        "sensitive_path_count": len(dependency_map.sensitive_paths),
        "source_test_link_count": coverage_map.link_count,
        "subsystem_count": coverage_map.subsystem_count,
        "architecture_record_count": architecture_memory.record_count,
        "changed_path_count": len(impact_report.changed_paths),
        "impacted_path_count": len(impact_report.impacted_paths),
        "impacted_test_count": len(impact_report.impacted_tests),
        "impacted_subsystem_count": len(impact_report.impacted_subsystems),
        "requires_human_review": impact_report.requires_human_review,
        "max_severity": impact_report.max_severity.value,
        "receipt_count": evidence_snapshot.receipt_count,
        "evidence_chain_valid": evidence_snapshot.chain_valid,
    }
