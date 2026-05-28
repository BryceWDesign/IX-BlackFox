from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from ix_blackfox.repository.models import (
    RepositoryDependencyMap,
    RepositoryEdgeKind,
    RepositoryFileRecord,
    RepositoryFileRole,
    RepositoryImpactFinding,
    RepositoryImpactReport,
    RepositoryImpactSeverity,
    RepositorySensitivity,
    RepositorySnapshot,
    normalize_path_tuple,
    normalize_relative_path,
)

if TYPE_CHECKING:
    from ix_blackfox.repository.architecture_memory import ArchitectureMemorySnapshot
    from ix_blackfox.repository.coverage_map import RepositoryCoverageMap


@dataclass(frozen=True, slots=True)
class RepositoryImpactAnalyzer:
    """Analyze conservative repository impact for changed paths.

    The analyzer intentionally reports review-oriented impact. It does not claim
    perfect program slicing, perfect test selection, or certified safety. It
    binds repository inventory, dependency edges, source-test mapping, and
    architectural memory into a reviewable impact report before humans are asked
    to trust a code-change path.
    """

    escalate_unknown_paths: bool = True

    def analyze(
        self,
        *,
        snapshot: RepositorySnapshot,
        dependency_map: RepositoryDependencyMap,
        coverage_map: RepositoryCoverageMap,
        architecture_memory: ArchitectureMemorySnapshot,
        changed_paths: Sequence[str],
        report_id: str = "wave-8-repository-impact-report",
    ) -> RepositoryImpactReport:
        normalized_changed_paths = normalize_path_tuple(
            changed_paths,
            label="changed_paths",
        )
        records_by_path = snapshot_records_by_path(snapshot)

        impacted_paths: set[str] = set(normalized_changed_paths)
        impacted_tests: set[str] = set()
        impacted_subsystems: set[str] = set()
        findings: list[RepositoryImpactFinding] = []

        for changed_path in normalized_changed_paths:
            record = records_by_path.get(changed_path)
            impacted_paths.update(
                dependency_impacted_paths(dependency_map, changed_path)
            )
            impacted_subsystems.update(coverage_map.subsystems_for_path(changed_path))
            impacted_subsystems.update(
                record.subsystem
                for record in architecture_memory.records_for_path(changed_path)
            )

            if record is None:
                findings.extend(
                    unknown_path_findings(
                        changed_path,
                        escalate=self.escalate_unknown_paths,
                    )
                )
                continue

            impacted_tests.update(tests_impacted_by_record(record, coverage_map))
            findings.extend(sensitivity_findings(record))
            findings.extend(role_findings(record))

        for impacted_path in tuple(sorted(impacted_paths)):
            impacted_record = records_by_path.get(impacted_path)
            if impacted_record is not None:
                impacted_tests.update(
                    tests_impacted_by_record(impacted_record, coverage_map)
                )
            impacted_subsystems.update(coverage_map.subsystems_for_path(impacted_path))
            impacted_subsystems.update(
                record.subsystem
                for record in architecture_memory.records_for_path(impacted_path)
            )

        for changed_path in normalized_changed_paths:
            record = records_by_path.get(changed_path)
            if record is not None:
                findings.extend(
                    unmapped_test_findings(
                        record,
                        coverage_map.tests_for_source(changed_path),
                    )
                )

        findings.extend(cross_subsystem_findings(impacted_subsystems))
        findings = deduplicate_findings(findings)

        return RepositoryImpactReport(
            report_id=report_id,
            changed_paths=normalized_changed_paths,
            impacted_paths=tuple(sorted(impacted_paths)),
            impacted_tests=tuple(sorted(impacted_tests)),
            impacted_subsystems=tuple(sorted(impacted_subsystems)),
            findings=tuple(findings),
            recommended_commands=tuple(
                build_recommended_commands(
                    impacted_tests=impacted_tests,
                    impacted_subsystems=impacted_subsystems,
                    findings=findings,
                    changed_paths=normalized_changed_paths,
                )
            ),
            metadata={
                "snapshot_digest": snapshot.digest,
                "dependency_map_digest": dependency_map.digest,
                "coverage_map_digest": coverage_map.digest,
                "architecture_memory_digest": architecture_memory.digest,
                "analysis_mode": "conservative-review-impact",
            },
        )


def analyze_repository_impact(
    *,
    snapshot: RepositorySnapshot,
    dependency_map: RepositoryDependencyMap,
    coverage_map: RepositoryCoverageMap,
    architecture_memory: ArchitectureMemorySnapshot,
    changed_paths: Sequence[str],
    report_id: str = "wave-8-repository-impact-report",
) -> RepositoryImpactReport:
    """Convenience wrapper for the default Wave 8 impact analyzer."""
    return RepositoryImpactAnalyzer().analyze(
        snapshot=snapshot,
        dependency_map=dependency_map,
        coverage_map=coverage_map,
        architecture_memory=architecture_memory,
        changed_paths=changed_paths,
        report_id=report_id,
    )


def snapshot_records_by_path(
    snapshot: RepositorySnapshot,
) -> dict[str, RepositoryFileRecord]:
    return {record.path: record for record in snapshot.files}


def dependency_impacted_paths(
    dependency_map: RepositoryDependencyMap,
    changed_path: str,
) -> tuple[str, ...]:
    normalized = normalize_relative_path(changed_path)
    impacted: set[str] = set()

    for edge in dependency_map.internal_edges:
        source_path = str(edge.metadata.get("source_path") or "")
        resolved_path = str(edge.metadata.get("resolved_path") or "")

        if edge.kind is not RepositoryEdgeKind.IMPORTS:
            continue
        if source_path == normalized and resolved_path:
            impacted.add(resolved_path)
        if resolved_path == normalized and source_path:
            impacted.add(source_path)

    return tuple(sorted(impacted))


def tests_impacted_by_record(
    record: RepositoryFileRecord,
    coverage_map: RepositoryCoverageMap,
) -> tuple[str, ...]:
    if record.role is RepositoryFileRole.TEST:
        return (record.path,)
    if record.role is RepositoryFileRole.SOURCE:
        return coverage_map.tests_for_source(record.path)
    return ()


def sensitivity_findings(
    record: RepositoryFileRecord,
) -> tuple[RepositoryImpactFinding, ...]:
    if record.sensitivity is RepositorySensitivity.NORMAL:
        return ()

    severity = {
        RepositorySensitivity.POLICY_RELEVANT: RepositoryImpactSeverity.HIGH,
        RepositorySensitivity.SECURITY_RELEVANT: RepositoryImpactSeverity.HIGH,
        RepositorySensitivity.RELEASE_RELEVANT: RepositoryImpactSeverity.HIGH,
        RepositorySensitivity.GENERATED_OR_ARTIFACT: RepositoryImpactSeverity.MEDIUM,
    }[record.sensitivity]

    return (
        RepositoryImpactFinding(
            code=f"repository.sensitivity.{record.sensitivity.value}",
            severity=severity,
            summary=(
                f"{record.path} is classified as {record.sensitivity.value}; "
                "human review should confirm the change does not weaken policy, "
                "security, release, or evidence posture."
            ),
            paths=(record.path,),
            review_required=True,
        ),
    )


def role_findings(record: RepositoryFileRecord) -> tuple[RepositoryImpactFinding, ...]:
    if record.role is RepositoryFileRole.WORKFLOW:
        return (
            RepositoryImpactFinding(
                code="repository.role.workflow",
                severity=RepositoryImpactSeverity.HIGH,
                summary=(
                    f"{record.path} changes CI workflow behavior; review must confirm "
                    "tests, failure handling, and evidence artifacts are not bypassed."
                ),
                paths=(record.path,),
                review_required=True,
            ),
        )
    if record.role is RepositoryFileRole.SCRIPT:
        return (
            RepositoryImpactFinding(
                code="repository.role.script",
                severity=RepositoryImpactSeverity.HIGH,
                summary=(
                    f"{record.path} changes an operator/CI script; review must confirm "
                    "it remains deterministic, bounded, and fail-closed."
                ),
                paths=(record.path,),
                review_required=True,
            ),
        )
    if record.role is RepositoryFileRole.LICENSE:
        return (
            RepositoryImpactFinding(
                code="repository.role.license",
                severity=RepositoryImpactSeverity.CRITICAL,
                summary=(
                    f"{record.path} changes licensing or notice posture; this requires "
                    "explicit human legal/commercial review."
                ),
                paths=(record.path,),
                review_required=True,
            ),
        )
    return ()


def unknown_path_findings(
    changed_path: str,
    *,
    escalate: bool,
) -> tuple[RepositoryImpactFinding, ...]:
    if not escalate:
        return ()
    return (
        RepositoryImpactFinding(
            code="repository.change.unknown_path",
            severity=RepositoryImpactSeverity.MEDIUM,
            summary=(
                f"{changed_path} was not present in the repository inventory snapshot; "
                "review must confirm whether this is a new file, deleted file, or stale path."
            ),
            paths=(changed_path,),
            review_required=True,
        ),
    )


def unmapped_test_findings(
    record: RepositoryFileRecord,
    mapped_tests: Sequence[str],
) -> tuple[RepositoryImpactFinding, ...]:
    if record.role is not RepositoryFileRole.SOURCE:
        return ()
    if record.path.endswith("/__init__.py"):
        return ()
    if mapped_tests:
        return ()
    return (
        RepositoryImpactFinding(
            code="repository.coverage.unmapped_source",
            severity=RepositoryImpactSeverity.MEDIUM,
            summary=(
                f"{record.path} has no mapped test in the Wave 8 coverage map; "
                "review should confirm whether targeted test coverage is missing or "
                "only not inferable."
            ),
            paths=(record.path,),
            review_required=True,
        ),
    )


def cross_subsystem_findings(
    impacted_subsystems: Iterable[str],
) -> tuple[RepositoryImpactFinding, ...]:
    subsystems = tuple(sorted(set(impacted_subsystems)))
    if len(subsystems) <= 1:
        return ()
    return (
        RepositoryImpactFinding(
            code="repository.impact.cross_subsystem",
            severity=RepositoryImpactSeverity.MEDIUM,
            summary=(
                "The change crosses subsystem boundaries: "
                f"{', '.join(subsystems)}. Review should confirm coupling and "
                "test scope are intentional."
            ),
            paths=(),
            review_required=True,
        ),
    )


def deduplicate_findings(
    findings: Sequence[RepositoryImpactFinding],
) -> list[RepositoryImpactFinding]:
    deduped: list[RepositoryImpactFinding] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()

    for finding in findings:
        key = (finding.code, finding.paths)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)

    return deduped


def build_recommended_commands(
    *,
    impacted_tests: set[str],
    impacted_subsystems: set[str],
    findings: Sequence[RepositoryImpactFinding],
    changed_paths: Sequence[str],
) -> list[str]:
    commands: list[str] = []

    if impacted_tests:
        commands.append(f"python -m pytest {' '.join(sorted(impacted_tests))} -q")

    if "repository" in impacted_subsystems:
        commands.append("python -m pytest tests/repository -q")
    if "ci-workflows" in impacted_subsystems:
        commands.append("python -m pytest tests/ci -q")
    if "interface" in impacted_subsystems:
        commands.append("python -m pytest tests/interface -q")
    if "runtime" in impacted_subsystems:
        commands.append("python -m pytest tests/runtime -q")
    if "governance" in impacted_subsystems:
        commands.append("python -m pytest tests/governance -q")
    if "sandbox" in impacted_subsystems:
        commands.append("python -m pytest tests/sandbox -q")
    if "workflow" in impacted_subsystems:
        commands.append("python -m pytest tests/workflow -q")

    if any(path_requires_compile_check(path) for path in changed_paths):
        commands.append("python -m compileall -q src tests scripts")

    if any(
        finding.severity
        in {
            RepositoryImpactSeverity.HIGH,
            RepositoryImpactSeverity.CRITICAL,
        }
        for finding in findings
    ):
        commands.append("python -m pytest -q")

    return deduplicate_commands(commands)


def deduplicate_commands(commands: Sequence[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for command in commands:
        if command in seen:
            continue
        seen.add(command)
        deduped.append(command)
    return deduped


def path_requires_compile_check(path: str) -> bool:
    normalized = normalize_relative_path(path)
    return normalized.endswith(".py") or normalized.startswith("scripts/")


def path_basename(path: str) -> str:
    return PurePosixPath(normalize_relative_path(path)).name
