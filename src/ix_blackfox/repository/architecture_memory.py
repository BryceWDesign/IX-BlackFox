from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ix_blackfox.repository.models import (
    RepositoryArchitectureRecord,
    RepositoryFileRole,
    RepositorySensitivity,
    RepositorySnapshot,
    digest_payload,
    normalize_identifier,
    normalize_relative_path,
)

if TYPE_CHECKING:
    from ix_blackfox.repository.coverage_map import RepositoryCoverageMap


@dataclass(frozen=True, slots=True)
class ArchitectureMemorySnapshot:
    memory_id: str
    records: tuple[RepositoryArchitectureRecord, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "memory_id",
            normalize_identifier(self.memory_id, label="memory_id"),
        )
        records = tuple(sorted(self.records, key=lambda item: item.record_id))
        record_ids = [record.record_id for record in records]
        if len(record_ids) != len(set(record_ids)):
            raise ValueError("Architecture memory record_id values must be unique.")

        subsystems = [record.subsystem for record in records]
        if len(subsystems) != len(set(subsystems)):
            raise ValueError("Architecture memory subsystem values must be unique.")

        object.__setattr__(self, "records", records)
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def record_count(self) -> int:
        return len(self.records)

    @property
    def subsystem_ids(self) -> tuple[str, ...]:
        return tuple(record.subsystem for record in self.records)

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def records_for_path(self, path: str) -> tuple[RepositoryArchitectureRecord, ...]:
        normalized = normalize_relative_path(path)
        return tuple(record for record in self.records if record.owns_path(normalized))

    def record_for_subsystem(self, subsystem: str) -> RepositoryArchitectureRecord | None:
        normalized = normalize_identifier(subsystem, label="subsystem")
        for record in self.records:
            if record.subsystem == normalized:
                return record
        return None

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "memory_id": self.memory_id,
            "record_count": self.record_count,
            "subsystem_ids": list(self.subsystem_ids),
            "records": [record.to_dict() for record in self.records],
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


def build_architecture_memory(
    snapshot: RepositorySnapshot | None = None,
    coverage_map: RepositoryCoverageMap | None = None,
    *,
    memory_id: str = "wave-8-architecture-memory",
) -> ArchitectureMemorySnapshot:
    records = list(default_architecture_records())
    records.extend(discovered_architecture_records(coverage_map, records))

    return ArchitectureMemorySnapshot(
        memory_id=memory_id,
        records=tuple(records),
        metadata=build_architecture_memory_metadata(
            records=records,
            snapshot=snapshot,
            coverage_map=coverage_map,
        ),
    )


def default_architecture_records() -> tuple[RepositoryArchitectureRecord, ...]:
    return (
        RepositoryArchitectureRecord(
            record_id="repo-governance-boundary",
            subsystem="repo-governance",
            owned_paths=(
                ".blackfox-workspace",
                ".editorconfig",
                ".gitattributes",
                ".github",
                ".gitignore",
                "COMMERCIAL.md",
                "LICENSE",
                "NOTICE.md",
                "README.md",
                "blackfox.policy.toml",
                "pyproject.toml",
            ),
            responsibilities=(
                "Preserve repository policy, licensing, package metadata, public positioning, and review surfaces.",
                "Keep source-available and human-authority claims explicit when governance files change.",
            ),
            constraints=(
                "Do not weaken license, commercial-use, human-review, or non-production language without explicit human review.",
                "Repository metadata changes require impact analysis because they can affect adoption, CI, packaging, or legal posture.",
            ),
            evidence_expectations=(
                "Policy, license, packaging, README, and workflow-adjacent changes must produce reviewable impact findings.",
                "Evidence reports must distinguish implementation proof from positioning or roadmap claims.",
            ),
        ),
        RepositoryArchitectureRecord(
            record_id="ci-workflows-boundary",
            subsystem="ci-workflows",
            owned_paths=(".github/workflows",),
            responsibilities=(
                "Run deterministic validation workflows for tests, typing, linting, and wave-specific evidence generation.",
                "Expose CI-bound evidence artifacts without depending on live model credentials or network-only behavior.",
            ),
            constraints=(
                "Workflow changes must not bypass tests, hide failures, or convert hard failures into silent success.",
                "Wave evidence workflows must stay deterministic, offline-capable, and artifact-producing.",
            ),
            evidence_expectations=(
                "Workflow changes require targeted CI tests plus human-reviewable reasons for any validation-surface change.",
                "Wave 8 repository-intelligence workflows must export structured JSON evidence.",
            ),
        ),
        RepositoryArchitectureRecord(
            record_id="scripts-boundary",
            subsystem="scripts",
            owned_paths=("scripts",),
            responsibilities=(
                "Provide operator-run validation and evidence-export entry points for local and CI use.",
                "Keep script behavior explicit, deterministic, and fail-closed when required evidence is missing.",
            ),
            constraints=(
                "Scripts must not mutate repository source unexpectedly.",
                "Scripts must not require secrets or live model calls for baseline validation.",
            ),
            evidence_expectations=(
                "Script outputs must be machine-readable where they feed CI evidence.",
                "Scripts that create artifacts must report output paths and pass/fail status.",
            ),
        ),
        RepositoryArchitectureRecord(
            record_id="runtime-boundary",
            subsystem="runtime",
            owned_paths=("src/ix_blackfox/runtime", "tests/runtime"),
            responsibilities=(
                "Coordinate governed execution, repair evidence, verification summaries, receipts, and operator-readable runtime reports.",
                "Treat model output as untrusted input until policy, evidence, and human-review gates decide otherwise.",
            ),
            constraints=(
                "Runtime flows must not bypass policy gates, receipt generation, or human authorization boundaries.",
                "Runtime changes require especially strong impact analysis because they affect the code-change control plane.",
            ),
            evidence_expectations=(
                "Runtime changes must identify affected receipts, verification summaries, and operator-facing evidence.",
                "Recommended tests must include runtime tests and any wave-specific CI reports touched by the change.",
            ),
        ),
        RepositoryArchitectureRecord(
            record_id="brains-boundary",
            subsystem="brains",
            owned_paths=("src/ix_blackfox/brains", "tests/brains"),
            responsibilities=(
                "Represent provider-agnostic model routing, model roles, scoring, budget controls, and candidate selection boundaries.",
                "Keep model comparison separate from final authority over repository mutation.",
            ),
            constraints=(
                "No model role may self-approve its own repair candidate.",
                "Provider abstraction must not erase evidence about which model role produced, reviewed, rejected, or blocked a candidate.",
            ),
            evidence_expectations=(
                "Brain/provider changes must preserve selected, rejected, blocked, and review-role evidence.",
                "Routing changes must report budget, provider, and role-separation impact.",
            ),
        ),
        RepositoryArchitectureRecord(
            record_id="authoring-boundary",
            subsystem="authoring",
            owned_paths=("src/ix_blackfox/authoring", "tests/authoring"),
            responsibilities=(
                "Build bounded patch authoring, task decomposition, repair context, and model-facing work-package structures.",
                "Convert repository knowledge into reviewable context without silently changing source files.",
            ),
            constraints=(
                "Authoring code must not perform silent mutation.",
                "Patch planning must remain evidence-bound and human-reviewable.",
            ),
            evidence_expectations=(
                "Authoring changes must report affected patch-planning and repair-context behavior.",
                "Wave 8 repository intelligence should feed authoring context only as bounded evidence, not as assumed truth.",
            ),
        ),
        RepositoryArchitectureRecord(
            record_id="workflow-boundary",
            subsystem="workflow",
            owned_paths=("src/ix_blackfox/workflow", "tests/workflow"),
            responsibilities=(
                "Represent pull-request gates, approval posture, evidence packs, organization-grade review flow, and CI handoff.",
                "Keep AI-assisted code-change workflows inspectable before humans are asked to approve them.",
            ),
            constraints=(
                "Workflow gates must not be weakened by convenience paths.",
                "Approval and evidence-pack behavior must remain explicit and reviewable.",
            ),
            evidence_expectations=(
                "Workflow changes must identify affected PR-gate, approval, and evidence-pack behavior.",
                "Impact reports must escalate approval-surface changes for human review.",
            ),
        ),
        RepositoryArchitectureRecord(
            record_id="sandbox-boundary",
            subsystem="sandbox",
            owned_paths=("src/ix_blackfox/sandbox", "tests/sandbox"),
            responsibilities=(
                "Constrain workspace execution, repository boundaries, isolated workspaces, artifact handling, and safety limits.",
                "Prevent patch-test-verify flows from escaping the intended reviewable workspace.",
            ),
            constraints=(
                "Sandbox changes must not expand filesystem, process, network, or artifact authority without explicit review.",
                "Workspace-boundary failures must remain hard failures.",
            ),
            evidence_expectations=(
                "Sandbox changes require impact findings that call out authority, isolation, and artifact-handling effects.",
                "Recommended tests must include sandbox and workspace-boundary coverage.",
            ),
        ),
        RepositoryArchitectureRecord(
            record_id="governance-boundary",
            subsystem="governance",
            owned_paths=("src/ix_blackfox/governance", "tests/governance"),
            responsibilities=(
                "Evaluate policy gates, fail-closed decisions, constraints, and governance outcomes.",
                "Enforce the separation between proposed model action and authorized human decision.",
            ),
            constraints=(
                "Governance failures must not degrade into warnings when the policy requires denial.",
                "Policy-gate logic must remain inspectable and test-backed.",
            ),
            evidence_expectations=(
                "Governance changes must produce policy-impact findings and human-review requirements when gates are affected.",
                "Recommended tests must include governance and any workflow/runtime tests that consume gate decisions.",
            ),
        ),
        RepositoryArchitectureRecord(
            record_id="forge-boundary",
            subsystem="forge",
            owned_paths=("src/ix_blackfox/forge", "tests/forge"),
            responsibilities=(
                "Assemble, validate, and describe patch candidates, bundles, receipts, and repair artifacts.",
                "Keep candidate material explicit rather than allowing hidden mutation or untracked edits.",
            ),
            constraints=(
                "Forge changes must preserve explicit candidate identity and artifact traceability.",
                "Patch bundle generation must remain reproducible from recorded inputs.",
            ),
            evidence_expectations=(
                "Forge changes must report affected bundle, receipt, and candidate-validation behavior.",
                "Impact reports must identify tests that cover patch artifact integrity.",
            ),
        ),
        RepositoryArchitectureRecord(
            record_id="memory-boundary",
            subsystem="memory",
            owned_paths=("src/ix_blackfox/memory", "tests/memory"),
            responsibilities=(
                "Represent bounded memory, stored facts, prior decisions, and recall surfaces used by governed workflows.",
                "Avoid stale or poisoned memory becoming unreviewed authority over code-change decisions.",
            ),
            constraints=(
                "Memory outputs must not outrank current repository evidence.",
                "Memory changes must preserve provenance, staleness awareness, and reviewability.",
            ),
            evidence_expectations=(
                "Memory changes must explain provenance and staleness effects.",
                "Impact reports must identify any affected recall, summarization, or prior-decision behavior.",
            ),
        ),
        RepositoryArchitectureRecord(
            record_id="vault-boundary",
            subsystem="vault",
            owned_paths=("src/ix_blackfox/vault", "tests/vault"),
            responsibilities=(
                "Protect sensitive local state, secret-handling surfaces, and data that must not leak into logs or evidence bundles.",
                "Keep evidence useful without exposing protected material.",
            ),
            constraints=(
                "Vault changes must not log, serialize, or export secrets accidentally.",
                "Secret-handling changes require explicit human review.",
            ),
            evidence_expectations=(
                "Vault changes must create security-relevant impact findings.",
                "Recommended tests must include redaction, serialization, and protected-state behavior where available.",
            ),
        ),
        RepositoryArchitectureRecord(
            record_id="sentinel-boundary",
            subsystem="sentinel",
            owned_paths=("src/ix_blackfox/sentinel", "tests/sentinel"),
            responsibilities=(
                "Detect contradictions, unsafe assumptions, policy conflicts, and evidence-quality concerns.",
                "Keep sentinel findings separate from final authorization while still forcing review attention.",
            ),
            constraints=(
                "Sentinel findings must not be silently dropped when they affect governance or safety claims.",
                "Contradiction detection must remain bounded and explainable.",
            ),
            evidence_expectations=(
                "Sentinel changes must identify affected contradiction, safety, and evidence-quality checks.",
                "Impact reports must recommend sentinel tests when safety-gate behavior is touched.",
            ),
        ),
        RepositoryArchitectureRecord(
            record_id="repository-boundary",
            subsystem="repository",
            owned_paths=("src/ix_blackfox/repository", "tests/repository"),
            responsibilities=(
                "Build Wave 8 repository intelligence: inventory, code graph, dependency mapping, coverage mapping, architectural memory, impact analysis, and evidence export.",
                "Make repository-change boundaries inspectable before AI-assisted repair or human review.",
            ),
            constraints=(
                "Repository intelligence must be conservative and must not claim perfect architectural understanding.",
                "Repository analysis must not import or execute repository modules while scanning.",
            ),
            evidence_expectations=(
                "Repository-intelligence changes must produce digestable reports and targeted repository tests.",
                "Wave 8 reports must clearly separate observed facts from inferred impact.",
            ),
        ),
        RepositoryArchitectureRecord(
            record_id="reliability-boundary",
            subsystem="reliability",
            owned_paths=("src/ix_blackfox/reliability", "tests/reliability"),
            responsibilities=(
                "Represent scenario suites, adversarial tests, repair metrics, and reliability-lab evidence.",
                "Keep reliability claims tied to measured scenario outputs rather than general confidence language.",
            ),
            constraints=(
                "Reliability changes must not reduce adversarial or scenario coverage without explicit review.",
                "Metrics must remain bounded to what the tests actually measure.",
            ),
            evidence_expectations=(
                "Reliability changes must identify affected scenario, metric, and adversarial-test behavior.",
                "Impact reports must recommend reliability tests when scenario or metric surfaces change.",
            ),
        ),
        RepositoryArchitectureRecord(
            record_id="interface-boundary",
            subsystem="interface",
            owned_paths=("src/ix_blackfox/interface", "tests/interface"),
            responsibilities=(
                "Expose command-line and operator-facing surfaces for governed runtime, reports, and local evidence review.",
                "Keep outputs understandable while preserving machine-readable evidence for CI and audits.",
            ),
            constraints=(
                "Interface changes must not hide failure state or omit critical review warnings.",
                "CLI output must remain stable enough for tests and operator workflows.",
            ),
            evidence_expectations=(
                "Interface changes must identify affected commands, output schemas, and operator summaries.",
                "Recommended tests must include CLI or interface coverage when command surfaces change.",
            ),
        ),
        RepositoryArchitectureRecord(
            record_id="docs-boundary",
            subsystem="docs",
            owned_paths=("docs",),
            responsibilities=(
                "Explain implemented capabilities, evidence boundaries, non-claims, and operator usage without overstating maturity.",
                "Keep public-facing technical documentation aligned with actual tested behavior.",
            ),
            constraints=(
                "Documentation must not claim production readiness, certification, official affiliation, autonomous authority, or perfect correctness.",
                "Roadmap language must remain distinct from implemented capability language.",
            ),
            evidence_expectations=(
                "Documentation changes must be checked against implemented files and tests.",
                "Impact reports must flag public-claim changes for human review when they alter capability positioning.",
            ),
        ),
    )


def discovered_architecture_records(
    coverage_map: RepositoryCoverageMap | None,
    existing_records: Sequence[RepositoryArchitectureRecord],
) -> tuple[RepositoryArchitectureRecord, ...]:
    if coverage_map is None:
        return ()

    existing_subsystems = {record.subsystem for record in existing_records}
    records: list[RepositoryArchitectureRecord] = []

    for subsystem in coverage_map.subsystems:
        if subsystem.subsystem in existing_subsystems:
            continue
        if subsystem.file_count == 0:
            continue
        records.append(
            RepositoryArchitectureRecord(
                record_id=f"{subsystem.subsystem}-discovered-boundary",
                subsystem=subsystem.subsystem,
                owned_paths=subsystem.owned_paths,
                responsibilities=(
                    "Preserve the discovered subsystem boundary identified by repository coverage mapping.",
                    "Keep source, tests, documentation, and sensitive review surfaces tied to explicit impact evidence.",
                ),
                constraints=(
                    "Discovered subsystem ownership must not be treated as perfect architecture knowledge.",
                    "Changes under this boundary still require repository evidence and human review when sensitive paths are affected.",
                ),
                evidence_expectations=(
                    "Impact reports must list affected source, tests, and sensitive paths for this discovered subsystem.",
                ),
                metadata={"discovered_from_coverage_map": True},
            )
        )

    return tuple(records)


def build_architecture_memory_metadata(
    *,
    records: Sequence[RepositoryArchitectureRecord],
    snapshot: RepositorySnapshot | None,
    coverage_map: RepositoryCoverageMap | None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "record_count": len(records),
        "wave": 8,
        "source": "default-wave-8-architecture-memory",
        "coverage_map_digest": coverage_map.digest if coverage_map is not None else None,
    }

    if snapshot is None:
        metadata.update(
            {
                "snapshot_digest": None,
                "source_path_count": 0,
                "owned_source_path_count": 0,
                "unowned_source_paths": [],
                "sensitive_path_count": 0,
                "owned_sensitive_path_count": 0,
                "unowned_sensitive_paths": [],
            }
        )
        return metadata

    source_paths = tuple(
        record.path
        for record in snapshot.files
        if record.role is RepositoryFileRole.SOURCE
    )
    sensitive_paths = tuple(
        record.path
        for record in snapshot.files
        if record.sensitivity is not RepositorySensitivity.NORMAL
    )
    owned_source_paths = owned_paths_from_records(source_paths, records)
    owned_sensitive_paths = owned_paths_from_records(sensitive_paths, records)

    metadata.update(
        {
            "snapshot_digest": snapshot.digest,
            "source_path_count": len(source_paths),
            "owned_source_path_count": len(owned_source_paths),
            "unowned_source_paths": sorted(set(source_paths) - set(owned_source_paths)),
            "sensitive_path_count": len(sensitive_paths),
            "owned_sensitive_path_count": len(owned_sensitive_paths),
            "unowned_sensitive_paths": sorted(
                set(sensitive_paths) - set(owned_sensitive_paths)
            ),
        }
    )
    return metadata


def owned_paths_from_records(
    candidate_paths: Sequence[str],
    records: Sequence[RepositoryArchitectureRecord],
) -> tuple[str, ...]:
    owned: list[str] = []
    for candidate_path in candidate_paths:
        normalized = normalize_relative_path(candidate_path)
        if any(record.owns_path(normalized) for record in records):
            owned.append(normalized)
    return tuple(sorted(set(owned)))


def architecture_records_for_path(
    records: Sequence[RepositoryArchitectureRecord],
    path: str,
) -> tuple[RepositoryArchitectureRecord, ...]:
    normalized = normalize_relative_path(path)
    return tuple(record for record in records if record.owns_path(normalized))


def architecture_records_by_subsystem(
    records: Sequence[RepositoryArchitectureRecord],
) -> dict[str, RepositoryArchitectureRecord]:
    return {record.subsystem: record for record in records}


def architecture_memory_summary(
    memory: ArchitectureMemorySnapshot,
) -> dict[str, Any]:
    return {
        "memory_id": memory.memory_id,
        "record_count": memory.record_count,
        "subsystem_ids": list(memory.subsystem_ids),
        "digest": memory.digest,
        "unowned_source_paths": list(memory.metadata.get("unowned_source_paths", [])),
        "unowned_sensitive_paths": list(
            memory.metadata.get("unowned_sensitive_paths", [])
        ),
    }


def validate_architecture_memory(
    memory: ArchitectureMemorySnapshot,
) -> dict[str, Any]:
    warnings: list[str] = []

    for record in memory.records:
        if not record.constraints:
            warnings.append(f"{record.record_id} has no constraints.")
        if not record.evidence_expectations:
            warnings.append(f"{record.record_id} has no evidence expectations.")
        if not record.owned_paths:
            warnings.append(f"{record.record_id} owns no paths.")

    unowned_source_paths = tuple(memory.metadata.get("unowned_source_paths", ()))
    unowned_sensitive_paths = tuple(memory.metadata.get("unowned_sensitive_paths", ()))

    return {
        "valid": not warnings,
        "warnings": warnings,
        "record_count": memory.record_count,
        "unowned_source_path_count": len(unowned_source_paths),
        "unowned_sensitive_path_count": len(unowned_sensitive_paths),
        "digest": memory.digest,
    }
