from __future__ import annotations

import hashlib

import pytest

from ix_blackfox.operating import (
    ManagedRepository,
    OperatingArtifactKind,
    OperatingArtifactRef,
    OperatingDisposition,
    OperatingRegistry,
    OperatingSourceWave,
    RepositoryDependency,
    RepositoryDependencyKind,
    RepositoryEvidenceState,
    RepositoryPolicyBinding,
    RepositoryRiskLevel,
    RepositoryRiskSurface,
    RepositoryRole,
)


def test_managed_repository_normalizes_roles_policy_evidence_and_risk() -> None:
    repository = ManagedRepository(
        repository_id=" IX BlackFox ",
        name="  IX-BlackFox  ",
        root_path=" repos\\IX-BlackFox ",
        owner_team_id=" Platform Security ",
        roles=(
            RepositoryRole.GOVERNED_REPOSITORY,
            RepositoryRole.CONTROL_PLANE,
            RepositoryRole.GOVERNED_REPOSITORY,
        ),
        policy_bindings=(
            RepositoryPolicyBinding(
                policy_id=" Core Governance ",
                policy_pack="Wave 10 Operating Controls",
                version="v1",
                path="policies/wave10/core.json",
                required_controls=("human authority", "policy gate", "human authority"),
            ),
        ),
        evidence_state=RepositoryEvidenceState(
            repository_id="ix-blackfox",
            artifacts=(_artifact("wave9-governance-report"),),
            verified=True,
        ),
        risk_surface=RepositoryRiskSurface(
            repository_id="ix-blackfox",
            handles_secrets=True,
            internet_exposed=True,
            production_touching=True,
            third_party_dependencies=True,
        ),
        description="  Governed AI engineering control plane.  ",
    )

    assert repository.repository_id == "ix-blackfox"
    assert repository.root_path == "repos/IX-BlackFox"
    assert repository.owner_team_id == "platform-security"
    assert repository.roles == (
        RepositoryRole.CONTROL_PLANE,
        RepositoryRole.GOVERNED_REPOSITORY,
    )
    assert repository.policy_bindings[0].required_controls == (
        "human authority",
        "policy gate",
    )
    assert repository.has_policy_coverage is True
    assert repository.has_verified_evidence is True
    assert repository.risk_level is RepositoryRiskLevel.CRITICAL
    assert repository.to_dict()["description"] == "Governed AI engineering control plane."


def test_repository_risk_surface_promotes_critical_risk_for_high_consequence_repos() -> None:
    risk = RepositoryRiskSurface(
        repository_id="autonomy-assurance",
        handles_secrets=True,
        internet_exposed=True,
        production_touching=True,
        safety_critical=True,
        regulated_data=True,
        third_party_dependencies=True,
    )

    assert risk.risk_score == 14
    assert risk.risk_level is RepositoryRiskLevel.CRITICAL
    assert risk.to_dict()["risk_level"] == "critical"


def test_operating_registry_orders_repositories_edges_findings_and_digest() -> None:
    blackfox = _ready_repository("ix-blackfox", RepositoryRole.CONTROL_PLANE)
    cognition = _ready_repository("ix-blackfox-cognition", RepositoryRole.EVIDENCE_PRODUCER)
    dependency = RepositoryDependency(
        dependency_id="cognition-handoff",
        source_repository_id="ix-blackfox",
        target_repository_id="ix-blackfox-cognition",
        kind=RepositoryDependencyKind.PRODUCES_EVIDENCE_FOR,
        rationale="Cognition work packages feed BlackFox operating governance.",
    )

    registry = OperatingRegistry(
        registry_id=" Wave 10 Registry ",
        repositories=(cognition, blackfox),
        dependencies=(dependency,),
    )
    same_registry = OperatingRegistry(
        registry_id="wave-10-registry",
        repositories=(blackfox, cognition),
        dependencies=(dependency,),
    )

    assert registry.registry_id == "wave-10-registry"
    assert registry.repository_ids == ("ix-blackfox", "ix-blackfox-cognition")
    assert registry.dependency_edges() == (
        ("ix-blackfox", "ix-blackfox-cognition", "produces_evidence_for"),
    )
    assert registry.repositories_by_role(RepositoryRole.CONTROL_PLANE) == (blackfox,)
    assert registry.findings == ()
    assert registry.to_envelope().disposition is OperatingDisposition.READY
    assert registry.to_dict()["digest"] == same_registry.to_dict()["digest"]


def test_operating_registry_blocks_missing_policy_and_unverified_evidence() -> None:
    repository = ManagedRepository(
        repository_id="uncovered-repo",
        name="Uncovered Repo",
        root_path="repos/uncovered",
        owner_team_id="security-team",
        roles=(RepositoryRole.GOVERNED_REPOSITORY,),
        evidence_state=RepositoryEvidenceState(
            repository_id="uncovered-repo",
            artifacts=(_artifact("stale-report"),),
            stale_artifact_ids=("stale-report",),
            verified=False,
        ),
    )

    registry = OperatingRegistry(registry_id="blocked", repositories=(repository,))

    finding_codes = {finding.code for finding in registry.findings}
    assert finding_codes == {
        "operating.registry.evidence-gap",
        "operating.registry.missing-policy-coverage",
        "operating.registry.missing-verified-evidence",
    }
    assert registry.to_envelope().disposition is OperatingDisposition.BLOCKED
    assert registry.to_dict()["disposition"] == "blocked"


def test_operating_registry_rejects_duplicate_repository_ids_and_unknown_dependencies() -> None:
    first = _ready_repository("ix-blackfox", RepositoryRole.CONTROL_PLANE)
    duplicate = _ready_repository(" IX_BlackFox ", RepositoryRole.GOVERNED_REPOSITORY)

    with pytest.raises(ValueError, match="repository_id values must be unique"):
        OperatingRegistry(registry_id="duplicate", repositories=(first, duplicate))

    dependency = RepositoryDependency(
        dependency_id="missing-target",
        source_repository_id="ix-blackfox",
        target_repository_id="missing-repo",
        kind=RepositoryDependencyKind.BUILDS_ON,
        rationale="This should fail because the target is not registered.",
    )

    with pytest.raises(ValueError, match="unregistered repository"):
        OperatingRegistry(
            registry_id="unknown-dependency",
            repositories=(first,),
            dependencies=(dependency,),
        )


def test_repository_evidence_state_rejects_stale_artifacts_not_in_inventory() -> None:
    with pytest.raises(ValueError, match="stale artifact ids are not registered"):
        RepositoryEvidenceState(
            repository_id="ix-blackfox",
            artifacts=(_artifact("registered"),),
            stale_artifact_ids=("missing",),
            verified=False,
        )


def _ready_repository(repository_id: str, role: RepositoryRole) -> ManagedRepository:
    normalized = repository_id.strip().lower().replace("_", "-").replace(" ", "-")
    artifact = _artifact(f"{normalized}-evidence")
    return ManagedRepository(
        repository_id=repository_id,
        name=repository_id,
        root_path=f"repos/{normalized}",
        owner_team_id="platform-security",
        roles=(role,),
        policy_bindings=(
            RepositoryPolicyBinding(
                policy_id=f"{normalized}-policy",
                policy_pack="Wave 10 Operating Controls",
                version="v1",
                path=f"policies/{normalized}.json",
                required_controls=("human authority", "evidence chain"),
            ),
        ),
        evidence_state=RepositoryEvidenceState(
            repository_id=repository_id,
            artifacts=(artifact,),
            verified=True,
        ),
        risk_surface=RepositoryRiskSurface(repository_id=repository_id),
    )


def _artifact(artifact_id: str) -> OperatingArtifactRef:
    normalized = artifact_id.strip().lower().replace("_", "-").replace(" ", "-")
    return OperatingArtifactRef(
        artifact_id=artifact_id,
        kind=OperatingArtifactKind.EVIDENCE_MANIFEST,
        source_wave=OperatingSourceWave.WAVE10,
        path=f"artifacts/{normalized}.json",
        sha256=hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        producer="IX-BlackFox Wave 10 operating registry tests",
    )
