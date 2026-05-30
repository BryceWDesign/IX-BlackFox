from __future__ import annotations

import pytest

from ix_blackfox.operating import (
    CampaignDependencyGraph,
    CampaignPhase,
    CampaignPhaseStatus,
    EvidenceRequirement,
    OperatingArtifactKind,
    OperatingCampaign,
    OperatingDisposition,
    OperatingDomain,
    OperatingSourceWave,
    OperatingWorkPackage,
    RequiredValidation,
    RollbackRequirement,
    ValidationKind,
    WorkPackageDependency,
    WorkPackageDependencyKind,
    WorkPackageStatus,
)


def test_operating_campaign_builds_deterministic_ready_graph() -> None:
    registry = _package("registry-foundation", status=WorkPackageStatus.COMPLETED)
    authority = _package("team-authority", dependency_ids=("registry-before-authority",))
    dependency = WorkPackageDependency(
        dependency_id="registry-before-authority",
        source_work_package_id="team-authority",
        target_work_package_id="registry-foundation",
        kind=WorkPackageDependencyKind.REQUIRES,
        rationale="Team authority requires the multi-repo registry foundation first.",
    )
    campaign = OperatingCampaign(
        campaign_id=" Wave 10 Operating System ",
        title="Wave 10 AI engineering operating system",
        objective="Compose governed work packages into a multi-repo operating campaign.",
        registry_id="Wave 10 Registry",
        board_id="Wave 10 Board",
        work_packages=(authority, registry),
        phases=(
            CampaignPhase(
                phase_id="foundation",
                title="Foundation",
                objective="Create the registry and authority foundation.",
                work_package_ids=("registry-foundation", "team-authority"),
                status=CampaignPhaseStatus.READY_FOR_REVIEW,
                exit_criteria=("registry evidence attached", "human review required"),
            ),
        ),
        dependencies=(dependency,),
    )
    same_campaign = OperatingCampaign(
        campaign_id="wave-10-operating-system",
        title="Wave 10 AI engineering operating system",
        objective="Compose governed work packages into a multi-repo operating campaign.",
        registry_id="wave-10-registry",
        board_id="wave-10-board",
        work_packages=(registry, authority),
        phases=(
            CampaignPhase(
                phase_id="foundation",
                title="Foundation",
                objective="Create the registry and authority foundation.",
                work_package_ids=("team-authority", "registry-foundation"),
                status=CampaignPhaseStatus.READY_FOR_REVIEW,
                exit_criteria=("human review required", "registry evidence attached"),
            ),
        ),
        dependencies=(dependency,),
    )

    assert campaign.campaign_id == "wave-10-operating-system"
    assert campaign.registry_id == "wave-10-registry"
    assert campaign.board_id == "wave-10-board"
    assert campaign.repository_ids == ("ix-blackfox",)
    assert campaign.owner_team_ids == ("platform-security",)
    assert campaign.graph.prerequisites_for("team-authority") == ("registry-foundation",)
    assert campaign.graph.dependents_of("registry-foundation") == ("team-authority",)
    assert campaign.graph.ready_work_package_ids(("registry-foundation",)) == ("team-authority",)
    assert campaign.graph.topological_order() == ("registry-foundation", "team-authority")
    assert campaign.validation_report.passed is True
    assert campaign.findings == ()
    assert campaign.to_envelope().disposition is OperatingDisposition.READY
    assert campaign.to_dict()["digest"] == same_campaign.to_dict()["digest"]


def test_operating_campaign_blocks_blocked_package_phase_gap_and_orphan_package() -> None:
    blocked = _package(
        "blocked-package",
        status=WorkPackageStatus.BLOCKED,
        evidence_satisfied=False,
    )
    orphan = _package("orphan-package")
    campaign = OperatingCampaign(
        campaign_id="blocked-campaign",
        title="Blocked campaign",
        objective="Demonstrate campaign fail-closed behavior.",
        registry_id="wave10-registry",
        work_packages=(blocked, orphan),
        phases=(
            CampaignPhase(
                phase_id="blocked-phase",
                title="Blocked phase",
                objective="This phase contains blocked work.",
                work_package_ids=("blocked-package",),
            ),
        ),
    )

    report = campaign.validation_report
    finding_codes = {finding.code for finding in campaign.findings}
    assert report.passed is False
    assert report.blocked_work_package_ids == ("blocked-package",)
    assert report.phase_gap_ids == ("blocked-phase",)
    assert report.orphan_work_package_ids == ("orphan-package",)
    assert finding_codes == {
        "operating.campaign.blocked-work-package",
        "operating.campaign.orphan-work-package",
        "operating.campaign.phase-gap",
    }
    assert campaign.to_dict()["disposition"] == "blocked"


def test_operating_campaign_warns_when_package_warns_without_blocking() -> None:
    warning_package = _package("warning-package", changed_paths=())
    campaign = OperatingCampaign(
        campaign_id="warning-campaign",
        title="Warning campaign",
        objective="Demonstrate warning-level package propagation.",
        registry_id="wave10-registry",
        work_packages=(warning_package,),
        phases=(
            CampaignPhase(
                phase_id="warning-phase",
                title="Warning phase",
                objective="This phase contains warning-level work.",
                work_package_ids=("warning-package",),
            ),
        ),
    )

    assert campaign.validation_report.passed is True
    assert campaign.validation_report.warning_work_package_ids == ("warning-package",)
    assert {finding.code for finding in campaign.findings} == {
        "operating.campaign.warning-work-package",
    }
    assert campaign.to_envelope().disposition is OperatingDisposition.WARNING


def test_campaign_dependency_graph_detects_cycles_and_unknown_dependencies() -> None:
    first = WorkPackageDependency(
        dependency_id="first-to-second",
        source_work_package_id="first",
        target_work_package_id="second",
        kind=WorkPackageDependencyKind.REQUIRES,
        rationale="First requires second.",
    )
    second = WorkPackageDependency(
        dependency_id="second-to-first",
        source_work_package_id="second",
        target_work_package_id="first",
        kind=WorkPackageDependencyKind.REQUIRES,
        rationale="Second requires first.",
    )
    graph = CampaignDependencyGraph(
        work_package_ids=("first", "second"),
        dependencies=(second, first),
    )

    assert graph.has_cycle is True
    assert graph.topological_order() == ()
    assert graph.cycle_path()[0] == graph.cycle_path()[-1]

    missing = WorkPackageDependency(
        dependency_id="missing",
        source_work_package_id="first",
        target_work_package_id="missing",
        kind=WorkPackageDependencyKind.REQUIRES,
        rationale="Missing dependency should fail.",
    )
    with pytest.raises(ValueError, match="unknown work package"):
        CampaignDependencyGraph(work_package_ids=("first",), dependencies=(missing,))


def test_operating_campaign_blocks_dependency_cycle() -> None:
    first = _package("first")
    second = _package("second")
    campaign = OperatingCampaign(
        campaign_id="cycle-campaign",
        title="Cycle campaign",
        objective="Detect dependency cycles before review.",
        registry_id="wave10-registry",
        work_packages=(first, second),
        phases=(
            CampaignPhase(
                phase_id="cycle-phase",
                title="Cycle phase",
                objective="Contains cyclic dependencies.",
                work_package_ids=("first", "second"),
            ),
        ),
        dependencies=(
            WorkPackageDependency(
                dependency_id="first-to-second",
                source_work_package_id="first",
                target_work_package_id="second",
                kind=WorkPackageDependencyKind.REQUIRES,
                rationale="First requires second.",
            ),
            WorkPackageDependency(
                dependency_id="second-to-first",
                source_work_package_id="second",
                target_work_package_id="first",
                kind=WorkPackageDependencyKind.REQUIRES,
                rationale="Second requires first.",
            ),
        ),
    )

    assert campaign.validation_report.passed is False
    assert campaign.validation_report.cycle_path[0] == campaign.validation_report.cycle_path[-1]
    assert "operating.campaign.dependency-cycle" in {finding.code for finding in campaign.findings}
    assert campaign.to_envelope().disposition is OperatingDisposition.BLOCKED


def test_operating_campaign_rejects_unknown_phase_package_and_prior_phase() -> None:
    package = _package("known-package")

    with pytest.raises(ValueError, match="unknown work package"):
        OperatingCampaign(
            campaign_id="unknown-package",
            title="Unknown package",
            objective="This should fail.",
            registry_id="wave10-registry",
            work_packages=(package,),
            phases=(
                CampaignPhase(
                    phase_id="phase",
                    title="Phase",
                    objective="References a missing package.",
                    work_package_ids=("missing-package",),
                ),
            ),
        )

    with pytest.raises(ValueError, match="unknown prior phase"):
        OperatingCampaign(
            campaign_id="unknown-phase",
            title="Unknown phase",
            objective="This should fail.",
            registry_id="wave10-registry",
            work_packages=(package,),
            phases=(
                CampaignPhase(
                    phase_id="phase",
                    title="Phase",
                    objective="References a missing prior phase.",
                    work_package_ids=("known-package",),
                    required_prior_phase_ids=("missing-phase",),
                ),
            ),
        )


def _package(
    work_package_id: str,
    *,
    status: WorkPackageStatus = WorkPackageStatus.READY_FOR_REVIEW,
    changed_paths: tuple[str, ...] = ("src/ix_blackfox/operating/campaign.py",),
    dependency_ids: tuple[str, ...] = (),
    evidence_satisfied: bool = True,
) -> OperatingWorkPackage:
    artifact_ids = ("wave10-campaign-evidence",) if evidence_satisfied else ()
    return OperatingWorkPackage(
        work_package_id=work_package_id,
        title=f"{work_package_id} work package",
        objective="Bind one Wave 10 campaign unit to evidence, validation, and rollback.",
        repository_ids=("ix-blackfox",),
        owner_team_id="platform-security",
        author_id="model-proposer",
        domains=(OperatingDomain.MULTI_REPO, OperatingDomain.REVIEWABLE),
        status=status,
        changed_paths=changed_paths,
        evidence_requirements=(
            EvidenceRequirement(
                requirement_id="campaign-evidence",
                artifact_kind=OperatingArtifactKind.CAMPAIGN_GRAPH,
                source_wave=OperatingSourceWave.WAVE10,
                description="Campaign evidence must be attached before review.",
                satisfied_by_artifact_ids=artifact_ids,
            ),
        ),
        required_validations=(
            RequiredValidation(
                validation_id="campaign-tests",
                kind=ValidationKind.UNIT_TEST,
                description="Campaign tests must pass.",
                command=("python", "-m", "pytest", "tests/operating/test_campaign.py"),
                expected_artifact_ids=("pytest-campaign-report",),
                passed=True,
            ),
        ),
        rollback_requirements=(
            RollbackRequirement(
                rollback_id="restore-prior-campaign-state",
                trigger="Campaign validation fails.",
                action="Restore the previous validated operating campaign package.",
                owner_team_id="platform-security",
                evidence_artifact_ids=("rollback-campaign-report",),
                tested=True,
            ),
        ),
        dependency_ids=dependency_ids,
    )
