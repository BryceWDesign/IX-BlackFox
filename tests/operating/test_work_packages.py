from __future__ import annotations

import pytest

from ix_blackfox.operating import (
    EvidenceRequirement,
    ForbiddenAction,
    OperatingArtifactKind,
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


def test_ready_work_package_is_deterministic_and_reviewable() -> None:
    package = _ready_package(
        work_package_id=" Wave 10 Registry Work ",
        changed_paths=(
            "tests/operating/test_work_packages.py",
            "src\\ix_blackfox\\operating\\work_packages.py",
        ),
    )
    same_package = _ready_package(
        work_package_id="wave-10-registry-work",
        changed_paths=(
            "src/ix_blackfox/operating/work_packages.py",
            "tests/operating/test_work_packages.py",
        ),
    )

    assert package.work_package_id == "wave-10-registry-work"
    assert package.repository_ids == ("ix-blackfox",)
    assert package.owner_team_id == "platform-security"
    assert package.domains == (
        OperatingDomain.MULTI_REPO,
        OperatingDomain.POLICY_GOVERNED,
        OperatingDomain.REVIEWABLE,
    )
    assert package.changed_paths == (
        "src/ix_blackfox/operating/work_packages.py",
        "tests/operating/test_work_packages.py",
    )
    assert package.findings == ()
    assert package.to_envelope().disposition is OperatingDisposition.READY
    assert package.to_dict()["digest"] == same_package.to_dict()["digest"]


def test_work_package_blocks_missing_evidence_validation_and_rollback() -> None:
    package = OperatingWorkPackage(
        work_package_id="blocked-package",
        title="Blocked work package",
        objective="Demonstrate fail-closed work package gaps.",
        repository_ids=("ix-blackfox",),
        owner_team_id="platform-security",
        author_id="model-proposer",
        domains=(OperatingDomain.MULTI_REPO, OperatingDomain.REVIEWABLE),
        status=WorkPackageStatus.READY_FOR_REVIEW,
        changed_paths=("src/ix_blackfox/operating/work_packages.py",),
        evidence_requirements=(
            EvidenceRequirement(
                requirement_id="wave9-report",
                artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
                source_wave=OperatingSourceWave.WAVE9,
                description="Wave 9 governance report must be attached.",
                mandatory=True,
            ),
        ),
        required_validations=(
            RequiredValidation(
                validation_id="operating-tests",
                kind=ValidationKind.UNIT_TEST,
                description="Operating tests must pass and emit evidence.",
                command=("python", "-m", "pytest", "tests/operating"),
                expected_artifact_ids=("pytest-report",),
                passed=False,
            ),
        ),
        rollback_requirements=(
            RollbackRequirement(
                rollback_id="restore-wave9",
                trigger="Wave 10 gate regression",
                action="Restore previous green Wave 9 tree and evidence artifacts.",
                owner_team_id="platform-security",
                tested=False,
            ),
        ),
    )

    finding_codes = {finding.code for finding in package.findings}
    assert finding_codes == {
        "operating.work_package.missing-evidence",
        "operating.work_package.rollback-gap",
        "operating.work_package.validation-gap",
    }
    assert package.missing_evidence_requirement_ids == ("wave9-report",)
    assert package.failing_validation_ids == ("operating-tests",)
    assert package.untested_rollback_ids == ("restore-wave9",)
    assert package.to_envelope().disposition is OperatingDisposition.BLOCKED


def test_work_package_blocks_forbidden_action_and_blocked_status() -> None:
    package = _ready_package(
        status=WorkPackageStatus.BLOCKED,
        forbidden_actions=(
            ForbiddenAction(
                action_id="silent-mutation",
                description="The work package must not silently mutate files without review.",
                rationale="Wave 10 requires explicit, reviewable work package boundaries.",
                enforcement_refs=("blackfox.policy.toml",),
                detected=True,
                evidence_artifact_ids=("policy-evaluation",),
            ),
        ),
    )

    finding_codes = {finding.code for finding in package.findings}
    assert "operating.work_package.blocked-status" in finding_codes
    assert "operating.work_package.forbidden-action-detected" in finding_codes
    assert package.detected_forbidden_action_ids == ("silent-mutation",)
    assert package.to_dict()["disposition"] == "blocked"


def test_work_package_warns_without_changed_paths_but_does_not_block() -> None:
    package = _ready_package(changed_paths=())

    assert {finding.code for finding in package.findings} == {
        "operating.work_package.no-changed-paths",
    }
    assert package.to_envelope().disposition is OperatingDisposition.WARNING


def test_work_package_rejects_duplicate_nested_identifiers() -> None:
    requirement = EvidenceRequirement(
        requirement_id="duplicate",
        artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
        source_wave=OperatingSourceWave.WAVE9,
        description="Duplicate requirement.",
        satisfied_by_artifact_ids=("wave9-report",),
    )

    with pytest.raises(ValueError, match="evidence requirement_id values must be unique"):
        OperatingWorkPackage(
            work_package_id="duplicate-requirements",
            title="Duplicate requirements",
            objective="This should fail.",
            repository_ids=("ix-blackfox",),
            owner_team_id="platform-security",
            author_id="model-proposer",
            domains=(OperatingDomain.MULTI_REPO,),
            evidence_requirements=(requirement, requirement),
        )


def test_work_package_dependency_normalizes_and_rejects_self_dependency() -> None:
    dependency = WorkPackageDependency(
        dependency_id=" Registry before Campaign ",
        source_work_package_id="campaign-graph",
        target_work_package_id="registry-foundation",
        kind=WorkPackageDependencyKind.REQUIRES,
        rationale="Campaign graph requires the registry foundation first.",
    )

    assert dependency.dependency_id == "registry-before-campaign"
    assert dependency.to_dict()["kind"] == "requires"
    assert dependency.to_dict()["required"] is True

    with pytest.raises(ValueError, match="cannot target the source"):
        WorkPackageDependency(
            dependency_id="self",
            source_work_package_id="same",
            target_work_package_id="same",
            kind=WorkPackageDependencyKind.REQUIRES,
            rationale="Self dependencies are not useful operating evidence.",
        )


def _ready_package(
    *,
    work_package_id: str = "wave10-work-package",
    status: WorkPackageStatus = WorkPackageStatus.READY_FOR_REVIEW,
    changed_paths: tuple[str, ...] = ("src/ix_blackfox/operating/work_packages.py",),
    forbidden_actions: tuple[ForbiddenAction, ...] = (),
) -> OperatingWorkPackage:
    return OperatingWorkPackage(
        work_package_id=work_package_id,
        title="Wave 10 work package foundation",
        objective="Create bounded, evidence-driven work packages for AI engineering operations.",
        repository_ids=("IX-BlackFox",),
        owner_team_id="Platform Security",
        author_id="model-proposer",
        domains=(
            OperatingDomain.REVIEWABLE,
            OperatingDomain.MULTI_REPO,
            OperatingDomain.POLICY_GOVERNED,
        ),
        status=status,
        changed_paths=changed_paths,
        evidence_requirements=(
            EvidenceRequirement(
                requirement_id="wave9-governance-report",
                artifact_kind=OperatingArtifactKind.OPERATING_REPORT,
                source_wave=OperatingSourceWave.WAVE9,
                description="Wave 9 governance report remains attached to the package.",
                satisfied_by_artifact_ids=("wave9-governance-report",),
            ),
        ),
        required_validations=(
            RequiredValidation(
                validation_id="operating-tests",
                kind=ValidationKind.UNIT_TEST,
                description="Operating package tests must pass.",
                command=("python", "-m", "pytest", "tests/operating"),
                expected_artifact_ids=("pytest-operating-report",),
                passed=True,
            ),
        ),
        rollback_requirements=(
            RollbackRequirement(
                rollback_id="restore-wave9-green",
                trigger="Wave 10 operating regression",
                action="Restore the last known green Wave 9 tree and evidence artifacts.",
                owner_team_id="platform-security",
                evidence_artifact_ids=("rollback-test-report",),
                tested=True,
            ),
        ),
        forbidden_actions=forbidden_actions,
        dependency_ids=("registry-foundation",),
        metadata={"donor_pattern": "ix-blackfox-cognition.work_packages"},
    )
