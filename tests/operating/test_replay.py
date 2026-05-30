from __future__ import annotations

import hashlib

import pytest

from ix_blackfox.operating import (
    OperatingArtifactKind,
    OperatingArtifactRef,
    OperatingDisposition,
    OperatingSourceWave,
    ReplayCommand,
    ReplayEnvironment,
    ReplayManifest,
    ReplayStep,
    ReplayValidationResult,
)


def test_replay_manifest_is_deterministic_and_orders_steps() -> None:
    manifest = _ready_manifest()
    same_manifest = ReplayManifest(
        manifest_id="wave-10-replay",
        campaign_id="wave-10-campaign",
        repository_ids=("ix-blackfox",),
        environment=_environment(),
        artifacts=(_artifact("operating-report"), _artifact("pytest-report"), _artifact("lockfile")),
        steps=(
            _step(
                "report-step",
                expected_artifact_ids=("operating-report",),
                depends_on_step_ids=("test-step",),
                evidence_artifact_ids=("operating-report",),
            ),
            _step("test-step", expected_artifact_ids=("pytest-report",), evidence_artifact_ids=("pytest-report",)),
        ),
        notes=("offline replay",),
    )

    assert manifest.manifest_id == "wave-10-replay"
    assert manifest.repository_ids == ("ix-blackfox",)
    assert manifest.artifact_ids == ("lockfile", "operating-report", "pytest-report")
    assert manifest.required_step_ids == ("report-step", "test-step")
    assert manifest.replay_order == ("test-step", "report-step")
    assert manifest.cycle_path == ()
    assert manifest.findings == ()
    assert manifest.to_envelope().disposition is OperatingDisposition.READY
    assert manifest.to_dict()["digest"] == same_manifest.to_dict()["digest"]


def test_replay_manifest_warns_without_dependency_lock() -> None:
    manifest = ReplayManifest(
        manifest_id="unlocked-replay",
        campaign_id="wave-10-campaign",
        repository_ids=("ix-blackfox",),
        environment=ReplayEnvironment(
            environment_id="no-lock",
            runtime="Python 3.11",
            platform="linux",
        ),
        artifacts=(_artifact("pytest-report"),),
        steps=(_step("test-step", expected_artifact_ids=("pytest-report",), evidence_artifact_ids=("pytest-report",)),),
    )

    assert {finding.code for finding in manifest.findings} == {
        "operating.replay.environment-missing-lock-artifact",
    }
    assert manifest.to_envelope().disposition is OperatingDisposition.WARNING


def test_replay_manifest_blocks_network_nondeterministic_missing_evidence_and_cycle() -> None:
    first = ReplayStep(
        step_id="first",
        title="First cyclic step",
        command=ReplayCommand(
            command_id="first-command",
            argv=("python", "-m", "pytest"),
            deterministic=False,
            network_allowed=True,
        ),
        expected_artifact_ids=("pytest-report",),
        depends_on_step_ids=("second",),
        evidence_artifact_ids=(),
    )
    second = _step(
        "second",
        expected_artifact_ids=("operating-report",),
        depends_on_step_ids=("first",),
        evidence_artifact_ids=("operating-report",),
    )
    manifest = ReplayManifest(
        manifest_id="blocked-replay",
        campaign_id="wave-10-campaign",
        repository_ids=("ix-blackfox",),
        environment=_environment(),
        artifacts=(_artifact("lockfile"), _artifact("operating-report"), _artifact("pytest-report")),
        steps=(second, first),
    )

    finding_codes = {finding.code for finding in manifest.findings}
    assert finding_codes == {
        "operating.replay.dependency-cycle",
        "operating.replay.network-required",
        "operating.replay.nondeterministic-command",
        "operating.replay.required-step-missing-evidence-binding",
    }
    assert manifest.replay_order == ()
    assert manifest.cycle_path[0] == manifest.cycle_path[-1]
    assert manifest.to_envelope().disposition is OperatingDisposition.BLOCKED


def test_replay_manifest_rejects_unknown_step_and_artifact_references() -> None:
    with pytest.raises(ValueError, match="unknown dependency"):
        ReplayManifest(
            manifest_id="unknown-step",
            campaign_id="wave-10-campaign",
            repository_ids=("ix-blackfox",),
            environment=_environment(),
            artifacts=(_artifact("lockfile"), _artifact("pytest-report")),
            steps=(
                _step(
                    "test-step",
                    expected_artifact_ids=("pytest-report",),
                    depends_on_step_ids=("missing-step",),
                    evidence_artifact_ids=("pytest-report",),
                ),
            ),
        )

    with pytest.raises(ValueError, match="unknown artifact"):
        ReplayManifest(
            manifest_id="unknown-artifact",
            campaign_id="wave-10-campaign",
            repository_ids=("ix-blackfox",),
            environment=_environment(),
            artifacts=(_artifact("lockfile"),),
            steps=(
                _step(
                    "test-step",
                    expected_artifact_ids=("missing-artifact",),
                    evidence_artifact_ids=(),
                ),
            ),
        )


def test_replay_validation_passes_matching_artifacts_and_executed_required_steps() -> None:
    manifest = _ready_manifest()
    result = ReplayValidationResult(
        validation_id="replay-validation",
        manifest=manifest,
        observed_artifacts=manifest.artifacts,
        executed_step_ids=("test-step", "report-step"),
        checked_by="platform security reviewer",
    )

    assert result.passed is True
    assert result.missing_artifact_ids == ()
    assert result.mismatched_artifact_ids == ()
    assert result.unexecuted_required_step_ids == ()
    assert result.to_envelope().disposition is OperatingDisposition.READY


def test_replay_validation_blocks_missing_mismatch_and_unexecuted_required_step() -> None:
    manifest = _ready_manifest()
    mismatched = _artifact("pytest-report", content=b"changed")
    result = ReplayValidationResult(
        validation_id="blocked-validation",
        manifest=manifest,
        observed_artifacts=(_artifact("lockfile"), mismatched, _artifact("extra-report")),
        executed_step_ids=("test-step",),
        checked_by="platform security reviewer",
    )

    finding_codes = {finding.code for finding in result.findings}
    assert finding_codes == {
        "operating.replay.artifact-digest-mismatch",
        "operating.replay.missing-artifact",
        "operating.replay.required-step-not-executed",
        "operating.replay.unexpected-artifact",
    }
    assert result.passed is False
    assert result.missing_artifact_ids == ("operating-report",)
    assert result.mismatched_artifact_ids == ("pytest-report",)
    assert result.unexpected_artifact_ids == ("extra-report",)
    assert result.unexecuted_required_step_ids == ("report-step",)
    assert result.to_dict()["disposition"] == "blocked"


def _ready_manifest() -> ReplayManifest:
    return ReplayManifest(
        manifest_id=" Wave 10 Replay ",
        campaign_id="Wave 10 Campaign",
        repository_ids=("IX-BlackFox",),
        environment=_environment(),
        artifacts=(_artifact("pytest-report"), _artifact("operating-report"), _artifact("lockfile")),
        steps=(
            _step("test-step", expected_artifact_ids=("pytest-report",), evidence_artifact_ids=("pytest-report",)),
            _step(
                "report-step",
                expected_artifact_ids=("operating-report",),
                depends_on_step_ids=("test-step",),
                evidence_artifact_ids=("operating-report",),
            ),
        ),
        notes=("offline replay",),
    )


def _environment() -> ReplayEnvironment:
    return ReplayEnvironment(
        environment_id="CI Replay Environment",
        runtime="Python 3.11",
        platform="linux",
        dependency_lock_artifact_ids=("lockfile",),
        required_variables=("pythonpath",),
        notes=("network disabled",),
    )


def _step(
    step_id: str,
    *,
    expected_artifact_ids: tuple[str, ...],
    depends_on_step_ids: tuple[str, ...] = (),
    evidence_artifact_ids: tuple[str, ...] = (),
) -> ReplayStep:
    return ReplayStep(
        step_id=step_id,
        title=f"{step_id} replay step",
        command=ReplayCommand(
            command_id=f"{step_id}-command",
            argv=("python", "-m", "pytest", "tests/operating"),
            working_directory=".",
            environment_keys=("pythonpath",),
        ),
        expected_artifact_ids=expected_artifact_ids,
        depends_on_step_ids=depends_on_step_ids,
        evidence_artifact_ids=evidence_artifact_ids,
    )


def _artifact(artifact_id: str, *, content: bytes | None = None) -> OperatingArtifactRef:
    normalized = artifact_id.strip().lower().replace(" ", "-")
    payload = content if content is not None else normalized.encode("utf-8")
    return OperatingArtifactRef(
        artifact_id=artifact_id,
        kind=OperatingArtifactKind.EVIDENCE_MANIFEST,
        source_wave=OperatingSourceWave.WAVE10,
        path=f".blackfox-artifacts/wave10/{normalized}.json",
        sha256=hashlib.sha256(payload).hexdigest(),
        producer="IX-BlackFox Wave 10 replay tests",
    )
