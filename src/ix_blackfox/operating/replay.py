from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ix_blackfox.operating.models import (
    OperatingArtifactKind,
    OperatingArtifactRef,
    OperatingDomain,
    OperatingEnvelope,
    OperatingFinding,
    OperatingSeverity,
    normalize_identifier,
    normalize_relative_path,
    normalize_text,
)
from ix_blackfox.operating.registry import (
    normalize_identifier_tuple,
    normalize_text_tuple,
)
from ix_blackfox.operating.work_packages import normalize_command_tuple


@dataclass(frozen=True, slots=True)
class ReplayEnvironment:
    """Deterministic environment contract required to replay Wave 10 evidence."""

    environment_id: str
    runtime: str
    platform: str
    dependency_lock_artifact_ids: tuple[str, ...] = ()
    required_variables: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "environment_id",
            normalize_identifier(self.environment_id, label="environment_id"),
        )
        object.__setattr__(self, "runtime", normalize_text(self.runtime, label="runtime"))
        object.__setattr__(self, "platform", normalize_text(self.platform, label="platform"))
        object.__setattr__(
            self,
            "dependency_lock_artifact_ids",
            normalize_identifier_tuple(
                self.dependency_lock_artifact_ids,
                label="dependency_lock_artifact_ids",
            ),
        )
        object.__setattr__(
            self,
            "required_variables",
            normalize_identifier_tuple(self.required_variables, label="required_variables"),
        )
        object.__setattr__(self, "notes", normalize_text_tuple(self.notes, label="notes"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def has_dependency_lock(self) -> bool:
        return bool(self.dependency_lock_artifact_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "environment_id": self.environment_id,
            "runtime": self.runtime,
            "platform": self.platform,
            "dependency_lock_artifact_ids": list(self.dependency_lock_artifact_ids),
            "required_variables": list(self.required_variables),
            "notes": list(self.notes),
            "has_dependency_lock": self.has_dependency_lock,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ReplayCommand:
    """Command contract for one replayable step.

    Commands are represented as argv tuples on purpose. Wave 10 replay evidence
    must not depend on unreviewable shell strings or ambient authority.
    """

    command_id: str
    argv: tuple[str, ...]
    working_directory: str = "."
    environment_keys: tuple[str, ...] = ()
    timeout_seconds: int = 300
    deterministic: bool = True
    network_allowed: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "command_id", normalize_identifier(self.command_id, label="command_id"))
        if not self.argv:
            raise ValueError("ReplayCommand argv must not be empty.")
        object.__setattr__(self, "argv", normalize_command_tuple(self.argv))
        object.__setattr__(
            self,
            "working_directory",
            normalize_relative_path(self.working_directory),
        )
        object.__setattr__(
            self,
            "environment_keys",
            normalize_identifier_tuple(self.environment_keys, label="environment_keys"),
        )
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero.")
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def review_required(self) -> bool:
        return self.network_allowed or not self.deterministic

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "argv": list(self.argv),
            "working_directory": self.working_directory,
            "environment_keys": list(self.environment_keys),
            "timeout_seconds": self.timeout_seconds,
            "deterministic": self.deterministic,
            "network_allowed": self.network_allowed,
            "review_required": self.review_required,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ReplayStep:
    """Ordered replay step bound to commands, dependencies, and artifacts."""

    step_id: str
    title: str
    command: ReplayCommand
    expected_artifact_ids: tuple[str, ...]
    depends_on_step_ids: tuple[str, ...] = ()
    evidence_artifact_ids: tuple[str, ...] = ()
    required: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "step_id", normalize_identifier(self.step_id, label="step_id"))
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        if not self.expected_artifact_ids:
            raise ValueError("ReplayStep expected_artifact_ids must not be empty.")
        object.__setattr__(
            self,
            "expected_artifact_ids",
            normalize_identifier_tuple(self.expected_artifact_ids, label="expected_artifact_ids"),
        )
        object.__setattr__(
            self,
            "depends_on_step_ids",
            normalize_identifier_tuple(self.depends_on_step_ids, label="depends_on_step_ids"),
        )
        if self.step_id in self.depends_on_step_ids:
            raise ValueError("ReplayStep cannot depend on itself.")
        object.__setattr__(
            self,
            "evidence_artifact_ids",
            normalize_identifier_tuple(self.evidence_artifact_ids, label="evidence_artifact_ids"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def evidence_bound(self) -> bool:
        return bool(self.evidence_artifact_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "title": self.title,
            "command": self.command.to_dict(),
            "expected_artifact_ids": list(self.expected_artifact_ids),
            "depends_on_step_ids": list(self.depends_on_step_ids),
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "required": self.required,
            "evidence_bound": self.evidence_bound,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ReplayManifest:
    """Replayable Wave 10 manifest for deterministic operating evidence."""

    manifest_id: str
    campaign_id: str
    repository_ids: tuple[str, ...]
    environment: ReplayEnvironment
    artifacts: tuple[OperatingArtifactRef, ...]
    steps: tuple[ReplayStep, ...]
    generated_by: str = "IX-BlackFox Wave 10 replay manifest"
    notes: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "manifest_id", normalize_identifier(self.manifest_id, label="manifest_id"))
        object.__setattr__(self, "campaign_id", normalize_identifier(self.campaign_id, label="campaign_id"))
        if not self.repository_ids:
            raise ValueError("ReplayManifest repository_ids must not be empty.")
        object.__setattr__(
            self,
            "repository_ids",
            normalize_identifier_tuple(self.repository_ids, label="repository_ids"),
        )
        if not self.artifacts:
            raise ValueError("ReplayManifest artifacts must not be empty.")
        artifacts = tuple(sorted(self.artifacts, key=lambda artifact: artifact.artifact_id))
        artifact_ids = [artifact.artifact_id for artifact in artifacts]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError("ReplayManifest artifact_id values must be unique.")
        object.__setattr__(self, "artifacts", artifacts)
        if not self.steps:
            raise ValueError("ReplayManifest steps must not be empty.")
        steps = tuple(sorted(self.steps, key=lambda step: step.step_id))
        step_ids = [step.step_id for step in steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("ReplayManifest step_id values must be unique.")
        registered_steps = set(step_ids)
        registered_artifacts = set(artifact_ids)
        for step in steps:
            missing_steps = set(step.depends_on_step_ids) - registered_steps
            if missing_steps:
                missing = ", ".join(sorted(missing_steps))
                raise ValueError(f"replay step references unknown dependency: {missing}")
            missing_artifacts = set(step.expected_artifact_ids) - registered_artifacts
            if missing_artifacts:
                missing = ", ".join(sorted(missing_artifacts))
                raise ValueError(f"replay step references unknown artifact: {missing}")
            missing_evidence = set(step.evidence_artifact_ids) - registered_artifacts
            if missing_evidence:
                missing = ", ".join(sorted(missing_evidence))
                raise ValueError(f"replay step references unknown evidence artifact: {missing}")
        object.__setattr__(self, "steps", steps)
        object.__setattr__(
            self,
            "generated_by",
            normalize_text(self.generated_by, label="generated_by"),
        )
        object.__setattr__(self, "notes", normalize_text_tuple(self.notes, label="notes"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def artifact_ids(self) -> tuple[str, ...]:
        return tuple(artifact.artifact_id for artifact in self.artifacts)

    @property
    def required_step_ids(self) -> tuple[str, ...]:
        return tuple(step.step_id for step in self.steps if step.required)

    @property
    def replay_order(self) -> tuple[str, ...]:
        remaining = {step.step_id for step in self.steps}
        completed: set[str] = set()
        ordered: list[str] = []
        by_id = {step.step_id: step for step in self.steps}
        while remaining:
            ready = [
                step_id
                for step_id in sorted(remaining)
                if set(by_id[step_id].depends_on_step_ids) <= completed
            ]
            if not ready:
                return ()
            for step_id in ready:
                ordered.append(step_id)
                completed.add(step_id)
                remaining.remove(step_id)
        return tuple(ordered)

    @property
    def cycle_path(self) -> tuple[str, ...]:
        by_id = {step.step_id: step for step in self.steps}
        visiting: set[str] = set()
        visited: set[str] = set()
        stack: list[str] = []

        def visit(step_id: str) -> tuple[str, ...]:
            if step_id in visiting:
                start = stack.index(step_id)
                return tuple([*stack[start:], step_id])
            if step_id in visited:
                return ()
            visiting.add(step_id)
            stack.append(step_id)
            for dependency_id in by_id[step_id].depends_on_step_ids:
                cycle = visit(dependency_id)
                if cycle:
                    return cycle
            stack.pop()
            visiting.remove(step_id)
            visited.add(step_id)
            return ()

        for step_id in sorted(by_id):
            cycle = visit(step_id)
            if cycle:
                return cycle
        return ()

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []
        if self.cycle_path:
            findings.append(
                self._finding(
                    code="operating.replay.dependency-cycle",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Replay manifest contains a step dependency cycle: {' -> '.join(self.cycle_path)}.",
                    metadata={"cycle_path": list(self.cycle_path)},
                )
            )
        if not self.environment.has_dependency_lock:
            findings.append(
                self._finding(
                    code="operating.replay.environment-missing-lock-artifact",
                    severity=OperatingSeverity.MEDIUM,
                    summary="Replay environment has no dependency lock artifact binding.",
                    blocking=False,
                    metadata={"environment_id": self.environment.environment_id},
                )
            )
        for step in self.steps:
            if step.command.network_allowed:
                findings.append(
                    self._finding(
                        code="operating.replay.network-required",
                        severity=OperatingSeverity.CRITICAL,
                        summary=f"Replay step {step.step_id} allows network access.",
                        metadata={"step_id": step.step_id, "command_id": step.command.command_id},
                    )
                )
            if not step.command.deterministic:
                findings.append(
                    self._finding(
                        code="operating.replay.nondeterministic-command",
                        severity=OperatingSeverity.CRITICAL,
                        summary=f"Replay step {step.step_id} is marked nondeterministic.",
                        metadata={"step_id": step.step_id, "command_id": step.command.command_id},
                    )
                )
            if step.required and not step.evidence_bound:
                findings.append(
                    self._finding(
                        code="operating.replay.required-step-missing-evidence-binding",
                        severity=OperatingSeverity.HIGH,
                        summary=f"Required replay step {step.step_id} is not bound to evidence artifacts.",
                        metadata={"step_id": step.step_id},
                    )
                )
        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.manifest_id}-replay-manifest-envelope",
            artifact_kind=OperatingArtifactKind.REPLAY_MANIFEST,
            subject=f"Wave 10 replay manifest {self.manifest_id}",
            domains=(OperatingDomain.REPLAYABLE, OperatingDomain.REVIEWABLE),
            evidence=self.artifacts,
            findings=self.findings,
            metadata={
                "manifest_id": self.manifest_id,
                "campaign_id": self.campaign_id,
                "repository_ids": list(self.repository_ids),
                "environment_id": self.environment.environment_id,
                "artifact_ids": list(self.artifact_ids),
                "step_ids": [step.step_id for step in self.steps],
                "required_step_ids": list(self.required_step_ids),
                "replay_order": list(self.replay_order),
            },
        )

    def to_dict(self) -> dict[str, Any]:
        envelope = self.to_envelope()
        return {
            "manifest_id": self.manifest_id,
            "campaign_id": self.campaign_id,
            "repository_ids": list(self.repository_ids),
            "environment": self.environment.to_dict(),
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "steps": [step.to_dict() for step in self.steps],
            "artifact_ids": list(self.artifact_ids),
            "required_step_ids": list(self.required_step_ids),
            "replay_order": list(self.replay_order),
            "cycle_path": list(self.cycle_path),
            "generated_by": self.generated_by,
            "notes": list(self.notes),
            "findings": [finding.to_dict() for finding in self.findings],
            "disposition": envelope.disposition.value,
            "digest": envelope.digest,
            "metadata": dict(self.metadata),
        }

    def _finding(
        self,
        *,
        code: str,
        severity: OperatingSeverity,
        summary: str,
        blocking: bool = True,
        metadata: Mapping[str, Any] | None = None,
    ) -> OperatingFinding:
        return OperatingFinding(
            code=code,
            severity=severity,
            summary=summary,
            domains=(OperatingDomain.REPLAYABLE, OperatingDomain.REVIEWABLE),
            blocking=blocking,
            metadata={"manifest_id": self.manifest_id, **dict(metadata or {})},
        )


@dataclass(frozen=True, slots=True)
class ReplayValidationResult:
    """Result of comparing observed replay artifacts against a replay manifest."""

    validation_id: str
    manifest: ReplayManifest
    observed_artifacts: tuple[OperatingArtifactRef, ...]
    executed_step_ids: tuple[str, ...]
    checked_by: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "validation_id",
            normalize_identifier(self.validation_id, label="validation_id"),
        )
        observed = tuple(sorted(self.observed_artifacts, key=lambda artifact: artifact.artifact_id))
        observed_ids = [artifact.artifact_id for artifact in observed]
        if len(observed_ids) != len(set(observed_ids)):
            raise ValueError("ReplayValidationResult observed artifact_id values must be unique.")
        object.__setattr__(self, "observed_artifacts", observed)
        object.__setattr__(
            self,
            "executed_step_ids",
            normalize_identifier_tuple(self.executed_step_ids, label="executed_step_ids"),
        )
        unknown_steps = set(self.executed_step_ids) - {step.step_id for step in self.manifest.steps}
        if unknown_steps:
            unknown = ", ".join(sorted(unknown_steps))
            raise ValueError(f"executed_step_ids reference unknown replay steps: {unknown}")
        object.__setattr__(self, "checked_by", normalize_text(self.checked_by, label="checked_by"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def observed_artifact_ids(self) -> tuple[str, ...]:
        return tuple(artifact.artifact_id for artifact in self.observed_artifacts)

    @property
    def missing_artifact_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.manifest.artifact_ids) - set(self.observed_artifact_ids)))

    @property
    def unexpected_artifact_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.observed_artifact_ids) - set(self.manifest.artifact_ids)))

    @property
    def mismatched_artifact_ids(self) -> tuple[str, ...]:
        expected = {artifact.artifact_id: artifact.sha256 for artifact in self.manifest.artifacts}
        observed = {artifact.artifact_id: artifact.sha256 for artifact in self.observed_artifacts}
        return tuple(
            sorted(
                artifact_id
                for artifact_id, expected_sha256 in expected.items()
                if artifact_id in observed and observed[artifact_id] != expected_sha256
            )
        )

    @property
    def unexecuted_required_step_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.manifest.required_step_ids) - set(self.executed_step_ids)))

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = [*self.manifest.findings]
        for artifact_id in self.missing_artifact_ids:
            findings.append(
                self._finding(
                    code="operating.replay.missing-artifact",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Replay validation is missing expected artifact {artifact_id}.",
                    metadata={"artifact_id": artifact_id},
                )
            )
        for artifact_id in self.mismatched_artifact_ids:
            findings.append(
                self._finding(
                    code="operating.replay.artifact-digest-mismatch",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Replay artifact {artifact_id} digest does not match the manifest.",
                    metadata={"artifact_id": artifact_id},
                )
            )
        for step_id in self.unexecuted_required_step_ids:
            findings.append(
                self._finding(
                    code="operating.replay.required-step-not-executed",
                    severity=OperatingSeverity.CRITICAL,
                    summary=f"Required replay step {step_id} was not executed.",
                    metadata={"step_id": step_id},
                )
            )
        for artifact_id in self.unexpected_artifact_ids:
            findings.append(
                self._finding(
                    code="operating.replay.unexpected-artifact",
                    severity=OperatingSeverity.MEDIUM,
                    summary=f"Replay produced unexpected artifact {artifact_id}.",
                    blocking=False,
                    metadata={"artifact_id": artifact_id},
                )
            )
        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    @property
    def passed(self) -> bool:
        return not any(finding.blocking for finding in self.findings)

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.validation_id}-replay-validation-envelope",
            artifact_kind=OperatingArtifactKind.REPLAY_MANIFEST,
            subject=f"Wave 10 replay validation {self.validation_id}",
            domains=(OperatingDomain.REPLAYABLE, OperatingDomain.REVIEWABLE),
            evidence=self.observed_artifacts,
            findings=self.findings,
            metadata={
                "validation_id": self.validation_id,
                "manifest_id": self.manifest.manifest_id,
                "checked_by": self.checked_by,
                "executed_step_ids": list(self.executed_step_ids),
                "missing_artifact_ids": list(self.missing_artifact_ids),
                "mismatched_artifact_ids": list(self.mismatched_artifact_ids),
                "unexpected_artifact_ids": list(self.unexpected_artifact_ids),
                "unexecuted_required_step_ids": list(self.unexecuted_required_step_ids),
                "passed": self.passed,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        envelope = self.to_envelope()
        return {
            "validation_id": self.validation_id,
            "manifest": self.manifest.to_dict(),
            "observed_artifacts": [artifact.to_dict() for artifact in self.observed_artifacts],
            "observed_artifact_ids": list(self.observed_artifact_ids),
            "executed_step_ids": list(self.executed_step_ids),
            "checked_by": self.checked_by,
            "missing_artifact_ids": list(self.missing_artifact_ids),
            "mismatched_artifact_ids": list(self.mismatched_artifact_ids),
            "unexpected_artifact_ids": list(self.unexpected_artifact_ids),
            "unexecuted_required_step_ids": list(self.unexecuted_required_step_ids),
            "findings": [finding.to_dict() for finding in self.findings],
            "passed": self.passed,
            "disposition": envelope.disposition.value,
            "digest": envelope.digest,
            "metadata": dict(self.metadata),
        }

    def _finding(
        self,
        *,
        code: str,
        severity: OperatingSeverity,
        summary: str,
        blocking: bool = True,
        metadata: Mapping[str, Any] | None = None,
    ) -> OperatingFinding:
        return OperatingFinding(
            code=code,
            severity=severity,
            summary=summary,
            domains=(OperatingDomain.REPLAYABLE, OperatingDomain.REVIEWABLE),
            blocking=blocking,
            metadata={
                "validation_id": self.validation_id,
                "manifest_id": self.manifest.manifest_id,
                **dict(metadata or {}),
            },
        )
