from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Mapping

from ix_blackfox.brains import (
    BrainManifest,
    BrainRole,
    build_primary_brain_catalog,
    build_reasoning_brain_catalog,
    build_wave1_operating_catalog,
)
from ix_blackfox.brains.providers import BrainProvider


class RuntimeReadinessStatus(StrEnum):
    """
    High-level runtime readiness classification.
    """

    READY = auto()
    DEGRADED = auto()
    UNAVAILABLE = auto()


@dataclass(frozen=True, slots=True)
class RuntimeLaneReadiness:
    """
    One readiness check for one brain lane.
    """

    lane_name: str
    brain_name: str
    provider_name: str
    is_critical: bool
    provider_present: bool
    provider_healthy: bool
    message: str

    @property
    def is_available(self) -> bool:
        """
        Return True when the lane is both present and healthy.
        """
        return self.provider_present and self.provider_healthy


@dataclass(frozen=True, slots=True)
class RuntimeReadinessReport:
    """
    Immutable runtime readiness report across all expected brain lanes.
    """

    status: RuntimeReadinessStatus
    lane_checks: tuple[RuntimeLaneReadiness, ...]
    issue_codes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def available_lane_count(self) -> int:
        """
        Return the number of lanes that are currently available.
        """
        return sum(1 for lane in self.lane_checks if lane.is_available)

    @property
    def total_lane_count(self) -> int:
        """
        Return the total number of checked lanes.
        """
        return len(self.lane_checks)

    def unavailable_lanes(self) -> tuple[str, ...]:
        """
        Return unavailable lane names in declaration order.
        """
        return tuple(lane.lane_name for lane in self.lane_checks if not lane.is_available)

    def critical_failures(self) -> tuple[str, ...]:
        """
        Return critical lane names that are unavailable.
        """
        return tuple(
            lane.lane_name
            for lane in self.lane_checks
            if lane.is_critical and not lane.is_available
        )

    def summary(self) -> str:
        """
        Return a concise human-readable readiness summary.
        """
        unavailable = self.unavailable_lanes()
        if self.status is RuntimeReadinessStatus.READY:
            return (
                f"Runtime ready: {self.available_lane_count}/{self.total_lane_count} "
                "brain lanes available."
            )
        if self.status is RuntimeReadinessStatus.UNAVAILABLE:
            return (
                "Runtime unavailable: critical lane failure in "
                f"{', '.join(self.critical_failures())}."
            )
        return (
            f"Runtime degraded: unavailable lanes -> {', '.join(unavailable)}."
            if unavailable
            else "Runtime degraded."
        )


@dataclass(frozen=True, slots=True)
class _LaneSpec:
    lane_name: str
    manifest: BrainManifest
    is_critical: bool = False


class RuntimeReadinessInspector:
    """
    Inspect whether the BlackFox multi-brain operating runtime is actually available.

    Readiness semantics:
    - READY: every expected lane is present and healthy
    - DEGRADED: primary lane is healthy, but one or more non-critical lanes are missing/unhealthy
    - UNAVAILABLE: at least one critical lane is missing or unhealthy
    """

    def __init__(
        self,
        *,
        lane_specs: tuple[_LaneSpec, ...] | None = None,
    ) -> None:
        self._lane_specs = lane_specs or self._build_default_lane_specs()

    def inspect(
        self,
        *,
        providers: Mapping[str, BrainProvider],
    ) -> RuntimeReadinessReport:
        """
        Inspect runtime readiness from currently available provider instances.
        """
        lane_checks: list[RuntimeLaneReadiness] = []
        issue_codes: list[str] = []

        for lane_spec in self._lane_specs:
            provider = providers.get(lane_spec.manifest.provider_name)
            if provider is None:
                lane_checks.append(
                    RuntimeLaneReadiness(
                        lane_name=lane_spec.lane_name,
                        brain_name=lane_spec.manifest.brain_name,
                        provider_name=lane_spec.manifest.provider_name,
                        is_critical=lane_spec.is_critical,
                        provider_present=False,
                        provider_healthy=False,
                        message="Provider instance is not configured.",
                    )
                )
                issue_codes.append(f"runtime.readiness.provider_missing.{lane_spec.lane_name}")
                continue

            try:
                health = provider.health_check()
            except Exception as error:
                lane_checks.append(
                    RuntimeLaneReadiness(
                        lane_name=lane_spec.lane_name,
                        brain_name=lane_spec.manifest.brain_name,
                        provider_name=lane_spec.manifest.provider_name,
                        is_critical=lane_spec.is_critical,
                        provider_present=True,
                        provider_healthy=False,
                        message=f"Health check failed: {error}",
                    )
                )
                issue_codes.append(f"runtime.readiness.provider_error.{lane_spec.lane_name}")
                continue

            if health.is_available:
                lane_checks.append(
                    RuntimeLaneReadiness(
                        lane_name=lane_spec.lane_name,
                        brain_name=lane_spec.manifest.brain_name,
                        provider_name=lane_spec.manifest.provider_name,
                        is_critical=lane_spec.is_critical,
                        provider_present=True,
                        provider_healthy=True,
                        message=health.message,
                    )
                )
            else:
                lane_checks.append(
                    RuntimeLaneReadiness(
                        lane_name=lane_spec.lane_name,
                        brain_name=lane_spec.manifest.brain_name,
                        provider_name=lane_spec.manifest.provider_name,
                        is_critical=lane_spec.is_critical,
                        provider_present=True,
                        provider_healthy=False,
                        message=health.message,
                    )
                )
                issue_codes.append(f"runtime.readiness.provider_unhealthy.{lane_spec.lane_name}")

        report_status = self._derive_status(tuple(lane_checks))
        return RuntimeReadinessReport(
            status=report_status,
            lane_checks=tuple(lane_checks),
            issue_codes=tuple(issue_codes),
        )

    @staticmethod
    def _derive_status(
        lane_checks: tuple[RuntimeLaneReadiness, ...],
    ) -> RuntimeReadinessStatus:
        if any(lane.is_critical and not lane.is_available for lane in lane_checks):
            return RuntimeReadinessStatus.UNAVAILABLE
        if any(not lane.is_available for lane in lane_checks):
            return RuntimeReadinessStatus.DEGRADED
        return RuntimeReadinessStatus.READY

    @staticmethod
    def _build_default_lane_specs() -> tuple[_LaneSpec, ...]:
        primary_catalog = build_primary_brain_catalog()
        operating_catalog = build_wave1_operating_catalog()
        reasoning_catalog = build_reasoning_brain_catalog()

        primary_manifest = primary_catalog.default_manifest()

        policy_brain_name = operating_catalog.metadata["policy_brain_name"]
        policy_manifest = operating_catalog.get_manifest(policy_brain_name)
        if policy_manifest is None:  # pragma: no cover
            raise RuntimeError("Operating catalog policy manifest is missing.")

        safeguard_brain_name = operating_catalog.brain_for_role(BrainRole.SAFETY)
        if safeguard_brain_name is None:  # pragma: no cover
            raise RuntimeError("Operating catalog safeguard manifest is missing.")
        safeguard_manifest = operating_catalog.get_manifest(safeguard_brain_name)
        if safeguard_manifest is None:  # pragma: no cover
            raise RuntimeError("Operating catalog safeguard manifest is missing.")

        vision_brain_name = operating_catalog.brain_for_role(BrainRole.MULTIMODAL)
        if vision_brain_name is None:  # pragma: no cover
            raise RuntimeError("Operating catalog vision manifest is missing.")
        vision_manifest = operating_catalog.get_manifest(vision_brain_name)
        if vision_manifest is None:  # pragma: no cover
            raise RuntimeError("Operating catalog vision manifest is missing.")

        reasoner_manifest = reasoning_catalog.default_manifest()

        return (
            _LaneSpec(
                lane_name="primary",
                manifest=primary_manifest,
                is_critical=True,
            ),
            _LaneSpec(
                lane_name="policy",
                manifest=policy_manifest,
                is_critical=False,
            ),
            _LaneSpec(
                lane_name="safeguard",
                manifest=safeguard_manifest,
                is_critical=False,
            ),
            _LaneSpec(
                lane_name="vision",
                manifest=vision_manifest,
                is_critical=False,
            ),
            _LaneSpec(
                lane_name="reasoning",
                manifest=reasoner_manifest,
                is_critical=False,
            ),
        )
