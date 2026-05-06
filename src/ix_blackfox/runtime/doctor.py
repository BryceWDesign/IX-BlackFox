from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ix_blackfox.runtime.orchestrator import BlackFoxRuntime
from ix_blackfox.runtime.readiness import (
    RuntimeLaneReadiness,
    RuntimeReadinessReport,
    RuntimeReadinessStatus,
)


@dataclass(frozen=True, slots=True)
class RuntimeDoctorReport:
    """
    Immutable runtime diagnostics report.

    This report is intentionally operational:
    - what providers are configured right now
    - what the readiness state is
    - what actions are recommended before serious use
    """

    generated_at: datetime
    readiness_report: RuntimeReadinessReport
    configured_providers: tuple[str, ...] = field(default_factory=tuple)
    runtime_paths: dict[str, str] = field(default_factory=dict)
    recommendations: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "configured_providers": list(self.configured_providers),
            "runtime_paths": dict(self.runtime_paths),
            "readiness_report": _readiness_to_dict(self.readiness_report),
            "recommendations": list(self.recommendations),
        }

    def to_json(self, *, pretty: bool = True) -> str:
        indent = 2 if pretty else None
        separators = None if pretty else (",", ":")
        return json.dumps(
            self.to_dict(),
            indent=indent,
            separators=separators,
            sort_keys=True,
        )

    def write_json(self, path: str | Path, *, pretty: bool = True) -> Path:
        output_path = Path(path).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.to_json(pretty=pretty), encoding="utf-8")
        return output_path


class RuntimeDoctor:
    """
    Runtime doctor for IX-BlackFox.

    This provides a single, explicit diagnostics pass over the current
    runtime wiring without requiring a task execution.
    """

    def __init__(self, *, runtime: BlackFoxRuntime) -> None:
        self._runtime = runtime

    @classmethod
    def inspect_default(
        cls,
        *,
        root_dir: str | Path | None = None,
        env: dict[str, str] | None = None,
    ) -> RuntimeDoctorReport:
        runtime = BlackFoxRuntime.create_default(
            root_dir=None if root_dir is None else Path(root_dir),
            env=env,
        )
        return cls(runtime=runtime).inspect()

    def inspect(self) -> RuntimeDoctorReport:
        readiness_report = self._runtime._readiness_inspector.inspect(  # noqa: SLF001
            providers=self._runtime._brain_providers  # noqa: SLF001
        )
        configured_providers = tuple(
            sorted(self._runtime._brain_providers.keys())  # noqa: SLF001
        )
        runtime_paths = {
            "root_dir": str(self._runtime._config.paths.root_dir),  # noqa: SLF001
            "artifacts_dir": str(self._runtime._config.paths.artifacts_dir),  # noqa: SLF001
            "state_dir": str(self._runtime._config.paths.state_dir),  # noqa: SLF001
            "logs_dir": str(self._runtime._config.paths.logs_dir),  # noqa: SLF001
        }
        recommendations = _build_recommendations(readiness_report)

        return RuntimeDoctorReport(
            generated_at=_utc_now(),
            readiness_report=readiness_report,
            configured_providers=configured_providers,
            runtime_paths=runtime_paths,
            recommendations=recommendations,
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="blackfox-doctor",
        description="Run IX-BlackFox runtime diagnostics.",
    )
    parser.add_argument(
        "--root-dir",
        type=Path,
        default=None,
        help="Optional runtime root directory.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional JSON output path.",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit compact JSON instead of pretty JSON.",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    report = RuntimeDoctor.inspect_default(root_dir=args.root_dir)
    payload = report.to_json(pretty=not args.compact)

    if args.output is not None:
        report.write_json(args.output, pretty=not args.compact)
    else:
        print(payload)

    if report.readiness_report.status is RuntimeReadinessStatus.READY:
        return 0
    if report.readiness_report.status is RuntimeReadinessStatus.DEGRADED:
        return 1
    return 2


def _readiness_to_dict(report: RuntimeReadinessReport) -> dict[str, Any]:
    return {
        "status": report.status.value,
        "available_lane_count": report.available_lane_count,
        "total_lane_count": report.total_lane_count,
        "unavailable_lanes": list(report.unavailable_lanes()),
        "critical_failures": list(report.critical_failures()),
        "issue_codes": list(report.issue_codes),
        "summary": report.summary(),
        "lane_checks": [_lane_to_dict(lane) for lane in report.lane_checks],
    }


def _lane_to_dict(lane: RuntimeLaneReadiness) -> dict[str, Any]:
    return {
        "lane_name": lane.lane_name,
        "brain_name": lane.brain_name,
        "provider_name": lane.provider_name,
        "is_critical": lane.is_critical,
        "provider_present": lane.provider_present,
        "provider_healthy": lane.provider_healthy,
        "is_available": lane.is_available,
        "message": lane.message,
    }


def _build_recommendations(
    readiness_report: RuntimeReadinessReport,
) -> tuple[str, ...]:
    recommendations: list[str] = []

    for lane in readiness_report.lane_checks:
        if lane.is_available:
            continue

        if not lane.provider_present:
            recommendations.append(
                f"Configure provider '{lane.provider_name}' for the '{lane.lane_name}' lane."
            )
            continue

        recommendations.append(
            f"Restore health for provider '{lane.provider_name}' serving the '{lane.lane_name}' lane."
        )

    if not recommendations and readiness_report.status is RuntimeReadinessStatus.READY:
        recommendations.append("Runtime is fully ready. No corrective action is required.")

    return tuple(recommendations)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


if __name__ == "__main__":
    raise SystemExit(main())
