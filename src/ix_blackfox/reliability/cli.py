from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ix_blackfox.reliability.artifacts import (
    ReliabilityArtifactBundle,
    ReliabilityArtifactStore,
)
from ix_blackfox.reliability.metrics import (
    RepairMetricObservation,
)
from ix_blackfox.reliability.models import (
    ReliabilityScenarioResult,
)
from ix_blackfox.reliability.runner import (
    ReliabilityLabRunConfig,
    ReliabilityLabRunner,
    ReliabilityLabRunResult,
)
from ix_blackfox.reliability.scenarios import (
    WAVE4_FULL_SUITE_ID,
    ReliabilityScenarioRegistry,
)


class ReliabilityCliError(RuntimeError):
    """
    Raised when the Wave 4 reliability CLI receives an invalid request.
    """


@dataclass(frozen=True, slots=True)
class ReliabilityCliRunResult:
    """
    Structured result returned by the Wave 4 reliability CLI.
    """

    lab_result: ReliabilityLabRunResult
    artifact_bundle: ReliabilityArtifactBundle | None = None
    output_json_path: Path | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.output_json_path is not None:
            object.__setattr__(
                self,
                "output_json_path",
                self.output_json_path.expanduser().resolve(),
            )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def passed(self) -> bool:
        return self.lab_result.passed

    @property
    def decision(self) -> str:
        return self.lab_result.decision

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "decision": self.decision,
            "lab_result": self.lab_result.to_dict(),
            "artifact_bundle": (
                self.artifact_bundle.to_dict()
                if self.artifact_bundle is not None
                else None
            ),
            "output_json_path": (
                str(self.output_json_path)
                if self.output_json_path is not None
                else None
            ),
            "metadata": dict(self.metadata),
        }


def main(argv: Sequence[str] | None = None) -> int:
    """
    Console entrypoint for ``blackfox reliability``.
    """

    try:
        parser = _build_parser()
        args = parser.parse_args(list(argv) if argv is not None else None)

        if args.command is None:
            parser.print_help()
            return 0

        if args.command == "list-suites":
            _handle_list_suites(args)
            return 0

        if args.command == "run":
            result = run_reliability_cli_from_args(args)
            if args.json:
                print(
                    json.dumps(
                        result.to_dict(),
                        indent=2,
                        sort_keys=True,
                        ensure_ascii=False,
                    )
                )
            else:
                _print_human_run_summary(result)
            return 0 if result.passed else 1

        parser.error(f"Unsupported reliability command: {args.command}")
        return 2
    except Exception as exc:
        print(
            json.dumps(
                {
                    "succeeded": False,
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


def run_reliability_cli(argv: Sequence[str] | None = None) -> ReliabilityCliRunResult:
    """
    Run the Wave 4 reliability lab from CLI-style argv and return the result.
    """

    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command != "run":
        raise ReliabilityCliError("run_reliability_cli only supports the 'run' command.")
    return run_reliability_cli_from_args(args)


def run_reliability_cli_from_args(args: argparse.Namespace) -> ReliabilityCliRunResult:
    """
    Run the Wave 4 reliability lab from a parsed argparse namespace.
    """

    observations = _load_observations(Path(args.observations_file)) if args.observations_file else ()
    external_results = (
        _load_external_results(Path(args.external_results_file))
        if args.external_results_file
        else ()
    )
    metadata = _load_metadata(Path(args.metadata_file)) if args.metadata_file else {}

    config = ReliabilityLabRunConfig(
        suite_id=args.suite_id,
        include_adversarial_harness=not args.no_adversarial_harness,
        require_external_evidence_for_core=not args.allow_missing_core_evidence,
        metadata={
            "cli": "wave4-reliability",
            "observations_file": args.observations_file,
            "external_results_file": args.external_results_file,
            **metadata,
        },
    )
    lab_result = ReliabilityLabRunner().run(
        config=config,
        observations=observations,
        external_results=external_results,
        metadata={
            "cli": "wave4-reliability",
            **metadata,
        },
    )

    artifact_bundle = None
    if args.artifact_root is not None:
        artifact_bundle = ReliabilityArtifactStore(
            artifact_root=Path(args.artifact_root),
        ).write_run_result(
            lab_result,
            bundle_id=args.bundle_id,
            metadata={
                "cli": "wave4-reliability",
                "suite_id": args.suite_id,
            },
        )

    output_json_path = None
    result = ReliabilityCliRunResult(
        lab_result=lab_result,
        artifact_bundle=artifact_bundle,
        metadata={
            "cli": "wave4-reliability",
            "suite_id": args.suite_id,
            "artifact_root": args.artifact_root,
        },
    )
    if args.output_json is not None:
        output_json_path = _write_json_file(
            path=Path(args.output_json),
            payload=result.to_dict(),
        )
        result = ReliabilityCliRunResult(
            lab_result=lab_result,
            artifact_bundle=artifact_bundle,
            output_json_path=output_json_path,
            metadata=result.metadata,
        )

    return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blackfox reliability",
        description="Wave 4 IX-BlackFox reliability lab CLI.",
    )
    subparsers = parser.add_subparsers(dest="command")

    list_parser = subparsers.add_parser(
        "list-suites",
        help="List registered Wave 4 reliability scenario suites.",
    )
    list_parser.add_argument(
        "--json",
        action="store_true",
        help="Print suite registry data as JSON.",
    )

    run_parser = subparsers.add_parser(
        "run",
        help="Run a Wave 4 reliability scenario suite.",
    )
    run_parser.add_argument(
        "--suite-id",
        default=WAVE4_FULL_SUITE_ID,
        help=(
            "Reliability scenario suite id to run. Defaults to the full Wave 4 "
            "lab suite."
        ),
    )
    run_parser.add_argument(
        "--observations-file",
        default=None,
        help=(
            "Optional JSON file containing repair metric observations. Accepted "
            "shapes: a list, or an object with an 'observations' list."
        ),
    )
    run_parser.add_argument(
        "--external-results-file",
        default=None,
        help=(
            "Optional JSON file containing externally generated scenario results. "
            "Accepted shapes: a list, or an object with 'external_results' or "
            "'results'."
        ),
    )
    run_parser.add_argument(
        "--metadata-file",
        default=None,
        help="Optional JSON object merged into the reliability run metadata.",
    )
    run_parser.add_argument(
        "--artifact-root",
        default=None,
        help=(
            "Optional directory where reliability report, metrics, observations, "
            "receipts, and bundle manifest artifacts are written."
        ),
    )
    run_parser.add_argument(
        "--bundle-id",
        default=None,
        help="Optional deterministic artifact bundle id.",
    )
    run_parser.add_argument(
        "--output-json",
        default=None,
        help="Optional path for writing the complete CLI result JSON.",
    )
    run_parser.add_argument(
        "--no-adversarial-harness",
        action="store_true",
        help="Disable built-in non-executing adversarial probe evaluation.",
    )
    run_parser.add_argument(
        "--allow-missing-core-evidence",
        action="store_true",
        help=(
            "Allow core scenarios without explicit observations or external "
            "results to be skipped instead of treated as required evidence gaps."
        ),
    )
    run_parser.add_argument(
        "--json",
        action="store_true",
        help="Print the complete reliability run result as JSON.",
    )

    return parser


def _handle_list_suites(args: argparse.Namespace) -> None:
    registry = ReliabilityScenarioRegistry.built_in()
    payload = registry.to_dict()

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
        return

    print("Wave 4 reliability scenario suites:")
    for suite in registry.suites:
        print(
            f"- {suite.suite_id}: {suite.name} "
            f"({suite.scenario_count} scenarios, {suite.adversarial_count} adversarial)"
        )


def _load_observations(path: Path) -> tuple[RepairMetricObservation, ...]:
    payload = _load_json_file(path)
    return tuple(
        RepairMetricObservation.from_dict(raw_observation)
        for raw_observation in _mapping_payloads_from_payload(
            payload,
            top_level_keys=("observations",),
            label="observations",
        )
    )


def _load_external_results(path: Path) -> tuple[ReliabilityScenarioResult, ...]:
    payload = _load_json_file(path)
    return tuple(
        ReliabilityScenarioResult.from_dict(raw_result)
        for raw_result in _mapping_payloads_from_payload(
            payload,
            top_level_keys=("external_results", "results"),
            label="external_results",
        )
    )


def _load_metadata(path: Path) -> dict[str, Any]:
    payload = _load_json_file(path)
    if not isinstance(payload, Mapping):
        raise ReliabilityCliError("--metadata-file must point to a JSON object.")
    return dict(payload)


def _mapping_payloads_from_payload(
    payload: Any,
    *,
    top_level_keys: tuple[str, ...],
    label: str,
) -> tuple[Mapping[str, Any], ...]:
    if isinstance(payload, list):
        return _mapping_tuple(payload, label)

    if isinstance(payload, Mapping):
        for key in top_level_keys:
            raw_entries = payload.get(key)
            if raw_entries is not None:
                return _mapping_tuple(raw_entries, label)

    accepted = ", ".join(top_level_keys)
    raise ReliabilityCliError(
        f"{label} JSON must be a list or an object containing one of: {accepted}."
    )


def _mapping_tuple(value: Any, label: str) -> tuple[Mapping[str, Any], ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise ReliabilityCliError(f"{label} must be an iterable of JSON objects.")

    mappings: list[Mapping[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ReliabilityCliError(
                f"{label} entry at index {index} must be a JSON object."
            )
        mappings.append(item)

    return tuple(mappings)


def _load_json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json_file(*, path: Path, payload: Mapping[str, Any]) -> Path:
    output_path = path.expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(dict(payload), indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return output_path


def _print_human_run_summary(result: ReliabilityCliRunResult) -> None:
    lab_result = result.lab_result
    report = lab_result.report
    metrics_summary = lab_result.metrics_summary

    print(f"Reliability report: {report.report_id}")
    print(f"Suite: {report.suite.suite_id}")
    print(f"Decision: {result.decision}")
    print(f"Passed: {result.passed}")
    print(f"Scenarios: {report.metric_snapshot.scenario_count}")
    print(f"Scenario pass ratio: {report.metric_snapshot.pass_ratio:.2f}")
    print(f"Findings: {len(report.findings)}")
    print(f"Metrics: {len(metrics_summary.metrics)}")

    if result.artifact_bundle is not None:
        print(f"Artifact bundle: {result.artifact_bundle.bundle_id}")
        print(f"Artifact count: {result.artifact_bundle.artifact_count}")
        manifest_uri = result.artifact_bundle.metadata.get("manifest_uri")
        if isinstance(manifest_uri, str):
            print(f"Manifest URI: {manifest_uri}")

    if result.output_json_path is not None:
        print(f"Output JSON: {result.output_json_path}")
