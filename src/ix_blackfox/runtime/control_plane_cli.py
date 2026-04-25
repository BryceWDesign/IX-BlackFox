from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ix_blackfox.runtime.control_plane import (
    EngineeringControlPlane,
    EngineeringControlPlaneReport,
)
from ix_blackfox.runtime.run_bundle_export import (
    RunBundleExportFormat,
    RunBundleExportRequest,
    RunBundleExportResult,
    RunBundleExporter,
)
from ix_blackfox.tools.patch import PatchDiff


class ControlPlaneCliError(RuntimeError):
    """
    Raised when the engineering control-plane CLI receives an invalid request.
    """


@dataclass(frozen=True, slots=True)
class ControlPlaneCliResult:
    """
    Structured result returned by the control-plane CLI adapter.
    """

    report: EngineeringControlPlaneReport
    export_result: RunBundleExportResult | None = None
    report_output_path: Path | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.report_output_path is not None:
            object.__setattr__(
                self,
                "report_output_path",
                self.report_output_path.expanduser().resolve(),
            )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def succeeded(self) -> bool:
        return self.report.succeeded

    @property
    def verification_status(self) -> str:
        return self.report.verification_status

    def to_dict(self) -> dict[str, Any]:
        return {
            "succeeded": self.succeeded,
            "verification_status": self.verification_status,
            "report": self.report.to_dict(),
            "export_result": (
                self.export_result.to_dict() if self.export_result is not None else None
            ),
            "report_output_path": (
                str(self.report_output_path)
                if self.report_output_path is not None
                else None
            ),
            "metadata": dict(self.metadata),
        }


def run_control_plane_cli(argv: Sequence[str] | None = None) -> ControlPlaneCliResult:
    """
    Run the governed engineering control plane from CLI-style argv.

    This adapter intentionally accepts patch candidates from explicit JSON files.
    It does not ask a model to generate code. The CLI executes supplied patch
    candidates through the same controlled patch/test/receipt/bundle path as the
    Python API.
    """
    args = _build_parser().parse_args(list(argv) if argv is not None else None)

    workspace_root = Path(args.workspace_root)
    artifact_root = Path(args.artifact_root) if args.artifact_root else workspace_root
    policy_path = Path(args.policy) if args.policy else None
    candidate_patches = _load_patch_candidates(args.patch)
    test_command = tuple(args.test_command) if args.test_command else None
    allowed_executables = tuple(args.allowed_executable) if args.allowed_executable else (
        "python",
        "python3",
        "py",
        "pytest",
        Path(sys.executable).name,
    )

    control_plane = EngineeringControlPlane.from_workspace(
        workspace_root=workspace_root,
        policy_path=policy_path,
        artifact_root=artifact_root,
        require_workspace_marker=not args.no_workspace_marker,
        workspace_marker_name=args.workspace_marker_name,
        test_command=test_command,
        test_working_directory=args.test_working_directory,
        test_timeout_seconds=args.test_timeout_seconds,
        allowed_test_executables=allowed_executables,
        metadata={
            "cli": True,
            "patch_files": [str(Path(path)) for path in args.patch],
        },
    )
    report = control_plane.run_programming_repair(
        task_id=args.task_id,
        run_id=args.run_id,
        objective=args.objective,
        candidate_patches=candidate_patches,
        test_command=test_command,
        test_working_directory=args.test_working_directory,
        metadata={
            "cli": True,
            "patch_count": len(candidate_patches),
        },
    )

    export_result = None
    if args.export:
        export_request = RunBundleExportRequest.from_layout(
            layout=_layout_from_report_bundle_root(report.bundle_root, report.run_id),
            destination_dir=Path(args.export_dir),
            export_format=RunBundleExportFormat(args.export_format),
            export_name=args.export_name or args.run_id,
            require_manifest=True,
            overwrite=args.overwrite_export,
            metadata={"cli": True},
        )
        export_result = RunBundleExporter().export(export_request)

    report_output_path = None
    if args.output_json:
        report_output_path = _write_output_json(
            path=Path(args.output_json),
            payload=ControlPlaneCliResult(
                report=report,
                export_result=export_result,
                metadata={"cli": True},
            ).to_dict(),
        )

    return ControlPlaneCliResult(
        report=report,
        export_result=export_result,
        report_output_path=report_output_path,
        metadata={
            "cli": True,
            "patch_count": len(candidate_patches),
            "export_requested": bool(args.export),
        },
    )


def main(argv: Sequence[str] | None = None) -> int:
    """
    Console entrypoint for ``python -m ix_blackfox.runtime.control_plane_cli``.
    """
    try:
        result = run_control_plane_cli(argv)
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

    print(
        json.dumps(
            {
                "succeeded": result.succeeded,
                "verification_status": result.verification_status,
                "run_id": result.report.run_id,
                "task_id": result.report.task_id,
                "bundle_root": result.report.bundle_root,
                "export_path": (
                    str(result.export_result.export_path)
                    if result.export_result is not None
                    else None
                ),
                "report_output_path": (
                    str(result.report_output_path)
                    if result.report_output_path is not None
                    else None
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )

    return 0 if result.succeeded else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blackfox-control-plane",
        description=(
            "Run the IX-BlackFox governed engineering control plane against "
            "explicit patch candidates."
        ),
    )

    parser.add_argument(
        "--workspace-root",
        required=True,
        help="Reserved workspace root containing .blackfox-workspace.",
    )
    parser.add_argument(
        "--artifact-root",
        help="Root where artifacts/runs/<run_id> will be written. Defaults to workspace root.",
    )
    parser.add_argument(
        "--policy",
        help="Path to blackfox.policy.toml. Defaults to <workspace-root>/blackfox.policy.toml when present.",
    )
    parser.add_argument(
        "--task-id",
        required=True,
        help="Stable task identifier for receipts and bundle metadata.",
    )
    parser.add_argument(
        "--run-id",
        required=True,
        help="Stable run identifier for receipts and bundle metadata.",
    )
    parser.add_argument(
        "--objective",
        required=True,
        help="Human-readable repair objective.",
    )
    parser.add_argument(
        "--patch",
        action="append",
        required=True,
        help="PatchDiff JSON file. May be supplied multiple times in retry order.",
    )
    parser.add_argument(
        "--test-command",
        nargs="+",
        help="Allowlisted argv-style test command. Example: --test-command python -m pytest -q",
    )
    parser.add_argument(
        "--test-working-directory",
        default=".",
        help="Workspace-relative directory where the test command should run.",
    )
    parser.add_argument(
        "--test-timeout-seconds",
        type=float,
        default=60.0,
        help="Per-test-command timeout in seconds.",
    )
    parser.add_argument(
        "--allowed-executable",
        action="append",
        help="Allowed test executable basename. May be supplied multiple times.",
    )
    parser.add_argument(
        "--workspace-marker-name",
        default=".blackfox-workspace",
        help="Required marker file name for reserved workspaces.",
    )
    parser.add_argument(
        "--no-workspace-marker",
        action="store_true",
        help="Disable reserved workspace marker enforcement.",
    )
    parser.add_argument(
        "--output-json",
        help="Optional path to write the full CLI result JSON.",
    )
    parser.add_argument(
        "--export",
        action="store_true",
        help="Export the run bundle after completion.",
    )
    parser.add_argument(
        "--export-dir",
        default="exports",
        help="Directory where exported bundles are written.",
    )
    parser.add_argument(
        "--export-format",
        choices=tuple(item.value for item in RunBundleExportFormat),
        default=RunBundleExportFormat.ZIP.value,
        help="Run bundle export format.",
    )
    parser.add_argument(
        "--export-name",
        help="Optional export file/directory name. Defaults to run id.",
    )
    parser.add_argument(
        "--overwrite-export",
        action="store_true",
        help="Allow overwriting an existing export target.",
    )

    return parser


def _load_patch_candidates(paths: Iterable[str]) -> tuple[PatchDiff, ...]:
    patches: list[PatchDiff] = []

    for raw_path in paths:
        path = Path(raw_path).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"Patch file does not exist: {path}")
        if not path.is_file():
            raise ControlPlaneCliError(f"Patch path is not a file: {path}")

        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, Mapping):
            raise ControlPlaneCliError(
                f"Patch file must contain one PatchDiff JSON object: {path}"
            )

        patches.append(PatchDiff.from_dict(payload))

    if not patches:
        raise ControlPlaneCliError("At least one patch candidate is required.")

    return tuple(patches)


def _write_output_json(*, path: Path, payload: Mapping[str, Any]) -> Path:
    destination = path.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(
            dict(payload),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return destination


def _layout_from_report_bundle_root(bundle_root: str, run_id: str):
    from ix_blackfox.runtime.run_bundle import RunBundleLayout

    root = Path(bundle_root).expanduser().resolve()
    expected_suffix = Path("artifacts") / "runs" / run_id

    if not str(root).replace("\\", "/").endswith(expected_suffix.as_posix()):
        raise ControlPlaneCliError(
            "Cannot infer artifact root from report bundle root: "
            f"{bundle_root!r}."
        )

    artifact_root = root.parents[2]
    return RunBundleLayout(root_dir=artifact_root, run_id=run_id)


if __name__ == "__main__":
    raise SystemExit(main())
