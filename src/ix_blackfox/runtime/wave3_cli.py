from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Self

from ix_blackfox.runtime.authoring_repair import StaticPatchProposalProvider
from ix_blackfox.runtime.control_plane import EngineeringControlPlane
from ix_blackfox.runtime.wave3_acceptance import (
    Wave3AcceptanceReport,
    Wave3AcceptanceValidator,
)


class Wave3CliError(RuntimeError):
    """
    User-facing CLI error for governed Wave 3 authored repair runs.
    """


@dataclass(frozen=True, slots=True)
class Wave3CliResult:
    """
    Result returned by the Wave 3 CLI command.

    The CLI writes this payload as JSON so a manual operator can preserve the
    authored layer, Wave 2 execution layer, and acceptance layer together.
    """

    exit_code: int
    output_path: Path | None
    payload: Mapping[str, Any]
    errors: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload", dict(self.payload))
        object.__setattr__(
            self,
            "errors",
            tuple(_normalize_text(error, label="error") for error in self.errors),
        )

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "succeeded": self.succeeded,
            "output_path": None if self.output_path is None else str(self.output_path),
            "errors": list(self.errors),
            "payload": dict(self.payload),
        }


@dataclass(frozen=True, slots=True)
class Wave3CliRequest:
    """
    Normalized CLI request for a governed Wave 3 authored repair run.
    """

    workspace_root: Path
    artifact_root: Path
    task_id: str
    run_id: str
    objective: str
    include_paths: tuple[str, ...]
    proposal_responses: tuple[str, ...]
    raw_test_output: str | None = None
    output_path: Path | None = None
    policy_path: Path | None = None
    require_workspace_marker: bool = True
    workspace_marker_name: str = ".blackfox-workspace"
    test_command: tuple[str, ...] | None = None
    test_working_directory: str = "."
    test_timeout_seconds: float = 60.0
    allowed_test_executables: tuple[str, ...] = (
        "python",
        "python3",
        "py",
        "pytest",
    )
    authoring_test_return_code: int = 1
    authoring_test_timed_out: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "workspace_root",
            self.workspace_root.expanduser().resolve(),
        )
        object.__setattr__(
            self,
            "artifact_root",
            self.artifact_root.expanduser().resolve(),
        )
        object.__setattr__(
            self,
            "policy_path",
            None if self.policy_path is None else self.policy_path.expanduser().resolve(),
        )
        object.__setattr__(
            self,
            "output_path",
            None if self.output_path is None else self.output_path.expanduser().resolve(),
        )
        object.__setattr__(self, "task_id", _normalize_identifier(self.task_id, label="task_id"))
        object.__setattr__(self, "run_id", _normalize_identifier(self.run_id, label="run_id"))
        object.__setattr__(self, "objective", _normalize_text(self.objective, label="objective"))
        object.__setattr__(
            self,
            "include_paths",
            _normalize_string_tuple(self.include_paths, field_name="include_paths"),
        )
        object.__setattr__(
            self,
            "proposal_responses",
            tuple(_normalize_text(value, label="proposal_response") for value in self.proposal_responses),
        )
        object.__setattr__(
            self,
            "workspace_marker_name",
            _normalize_text(self.workspace_marker_name, label="workspace_marker_name"),
        )
        object.__setattr__(
            self,
            "test_command",
            None if self.test_command is None else tuple(self.test_command),
        )
        object.__setattr__(
            self,
            "test_working_directory",
            _normalize_text(self.test_working_directory, label="test_working_directory"),
        )
        object.__setattr__(
            self,
            "allowed_test_executables",
            _normalize_string_tuple(
                self.allowed_test_executables,
                field_name="allowed_test_executables",
            ),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

        if not self.proposal_responses:
            raise Wave3CliError("At least one proposal response is required.")
        if self.test_timeout_seconds <= 0:
            raise Wave3CliError("test_timeout_seconds must be positive.")

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> Self:
        workspace_root = Path(args.workspace_root)
        artifact_root = Path(args.artifact_root) if args.artifact_root else workspace_root
        output_path = None if args.output_path is None else Path(args.output_path)
        policy_path = None if args.policy_path is None else Path(args.policy_path)

        proposal_responses = _load_proposal_responses(
            proposal_json=args.proposal_json,
            proposal_file=args.proposal_file,
        )
        raw_test_output = _load_optional_text_file(args.raw_test_output_file)

        return cls(
            workspace_root=workspace_root,
            artifact_root=artifact_root,
            task_id=args.task_id,
            run_id=args.run_id,
            objective=args.objective,
            include_paths=tuple(args.include_path),
            proposal_responses=proposal_responses,
            raw_test_output=raw_test_output,
            output_path=output_path,
            policy_path=policy_path,
            require_workspace_marker=not args.no_workspace_marker,
            workspace_marker_name=args.workspace_marker_name,
            test_command=tuple(args.test_command) if args.test_command else None,
            test_working_directory=args.test_working_directory,
            test_timeout_seconds=args.test_timeout_seconds,
            allowed_test_executables=tuple(args.allowed_test_executable),
            authoring_test_return_code=args.authoring_test_return_code,
            authoring_test_timed_out=args.authoring_test_timed_out,
            metadata={
                "cli": "wave3",
                "proposal_source": _proposal_source(args),
            },
        )


def run_wave3_cli_request(request: Wave3CliRequest) -> Wave3CliResult:
    """
    Execute a governed Wave 3 authored repair request from normalized CLI input.
    """
    control_plane = EngineeringControlPlane.from_workspace(
        workspace_root=request.workspace_root,
        policy_path=request.policy_path,
        artifact_root=request.artifact_root,
        require_workspace_marker=request.require_workspace_marker,
        workspace_marker_name=request.workspace_marker_name,
        test_command=request.test_command,
        test_working_directory=request.test_working_directory,
        test_timeout_seconds=request.test_timeout_seconds,
        allowed_test_executables=request.allowed_test_executables,
        metadata={
            "cli": "wave3",
            **dict(request.metadata),
        },
    )

    authored_report = control_plane.run_authored_programming_repair(
        task_id=request.task_id,
        run_id=request.run_id,
        objective=request.objective,
        include_paths=request.include_paths,
        proposal_provider=StaticPatchProposalProvider(
            responses=request.proposal_responses,
            provider_name="wave3-cli-static-provider",
            model_name="manual-json-import",
        ),
        raw_test_output=request.raw_test_output,
        authoring_test_return_code=request.authoring_test_return_code,
        authoring_test_timed_out=request.authoring_test_timed_out,
        test_command=request.test_command,
        test_working_directory=request.test_working_directory,
        metadata={
            "cli": "wave3",
            **dict(request.metadata),
        },
    )

    acceptance_report = Wave3AcceptanceValidator().validate(authored_report)

    payload = {
        "schema_version": "wave3.cli.result.v1",
        "task_id": request.task_id,
        "run_id": request.run_id,
        "workspace_root": str(request.workspace_root),
        "artifact_root": str(request.artifact_root),
        "authored_engineering_report": authored_report.to_dict(),
        "wave3_acceptance_report": acceptance_report.to_dict(),
    }

    if request.output_path is not None:
        _write_json(request.output_path, payload)

    exit_code = _exit_code_from_acceptance(acceptance_report)

    return Wave3CliResult(
        exit_code=exit_code,
        output_path=request.output_path,
        payload=payload,
        errors=()
        if exit_code == 0
        else (
            f"Wave 3 acceptance status: {acceptance_report.status.value}",
        ),
    )


def run_wave3_cli(argv: Sequence[str] | None = None) -> Wave3CliResult:
    """
    Parse argv, execute the Wave 3 CLI command, and return a structured result.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        request = Wave3CliRequest.from_args(args)
        return run_wave3_cli_request(request)
    except Wave3CliError as exc:
        payload = {
            "schema_version": "wave3.cli.error.v1",
            "error": str(exc),
        }
        return Wave3CliResult(
            exit_code=2,
            output_path=None,
            payload=payload,
            errors=(str(exc),),
        )


def main(argv: Sequence[str] | None = None) -> int:
    """
    Console entrypoint for governed Wave 3 authored repair runs.
    """
    result = run_wave3_cli(argv)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return result.exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ix-blackfox-wave3",
        description=(
            "Run a governed IX-BlackFox Wave 3 authored repair path and optional "
            "Wave 2 execution using manually supplied patch proposal JSON."
        ),
    )

    parser.add_argument(
        "--workspace-root",
        required=True,
        help="Repository workspace root.",
    )
    parser.add_argument(
        "--artifact-root",
        default=None,
        help="Artifact root. Defaults to workspace root.",
    )
    parser.add_argument(
        "--policy-path",
        default=None,
        help="Optional path to blackfox.policy.toml.",
    )
    parser.add_argument(
        "--task-id",
        required=True,
        help="Stable task id for the repair run.",
    )
    parser.add_argument(
        "--run-id",
        required=True,
        help="Stable run id for bundle output.",
    )
    parser.add_argument(
        "--objective",
        required=True,
        help="Repair objective.",
    )
    parser.add_argument(
        "--include-path",
        action="append",
        default=[],
        help="Workspace-relative path to include in Wave 3 context. May be repeated.",
    )
    parser.add_argument(
        "--proposal-json",
        action="append",
        default=[],
        help="Raw Wave 3 patch proposal JSON string. May be repeated.",
    )
    parser.add_argument(
        "--proposal-file",
        action="append",
        default=[],
        help="Path to a file containing one raw Wave 3 proposal JSON object. May be repeated.",
    )
    parser.add_argument(
        "--raw-test-output-file",
        default=None,
        help="Optional file containing prior pytest output for authoring evidence.",
    )
    parser.add_argument(
        "--output-path",
        default=None,
        help="Optional path where the combined CLI result JSON should be written.",
    )
    parser.add_argument(
        "--no-workspace-marker",
        action="store_true",
        help="Disable .blackfox-workspace marker requirement.",
    )
    parser.add_argument(
        "--workspace-marker-name",
        default=".blackfox-workspace",
        help="Workspace marker filename.",
    )
    parser.add_argument(
        "--test-command",
        nargs="+",
        default=None,
        help="Wave 2 test command, for example: python -m pytest -q tests.",
    )
    parser.add_argument(
        "--test-working-directory",
        default=".",
        help="Wave 2 test working directory, workspace-relative.",
    )
    parser.add_argument(
        "--test-timeout-seconds",
        type=float,
        default=60.0,
        help="Wave 2 test timeout in seconds.",
    )
    parser.add_argument(
        "--allowed-test-executable",
        action="append",
        default=["python", "python3", "py", "pytest"],
        help="Allowed test executable. May be repeated.",
    )
    parser.add_argument(
        "--authoring-test-return-code",
        type=int,
        default=1,
        help="Return code associated with the supplied raw authoring test output.",
    )
    parser.add_argument(
        "--authoring-test-timed-out",
        action="store_true",
        help="Mark supplied authoring test output as timed out.",
    )

    return parser


def _exit_code_from_acceptance(acceptance: Wave3AcceptanceReport) -> int:
    if acceptance.passed:
        return 0

    if acceptance.requires_review:
        return 10

    if acceptance.blocked:
        return 20

    return 1


def _proposal_source(args: argparse.Namespace) -> str:
    sources: list[str] = []
    if args.proposal_json:
        sources.append("proposal_json")
    if args.proposal_file:
        sources.append("proposal_file")
    return "+".join(sources) if sources else "none"


def _load_proposal_responses(
    *,
    proposal_json: Iterable[str],
    proposal_file: Iterable[str],
) -> tuple[str, ...]:
    responses: list[str] = []

    for raw_json in proposal_json:
        cleaned = raw_json.strip()
        if cleaned:
            responses.append(cleaned)

    for file_name in proposal_file:
        path = Path(file_name).expanduser().resolve()
        if not path.is_file():
            raise Wave3CliError(f"Proposal file does not exist or is not a file: {path}")
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            raise Wave3CliError(f"Proposal file is empty: {path}")
        responses.append(text)

    if not responses:
        raise Wave3CliError("Provide at least one --proposal-json or --proposal-file.")

    return tuple(responses)


def _load_optional_text_file(file_name: str | None) -> str | None:
    if file_name is None:
        return None

    path = Path(file_name).expanduser().resolve()
    if not path.is_file():
        raise Wave3CliError(f"Raw test output file does not exist or is not a file: {path}")

    text = path.read_text(encoding="utf-8")
    return text if text.strip() else None


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(dict(payload), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise Wave3CliError(f"{label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise Wave3CliError(f"{label} must not be empty.")
    return cleaned


def _normalize_string_tuple(
    values: Iterable[str],
    *,
    field_name: str,
) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        if not isinstance(value, str):
            raise Wave3CliError(f"{field_name} must contain only strings.")
        cleaned = value.strip()
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    if not normalized:
        raise Wave3CliError(f"{field_name} must contain at least one value.")

    return tuple(normalized)


if __name__ == "__main__":
    sys.exit(main())
