from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from ix_blackfox.forge.workspace import WorkspaceReservation


class ForgeCommandError(RuntimeError):
    """
    Raised when forge command execution fails validation or exceeds limits.
    """


@dataclass(frozen=True, slots=True)
class CommandSpec:
    """
    One forge command invocation specification.

    Attributes
    ----------
    argv:
        Command argument vector. Shell execution is intentionally not used.
    cwd_relative_path:
        Workspace-relative working directory for the command.
    timeout_seconds:
        Maximum allowed execution time before the command is terminated.
    env_overrides:
        Optional environment variable overrides for the process.
    """

    argv: tuple[str, ...]
    cwd_relative_path: str = "."
    timeout_seconds: float = 30.0
    env_overrides: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized_argv = tuple(part.strip() for part in self.argv if part.strip())
        if not normalized_argv:
            raise ValueError("Forge command argv must not be empty.")
        if self.timeout_seconds <= 0:
            raise ValueError("Forge command timeout must be greater than zero.")

        normalized_cwd = _normalize_relative_path(self.cwd_relative_path)
        normalized_env = {
            key.strip(): value
            for key, value in self.env_overrides.items()
            if key.strip()
        }

        object.__setattr__(self, "argv", normalized_argv)
        object.__setattr__(self, "cwd_relative_path", normalized_cwd)
        object.__setattr__(self, "env_overrides", normalized_env)


@dataclass(frozen=True, slots=True)
class CommandResult:
    """
    Result of one forge command execution.

    Attributes
    ----------
    argv:
        Executed argument vector.
    cwd_path:
        Resolved working directory used for execution.
    exit_code:
        Process exit code.
    stdout:
        Captured standard output text.
    stderr:
        Captured standard error text.
    started_at:
        UTC timestamp when execution began.
    finished_at:
        UTC timestamp when execution ended.
    duration_seconds:
        Measured wall-clock duration.
    """

    argv: tuple[str, ...]
    cwd_path: Path
    exit_code: int
    stdout: str
    stderr: str
    started_at: datetime
    finished_at: datetime
    duration_seconds: float

    @property
    def succeeded(self) -> bool:
        """
        Return True when the command exited with status code zero.
        """
        return self.exit_code == 0


class ForgeCommandRunner:
    """
    Controlled command runner for forge workspaces.

    Commands execute without a shell and are restricted to a reserved
    workspace boundary so downstream build, test, and verification steps
    stay auditable and contained.
    """

    def run(
        self,
        *,
        workspace: WorkspaceReservation,
        spec: CommandSpec,
    ) -> CommandResult:
        """
        Execute one command inside a reserved workspace.
        """
        cwd_path = self._resolve_cwd(
            workspace=workspace,
            relative_path=spec.cwd_relative_path,
        )
        env = os.environ.copy()
        env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
        env.update(spec.env_overrides)

        started_at = _utc_now()
        started_perf = time.perf_counter()

        try:
            completed = subprocess.run(
                spec.argv,
                cwd=str(cwd_path),
                env=env,
                capture_output=True,
                text=True,
                timeout=spec.timeout_seconds,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ForgeCommandError(
                f"Forge command timed out after {spec.timeout_seconds} seconds."
            ) from exc
        except OSError as exc:
            raise ForgeCommandError(f"Forge command failed to start: {exc}") from exc

        finished_at = _utc_now()
        duration_seconds = time.perf_counter() - started_perf

        return CommandResult(
            argv=spec.argv,
            cwd_path=cwd_path,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=duration_seconds,
        )

    def _resolve_cwd(
        self,
        *,
        workspace: WorkspaceReservation,
        relative_path: str,
    ) -> Path:
        candidate = (workspace.root_path / relative_path).resolve()
        if not _is_relative_to(candidate, workspace.root_path):
            raise ForgeCommandError(
                "Resolved command working directory escapes the workspace boundary."
            )
        if not candidate.exists():
            raise ForgeCommandError(
                f"Command working directory does not exist: {candidate}"
            )
        if not candidate.is_dir():
            raise ForgeCommandError(
                f"Command working directory is not a directory: {candidate}"
            )
        return candidate


def _normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("Forge command working directory must not be empty.")
    return cleaned


def _is_relative_to(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
    except ValueError:
        return False
    return True


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
