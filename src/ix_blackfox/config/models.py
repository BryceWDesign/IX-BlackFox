from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AppPaths:
    """
    Canonical runtime paths for IX-BlackFox.

    Attributes
    ----------
    root_dir:
        Repository or deployment root.
    state_dir:
        Durable local application state.
    runtime_dir:
        Transient runtime files.
    artifacts_dir:
        Generated artifacts and outputs.
    logs_dir:
        Log file location.
    temp_dir:
        Temporary working directory for short-lived files.
    """

    root_dir: Path
    state_dir: Path
    runtime_dir: Path
    artifacts_dir: Path
    logs_dir: Path
    temp_dir: Path

    def ensure_exists(self) -> None:
        """
        Create the runtime directory tree if it does not already exist.
        """
        for directory in (
            self.state_dir,
            self.runtime_dir,
            self.artifacts_dir,
            self.logs_dir,
            self.temp_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    """
    Typed runtime configuration for IX-BlackFox.

    Attributes
    ----------
    app_name:
        Stable application identifier.
    environment:
        Runtime environment label, such as development, test, or production.
    log_level:
        Normalized application log level.
    debug:
        Whether debug mode is enabled.
    paths:
        Resolved runtime paths.
    config_file:
        Optional configuration file path that contributed values.
    """

    app_name: str
    environment: str
    log_level: str
    debug: bool
    paths: AppPaths
    config_file: Path | None = None
