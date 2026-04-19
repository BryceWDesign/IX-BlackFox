from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from uuid import uuid4

from ix_blackfox.config import RuntimeConfig


@dataclass(frozen=True, slots=True)
class WorkspaceReservation:
    """
    One reserved forge workspace.

    Attributes
    ----------
    workspace_id:
        Stable unique workspace identifier.
    root_path:
        Root directory of the reserved workspace.
    input_path:
        Directory for input material copied into the workspace.
    output_path:
        Directory for generated outputs.
    scratch_path:
        Directory for transient intermediate files.
    """

    workspace_id: str
    root_path: Path
    input_path: Path
    output_path: Path
    scratch_path: Path

    def ensure_exists(self) -> None:
        """
        Create the workspace directory tree if it does not already exist.
        """
        self.root_path.mkdir(parents=True, exist_ok=True)
        self.input_path.mkdir(parents=True, exist_ok=True)
        self.output_path.mkdir(parents=True, exist_ok=True)
        self.scratch_path.mkdir(parents=True, exist_ok=True)


class ForgeWorkspaceError(RuntimeError):
    """
    Raised when forge workspace operations fail validation or isolation checks.
    """


class ForgeWorkspaceManager:
    """
    Controlled workspace manager for BlackFox forge operations.

    Workspaces are reserved under the configured runtime temp directory so
    patch planning, builds, tests, and generated artifacts occur inside a
    predictable boundary instead of leaking across arbitrary paths.
    """

    def __init__(self, config: RuntimeConfig) -> None:
        self._config = config
        self._base_dir = (config.paths.temp_dir / "forge").resolve()
        self._lock = RLock()
        self._base_dir.mkdir(parents=True, exist_ok=True)

    @property
    def base_dir(self) -> Path:
        """
        Root directory that contains all forge workspaces.
        """
        return self._base_dir

    def reserve(self, *, prefix: str = "job") -> WorkspaceReservation:
        """
        Reserve a new isolated forge workspace.
        """
        normalized_prefix = _normalize_identifier(prefix, label="workspace prefix")
        workspace_id = f"{normalized_prefix}-{uuid4().hex[:12]}"
        root_path = (self._base_dir / workspace_id).resolve()

        self._assert_under_base(root_path)

        reservation = WorkspaceReservation(
            workspace_id=workspace_id,
            root_path=root_path,
            input_path=root_path / "input",
            output_path=root_path / "output",
            scratch_path=root_path / "scratch",
        )
        reservation.ensure_exists()
        return reservation

    def materialize_file(
        self,
        *,
        workspace: WorkspaceReservation,
        relative_path: str,
        content: str,
        encoding: str = "utf-8",
    ) -> Path:
        """
        Write text content into a workspace-relative path.
        """
        target_path = self.resolve_path(
            workspace=workspace,
            relative_path=relative_path,
        )
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(content, encoding=encoding)
        return target_path

    def copy_into_workspace(
        self,
        *,
        workspace: WorkspaceReservation,
        source_path: Path,
        destination_relative_path: str | None = None,
    ) -> Path:
        """
        Copy an existing file or directory into the workspace input tree.
        """
        resolved_source = source_path.resolve()
        if not resolved_source.exists():
            raise ForgeWorkspaceError(
                f"Source path does not exist: {resolved_source}"
            )

        destination_name = (
            destination_relative_path
            if destination_relative_path is not None
            else resolved_source.name
        )
        destination_path = self.resolve_path(
            workspace=workspace,
            relative_path=f"input/{destination_name}",
        )

        if resolved_source.is_dir():
            if destination_path.exists():
                shutil.rmtree(destination_path)
            shutil.copytree(resolved_source, destination_path)
        else:
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(resolved_source, destination_path)

        return destination_path

    def resolve_path(
        self,
        *,
        workspace: WorkspaceReservation,
        relative_path: str,
    ) -> Path:
        """
        Resolve a relative path safely within a workspace boundary.
        """
        normalized_relative = relative_path.strip()
        if not normalized_relative:
            raise ForgeWorkspaceError("Workspace relative path must not be empty.")

        candidate = (workspace.root_path / normalized_relative).resolve()
        self._assert_within_workspace(workspace=workspace, candidate=candidate)
        return candidate

    def read_text(
        self,
        *,
        workspace: WorkspaceReservation,
        relative_path: str,
        encoding: str = "utf-8",
    ) -> str:
        """
        Read text content from a workspace-relative path.
        """
        path = self.resolve_path(workspace=workspace, relative_path=relative_path)
        if not path.is_file():
            raise ForgeWorkspaceError(f"Workspace file does not exist: {path}")
        return path.read_text(encoding=encoding)

    def remove(self, workspace: WorkspaceReservation) -> bool:
        """
        Remove a reserved workspace directory tree.
        """
        with self._lock:
            if not workspace.root_path.exists():
                return False
            self._assert_under_base(workspace.root_path)
            shutil.rmtree(workspace.root_path)
            return True

    def list_workspaces(self) -> tuple[Path, ...]:
        """
        Return all current workspace roots in sorted order.
        """
        with self._lock:
            workspaces = tuple(
                sorted(
                    path.resolve()
                    for path in self._base_dir.iterdir()
                    if path.is_dir()
                )
            )
        return workspaces

    def clear(self) -> None:
        """
        Remove all forge workspaces under the managed base directory.
        """
        with self._lock:
            for path in self._base_dir.iterdir():
                if path.is_dir():
                    shutil.rmtree(path)

    def _assert_within_workspace(
        self,
        *,
        workspace: WorkspaceReservation,
        candidate: Path,
    ) -> None:
        if not _is_relative_to(candidate, workspace.root_path):
            raise ForgeWorkspaceError(
                "Resolved path escapes the reserved workspace boundary."
            )

    def _assert_under_base(self, candidate: Path) -> None:
        if not _is_relative_to(candidate, self._base_dir):
            raise ForgeWorkspaceError(
                "Workspace path escapes the forge base directory."
            )


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"Forge {label} must not be empty.")
    return cleaned


def _is_relative_to(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
    except ValueError:
        return False
    return True
