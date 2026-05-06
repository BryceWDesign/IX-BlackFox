from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from ix_blackfox.forge.workspace import ForgeWorkspaceError, WorkspaceReservation

TEXT_SUFFIXES: Final[frozenset[str]] = frozenset(
    {
        ".bat",
        ".c",
        ".cc",
        ".cfg",
        ".cpp",
        ".cs",
        ".css",
        ".csv",
        ".go",
        ".h",
        ".hpp",
        ".html",
        ".ini",
        ".java",
        ".js",
        ".json",
        ".jsx",
        ".kt",
        ".lua",
        ".md",
        ".py",
        ".rb",
        ".rs",
        ".sh",
        ".sql",
        ".swift",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)


@dataclass(frozen=True, slots=True)
class FileNode:
    """
    One discovered file within a forge workspace graph.

    Attributes
    ----------
    relative_path:
        Path relative to the workspace root.
    absolute_path:
        Resolved filesystem path to the file.
    suffix:
        Lowercase file suffix, or an empty string if none exists.
    size_bytes:
        File size in bytes.
    is_text:
        Whether the file is treated as text for downstream analysis.
    depth:
        Path depth relative to the workspace root.
    """

    relative_path: str
    absolute_path: Path
    suffix: str
    size_bytes: int
    is_text: bool
    depth: int


@dataclass(frozen=True, slots=True)
class DirectoryNode:
    """
    One discovered directory within a forge workspace graph.

    Attributes
    ----------
    relative_path:
        Directory path relative to the workspace root.
    absolute_path:
        Resolved filesystem path to the directory.
    depth:
        Path depth relative to the workspace root.
    """

    relative_path: str
    absolute_path: Path
    depth: int


@dataclass(frozen=True, slots=True)
class FileGraphSnapshot:
    """
    Immutable view of a scanned workspace file graph.
    """

    root_path: Path
    directories: tuple[DirectoryNode, ...] = field(default_factory=tuple)
    files: tuple[FileNode, ...] = field(default_factory=tuple)

    def file_count(self) -> int:
        """
        Return the total number of files in the graph.
        """
        return len(self.files)

    def directory_count(self) -> int:
        """
        Return the total number of directories in the graph.
        """
        return len(self.directories)

    def total_size_bytes(self) -> int:
        """
        Return the aggregate size of all scanned files.
        """
        return sum(node.size_bytes for node in self.files)

    def text_files(self) -> tuple[FileNode, ...]:
        """
        Return only text-classified files.
        """
        return tuple(node for node in self.files if node.is_text)

    def files_by_suffix(self, suffix: str) -> tuple[FileNode, ...]:
        """
        Return all files matching a suffix.
        """
        normalized_suffix = _normalize_suffix(suffix)
        return tuple(node for node in self.files if node.suffix == normalized_suffix)

    def get_file(self, relative_path: str) -> FileNode | None:
        """
        Retrieve one file node by relative path.
        """
        normalized_path = _normalize_relative_path(relative_path)
        for node in self.files:
            if node.relative_path == normalized_path:
                return node
        return None


class ForgeFileGraphScanner:
    """
    Deterministic scanner that builds a lightweight file graph.

    This scanner is intentionally filesystem-focused. It does not parse
    language syntax yet; it produces a stable inventory of directories
    and files so later forge layers can target analysis precisely.
    """

    def __init__(
        self,
        *,
        text_suffixes: frozenset[str] | None = None,
    ) -> None:
        self._text_suffixes = text_suffixes or TEXT_SUFFIXES

    def scan(self, workspace: WorkspaceReservation) -> FileGraphSnapshot:
        """
        Scan one reserved workspace and build a file graph snapshot.
        """
        if not workspace.root_path.is_dir():
            raise ForgeWorkspaceError(
                f"Workspace root does not exist: {workspace.root_path}"
            )

        directories: list[DirectoryNode] = []
        files: list[FileNode] = []

        for path in sorted(workspace.root_path.rglob("*")):
            resolved = path.resolve()
            relative = resolved.relative_to(workspace.root_path).as_posix()
            depth = len(Path(relative).parts)

            if path.is_dir():
                directories.append(
                    DirectoryNode(
                        relative_path=relative,
                        absolute_path=resolved,
                        depth=depth,
                    )
                )
                continue

            if not path.is_file():
                continue

            suffix = path.suffix.lower()
            files.append(
                FileNode(
                    relative_path=relative,
                    absolute_path=resolved,
                    suffix=suffix,
                    size_bytes=path.stat().st_size,
                    is_text=suffix in self._text_suffixes,
                    depth=depth,
                )
            )

        return FileGraphSnapshot(
            root_path=workspace.root_path,
            directories=tuple(directories),
            files=tuple(files),
        )


def _normalize_suffix(value: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError("Forge file suffix must not be empty.")
    if not cleaned.startswith("."):
        cleaned = f".{cleaned}"
    return cleaned


def _normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("Forge relative path must not be empty.")
    return cleaned
