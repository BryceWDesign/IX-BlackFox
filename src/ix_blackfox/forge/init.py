"""
Forge subsystem.

Forge is the programming workbench of BlackFox. It ingests code, inspects
symbols, plans patches, executes builds and tests, and verifies results
inside controlled environments. The first concrete layers are workspace
management for isolated file operations and file-graph scanning for
stable repository inventory.
"""

from ix_blackfox.forge.file_graph import (
    DirectoryNode,
    FileGraphSnapshot,
    FileNode,
    ForgeFileGraphScanner,
)
from ix_blackfox.forge.workspace import (
    ForgeWorkspaceError,
    ForgeWorkspaceManager,
    WorkspaceReservation,
)

__all__ = [
    "DirectoryNode",
    "FileGraphSnapshot",
    "FileNode",
    "ForgeFileGraphScanner",
    "ForgeWorkspaceError",
    "ForgeWorkspaceManager",
    "WorkspaceReservation",
]
