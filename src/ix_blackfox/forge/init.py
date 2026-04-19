"""
Forge subsystem.

Forge is the programming workbench of BlackFox. It ingests code, inspects
symbols, plans patches, executes builds and tests, and verifies results
inside controlled environments. The first concrete layer is workspace
management for isolated file operations.
"""

from ix_blackfox.forge.workspace import (
    ForgeWorkspaceError,
    ForgeWorkspaceManager,
    WorkspaceReservation,
)

__all__ = [
    "ForgeWorkspaceError",
    "ForgeWorkspaceManager",
    "WorkspaceReservation",
]
