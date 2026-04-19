"""
Forge subsystem.

Forge is the programming workbench of BlackFox. It ingests code, inspects
symbols, plans patches, executes builds and tests, and verifies results
inside controlled environments. The first concrete layers are workspace
management for isolated file operations, file-graph scanning for stable
repository inventory, and static Python code analysis.
"""

from ix_blackfox.forge.code_analysis import (
    CodeAnalysisSnapshot,
    ForgeCodeAnalyzer,
    PythonClassSymbol,
    PythonFunctionSymbol,
    PythonImportSymbol,
    PythonModuleAnalysis,
)
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
    "CodeAnalysisSnapshot",
    "DirectoryNode",
    "FileGraphSnapshot",
    "FileNode",
    "ForgeCodeAnalyzer",
    "ForgeFileGraphScanner",
    "ForgeWorkspaceError",
    "ForgeWorkspaceManager",
    "PythonClassSymbol",
    "PythonFunctionSymbol",
    "PythonImportSymbol",
    "PythonModuleAnalysis",
    "WorkspaceReservation",
]
