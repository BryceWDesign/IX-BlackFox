"""
Forge subsystem.

Forge is the programming workbench of BlackFox. It ingests code, inspects
symbols, plans patches, executes builds and tests, and verifies results
inside controlled environments. The first concrete layers are workspace
management for isolated file operations, file-graph scanning for stable
repository inventory, static Python code analysis, structured patch
planning, and controlled command execution.
"""

from ix_blackfox.forge.code_analysis import (
    CodeAnalysisSnapshot,
    ForgeCodeAnalyzer,
    PythonClassSymbol,
    PythonFunctionSymbol,
    PythonImportSymbol,
    PythonModuleAnalysis,
)
from ix_blackfox.forge.command_runner import (
    CommandResult,
    CommandSpec,
    ForgeCommandError,
    ForgeCommandRunner,
)
from ix_blackfox.forge.file_graph import (
    DirectoryNode,
    FileGraphSnapshot,
    FileNode,
    ForgeFileGraphScanner,
)
from ix_blackfox.forge.patch_plan import (
    ForgePatchPlanner,
    PatchOperation,
    PatchOperationType,
    PatchPlan,
    PatchPriority,
)
from ix_blackfox.forge.workspace import (
    ForgeWorkspaceError,
    ForgeWorkspaceManager,
    WorkspaceReservation,
)

__all__ = [
    "CodeAnalysisSnapshot",
    "CommandResult",
    "CommandSpec",
    "DirectoryNode",
    "FileGraphSnapshot",
    "FileNode",
    "ForgeCodeAnalyzer",
    "ForgeCommandError",
    "ForgeCommandRunner",
    "ForgeFileGraphScanner",
    "ForgePatchPlanner",
    "ForgeWorkspaceError",
    "ForgeWorkspaceManager",
    "PatchOperation",
    "PatchOperationType",
    "PatchPlan",
    "PatchPriority",
    "PythonClassSymbol",
    "PythonFunctionSymbol",
    "PythonImportSymbol",
    "PythonModuleAnalysis",
    "WorkspaceReservation",
]
