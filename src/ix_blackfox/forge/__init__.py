"""
Forge subsystem.

Forge is the programming workbench of BlackFox. It ingests code, inspects
symbols, plans patches, executes builds and tests, and verifies results
inside controlled environments. The first concrete layers are workspace
management for isolated file operations, file-graph scanning for stable
repository inventory, static Python code analysis, structured patch
planning, governed patch-intent bridging, controlled command execution,
governed command mediation, test running, regression result collection,
and governed execution tickets that normalize forge work before runtime
mediation.
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
from ix_blackfox.forge.execution_ticket import (
    ForgeExecutionDisposition,
    ForgeExecutionTicket,
    ForgeExecutionTicketBuilder,
)
from ix_blackfox.forge.file_graph import (
    DirectoryNode,
    FileGraphSnapshot,
    FileNode,
    ForgeFileGraphScanner,
)
from ix_blackfox.forge.governed_command_runner import (
    GovernedCommandRunResult,
    GovernedForgeCommandRunner,
)
from ix_blackfox.forge.governed_patch_intents import (
    ForgePatchIntentBridge,
    GovernedPatchIntentBundle,
)
from ix_blackfox.forge.patch_plan import (
    ForgePatchPlanner,
    PatchOperation,
    PatchOperationType,
    PatchPlan,
    PatchPriority,
)
from ix_blackfox.forge.regression import (
    ForgeRegressionCollector,
    RegressionReport,
    RegressionStatus,
    RegressionSuiteSummary,
)
from ix_blackfox.forge.test_runner import (
    ForgeTestRunner,
    TestRunResult,
    TestRunSpec,
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
    "ForgeExecutionDisposition",
    "ForgeExecutionTicket",
    "ForgeExecutionTicketBuilder",
    "ForgeFileGraphScanner",
    "ForgePatchIntentBridge",
    "ForgePatchPlanner",
    "ForgeRegressionCollector",
    "ForgeTestRunner",
    "ForgeWorkspaceError",
    "ForgeWorkspaceManager",
    "GovernedCommandRunResult",
    "GovernedForgeCommandRunner",
    "GovernedPatchIntentBundle",
    "PatchOperation",
    "PatchOperationType",
    "PatchPlan",
    "PatchPriority",
    "PythonClassSymbol",
    "PythonFunctionSymbol",
    "PythonImportSymbol",
    "PythonModuleAnalysis",
    "RegressionReport",
    "RegressionStatus",
    "RegressionSuiteSummary",
    "TestRunResult",
    "TestRunSpec",
    "WorkspaceReservation",
]
