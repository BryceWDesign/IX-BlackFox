"""
Kernel subsystem.

The kernel is the orchestration heart of BlackFox. It owns request intake,
task graph formation, execution lifecycle control, and shared runtime
coordination. The initial implementation establishes lifecycle discipline
first so later orchestration layers have a stable base to build on.
"""

from ix_blackfox.kernel.runtime import BlackFoxKernel, KernelSnapshot, KernelStatus
from ix_blackfox.kernel.state import SharedStateSnapshot, SharedStateStore, StateEntry
from ix_blackfox.kernel.tasks import (
    TaskInput,
    TaskKind,
    TaskPriority,
    TaskRecord,
    TaskRequest,
    TaskState,
)

__all__ = [
    "BlackFoxKernel",
    "KernelSnapshot",
    "KernelStatus",
    "SharedStateSnapshot",
    "SharedStateStore",
    "StateEntry",
    "TaskInput",
    "TaskKind",
    "TaskPriority",
    "TaskRecord",
    "TaskRequest",
    "TaskState",
]
