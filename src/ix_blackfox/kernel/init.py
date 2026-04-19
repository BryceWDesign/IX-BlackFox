"""
Kernel subsystem.

The kernel is the orchestration heart of BlackFox. It owns request intake,
task graph formation, execution lifecycle control, and shared runtime
coordination. The initial implementation establishes lifecycle discipline
first so later orchestration layers have a stable base to build on.
"""

from ix_blackfox.kernel.runtime import BlackFoxKernel, KernelSnapshot, KernelStatus

__all__ = [
    "BlackFoxKernel",
    "KernelSnapshot",
    "KernelStatus",
]
