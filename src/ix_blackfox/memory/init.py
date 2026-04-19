"""
Memory subsystem.

BlackFox memory is tiered into working, episodic, semantic, artifact,
and trace layers so the runtime can preserve context without collapsing
everything into a single unstructured history blob. The first concrete
layer is working memory for live execution context.
"""

from ix_blackfox.memory.working import (
    WorkingMemoryItem,
    WorkingMemorySnapshot,
    WorkingMemoryStore,
)

__all__ = [
    "WorkingMemoryItem",
    "WorkingMemorySnapshot",
    "WorkingMemoryStore",
]
