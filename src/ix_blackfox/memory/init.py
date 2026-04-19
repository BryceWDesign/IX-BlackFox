"""
Memory subsystem.

BlackFox memory is tiered into working, episodic, semantic, artifact,
and trace layers so the runtime can preserve context without collapsing
everything into a single unstructured history blob. The first concrete
layers are working memory for live execution context, episodic memory
for session-scoped recollection of prior outcomes, semantic memory
for distilled reusable facts and constraints, and artifact memory for
durable runtime outputs and files.
"""

from ix_blackfox.memory.artifact import (
    ArtifactMemorySnapshot,
    ArtifactMemoryStore,
    ArtifactRecord,
)
from ix_blackfox.memory.episodic import (
    EpisodeRecord,
    EpisodicMemorySnapshot,
    EpisodicMemoryStore,
)
from ix_blackfox.memory.semantic import (
    SemanticMemoryRecord,
    SemanticMemorySnapshot,
    SemanticMemoryStore,
)
from ix_blackfox.memory.working import (
    WorkingMemoryItem,
    WorkingMemorySnapshot,
    WorkingMemoryStore,
)

__all__ = [
    "ArtifactMemorySnapshot",
    "ArtifactMemoryStore",
    "ArtifactRecord",
    "EpisodeRecord",
    "EpisodicMemorySnapshot",
    "EpisodicMemoryStore",
    "SemanticMemoryRecord",
    "SemanticMemorySnapshot",
    "SemanticMemoryStore",
    "WorkingMemoryItem",
    "WorkingMemorySnapshot",
    "WorkingMemoryStore",
]
