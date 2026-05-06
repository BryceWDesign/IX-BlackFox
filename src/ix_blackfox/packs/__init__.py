"""
Capability and knowledge packs.

Packs are the internal specialist units of BlackFox. They define tools,
domain scope, validation rules, and task-handling behavior without
splitting the system into separate repositories. The initial layer is
manifest-driven so routing and loading decisions can be explicit and
testable before executable pack logic is introduced.
"""

from ix_blackfox.packs.base import (
    BasePack,
    PackBrainContext,
    PackContext,
    PackExecutionResult,
)
from ix_blackfox.packs.loader import (
    PackLoadError,
    PackLoader,
    PackRegistry,
)
from ix_blackfox.packs.manifest import (
    PackCapability,
    PackCapabilityType,
    PackManifest,
    PackSafetyBoundary,
)

__all__ = [
    "BasePack",
    "PackBrainContext",
    "PackCapability",
    "PackCapabilityType",
    "PackContext",
    "PackExecutionResult",
    "PackLoadError",
    "PackLoader",
    "PackManifest",
    "PackRegistry",
    "PackSafetyBoundary",
]
