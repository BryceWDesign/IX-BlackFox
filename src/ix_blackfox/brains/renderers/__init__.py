from __future__ import annotations

"""
Rendering helpers for the BlackFox brain plane.

These helpers normalize internal conversational state before provider
serialization and offer both a Harmony-oriented renderer and a plain
transcript fallback for safer degraded-mode behavior.
"""

from ix_blackfox.brains.renderers.harmony import (
    HarmonyRenderConfig,
    HarmonyRenderer,
    PlainTranscriptRenderer,
)
from ix_blackfox.brains.renderers.message_normalizer import (
    BrainMessageNormalizer,
    NormalizedConversation,
)

__all__ = [
    "BrainMessageNormalizer",
    "HarmonyRenderConfig",
    "HarmonyRenderer",
    "NormalizedConversation",
    "PlainTranscriptRenderer",
]
