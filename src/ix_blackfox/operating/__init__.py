"""
Wave 10 AI engineering operating-system primitives.

The operating package is the top-level Wave 10 layer for multi-repo,
multi-team, policy-governed, measurable, replayable, and reviewable AI-assisted
engineering workflows. Commit 1 establishes deterministic artifact envelopes,
finding records, evidence references, digest helpers, and the canonical Wave 10
domain vocabulary used by later registry, campaign, replay, review, scorecard,
and export layers.
"""

from __future__ import annotations

from ix_blackfox.operating.models import (
    WAVE10_OPERATING_SCHEMA_VERSION,
    OperatingArtifactKind,
    OperatingArtifactRef,
    OperatingDisposition,
    OperatingDomain,
    OperatingEnvelope,
    OperatingFinding,
    OperatingSeverity,
    OperatingSourceWave,
    digest_payload,
    normalize_dotted_name,
    normalize_identifier,
    normalize_optional_text,
    normalize_path_tuple,
    normalize_relative_path,
    normalize_sha256,
    normalize_text,
    unique_sorted_enum_tuple,
)

__all__ = [
    "WAVE10_OPERATING_SCHEMA_VERSION",
    "OperatingArtifactKind",
    "OperatingArtifactRef",
    "OperatingDisposition",
    "OperatingDomain",
    "OperatingEnvelope",
    "OperatingFinding",
    "OperatingSeverity",
    "OperatingSourceWave",
    "digest_payload",
    "normalize_dotted_name",
    "normalize_identifier",
    "normalize_optional_text",
    "normalize_path_tuple",
    "normalize_relative_path",
    "normalize_sha256",
    "normalize_text",
    "unique_sorted_enum_tuple",
]
