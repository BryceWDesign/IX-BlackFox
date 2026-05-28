"""
Repository-intelligence primitives for IX-BlackFox Wave 8.

The repository package builds deterministic, reviewable evidence about a
workspace before model-assisted code-change decisions are trusted. Commit 1
exposes only the stable model contracts; later Wave 8 commits add scanners,
code graphs, dependency mapping, impact analysis, architectural memory, and CI
evidence export on top of these contracts.
"""

from __future__ import annotations

from ix_blackfox.repository.models import (
    RepositoryArchitectureRecord,
    RepositoryCodeGraph,
    RepositoryCoverageLink,
    RepositoryDependencyMap,
    RepositoryDependencyRecord,
    RepositoryDependencyScope,
    RepositoryEdgeKind,
    RepositoryFileRecord,
    RepositoryFileRole,
    RepositoryGraphEdge,
    RepositoryImpactFinding,
    RepositoryImpactReport,
    RepositoryImpactSeverity,
    RepositoryNodeKind,
    RepositorySensitivity,
    RepositorySnapshot,
    RepositorySymbolRecord,
    digest_payload,
)

__all__ = [
    "RepositoryArchitectureRecord",
    "RepositoryCodeGraph",
    "RepositoryCoverageLink",
    "RepositoryDependencyMap",
    "RepositoryDependencyRecord",
    "RepositoryDependencyScope",
    "RepositoryEdgeKind",
    "RepositoryFileRecord",
    "RepositoryFileRole",
    "RepositoryGraphEdge",
    "RepositoryImpactFinding",
    "RepositoryImpactReport",
    "RepositoryImpactSeverity",
    "RepositoryNodeKind",
    "RepositorySensitivity",
    "RepositorySnapshot",
    "RepositorySymbolRecord",
    "digest_payload",
]
