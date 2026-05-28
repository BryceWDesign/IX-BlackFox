"""
Repository-intelligence primitives for IX-BlackFox Wave 8.

The repository package builds deterministic, reviewable evidence about a
workspace before model-assisted code-change decisions are trusted. The first
Wave 8 layers expose stable model contracts, deterministic inventory scanning,
and conservative Python AST graph extraction without importing repository code.
"""

from __future__ import annotations

from ix_blackfox.repository.inventory import (
    RepositoryInventoryScanner,
    build_file_record,
    classify_generated_reason,
    classify_repository_file,
    classify_repository_sensitivity,
    hash_file,
    is_text_repository_file,
    scan_repository,
)
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
from ix_blackfox.repository.python_graph import (
    PythonCodeGraphBuilder,
    assignment_target_names,
    build_python_code_graph,
    decorator_names,
    dotted_name,
    extract_constant_symbols,
    extract_method_symbols,
    extract_python_import_edges,
    extract_python_symbols,
    is_internal_module,
    module_name_from_path,
    resolve_from_import_module,
    resolve_imported_module,
)

__all__ = [
    "PythonCodeGraphBuilder",
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
    "RepositoryInventoryScanner",
    "RepositoryNodeKind",
    "RepositorySensitivity",
    "RepositorySnapshot",
    "RepositorySymbolRecord",
    "assignment_target_names",
    "build_file_record",
    "build_python_code_graph",
    "classify_generated_reason",
    "classify_repository_file",
    "classify_repository_sensitivity",
    "decorator_names",
    "digest_payload",
    "dotted_name",
    "extract_constant_symbols",
    "extract_method_symbols",
    "extract_python_import_edges",
    "extract_python_symbols",
    "hash_file",
    "is_internal_module",
    "is_text_repository_file",
    "module_name_from_path",
    "resolve_from_import_module",
    "resolve_imported_module",
    "scan_repository",
]
