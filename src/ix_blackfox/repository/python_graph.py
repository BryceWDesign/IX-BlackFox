from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from ix_blackfox.repository.models import (
    RepositoryCodeGraph,
    RepositoryDependencyScope,
    RepositoryEdgeKind,
    RepositoryFileRecord,
    RepositoryFileRole,
    RepositoryGraphEdge,
    RepositoryNodeKind,
    RepositorySnapshot,
    RepositorySymbolRecord,
)

GRAPHABLE_PYTHON_ROLES: Final[frozenset[RepositoryFileRole]] = frozenset(
    {
        RepositoryFileRole.SOURCE,
        RepositoryFileRole.TEST,
        RepositoryFileRole.SCRIPT,
    }
)

INTERNAL_MODULE_PREFIXES: Final[tuple[str, ...]] = (
    "ix_blackfox",
    "tests",
    "scripts",
)


@dataclass(frozen=True, slots=True)
class PythonCodeGraphBuilder:
    """Build a conservative Python AST graph without importing repo modules."""

    include_tests: bool = True
    include_scripts: bool = True

    def build(
        self,
        root: str | Path,
        snapshot: RepositorySnapshot,
        *,
        graph_id: str = "wave-8-python-code-graph",
    ) -> RepositoryCodeGraph:
        repo_root = Path(root).resolve()
        if not repo_root.is_dir():
            raise ValueError(f"Repository root does not exist: {repo_root}")

        python_files = self._select_python_files(snapshot)
        module_path_by_name = {
            module_name_from_path(file_record.path): file_record.path
            for file_record in python_files
        }

        symbols: list[RepositorySymbolRecord] = []
        edges: list[RepositoryGraphEdge] = []
        syntax_error_paths: list[str] = []

        for file_record in python_files:
            module_name = module_name_from_path(file_record.path)
            source_path = repo_root / file_record.path
            try:
                source_text = source_path.read_text(encoding="utf-8")
                tree = ast.parse(source_text, filename=file_record.path)
            except (OSError, UnicodeDecodeError, SyntaxError):
                syntax_error_paths.append(file_record.path)
                continue

            symbols.append(
                RepositorySymbolRecord(
                    path=file_record.path,
                    qualified_name=module_name,
                    kind=RepositoryNodeKind.MODULE,
                    line=1,
                    metadata={"role": file_record.role.value},
                )
            )
            symbols.extend(extract_python_symbols(tree, file_record.path, module_name))
            edges.extend(
                extract_python_import_edges(
                    tree,
                    source_path=file_record.path,
                    source_module=module_name,
                    module_path_by_name=module_path_by_name,
                )
            )

        return RepositoryCodeGraph(
            graph_id=graph_id,
            symbols=tuple(symbols),
            edges=tuple(deduplicate_edges(edges)),
            syntax_error_paths=tuple(syntax_error_paths),
            metadata={
                "builder": "python-ast",
                "graphable_file_count": len(python_files),
                "internal_prefixes": list(INTERNAL_MODULE_PREFIXES),
            },
        )

    def _select_python_files(
        self,
        snapshot: RepositorySnapshot,
    ) -> tuple[RepositoryFileRecord, ...]:
        selected: list[RepositoryFileRecord] = []
        for file_record in snapshot.files:
            if not file_record.path.endswith(".py"):
                continue
            if file_record.role not in GRAPHABLE_PYTHON_ROLES:
                continue
            if file_record.role is RepositoryFileRole.TEST and not self.include_tests:
                continue
            if file_record.role is RepositoryFileRole.SCRIPT and not self.include_scripts:
                continue
            selected.append(file_record)
        return tuple(selected)


def build_python_code_graph(
    root: str | Path,
    snapshot: RepositorySnapshot,
    *,
    graph_id: str = "wave-8-python-code-graph",
) -> RepositoryCodeGraph:
    """Convenience wrapper for the default Wave 8 Python AST graph."""
    return PythonCodeGraphBuilder().build(root, snapshot, graph_id=graph_id)


def extract_python_symbols(
    tree: ast.Module,
    path: str,
    module_name: str,
) -> tuple[RepositorySymbolRecord, ...]:
    symbols: list[RepositorySymbolRecord] = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            symbols.append(
                RepositorySymbolRecord(
                    path=path,
                    qualified_name=f"{module_name}.{node.name}",
                    kind=RepositoryNodeKind.CLASS,
                    line=node.lineno,
                    column=node.col_offset,
                    metadata={"decorators": decorator_names(node.decorator_list)},
                )
            )
            symbols.extend(extract_method_symbols(node, path, module_name))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            symbols.append(
                RepositorySymbolRecord(
                    path=path,
                    qualified_name=f"{module_name}.{node.name}",
                    kind=RepositoryNodeKind.FUNCTION,
                    line=node.lineno,
                    column=node.col_offset,
                    metadata={
                        "async": isinstance(node, ast.AsyncFunctionDef),
                        "decorators": decorator_names(node.decorator_list),
                    },
                )
            )
        elif isinstance(node, ast.Assign):
            symbols.extend(
                extract_constant_symbols(node.targets, path, module_name, node.lineno)
            )
        elif isinstance(node, ast.AnnAssign):
            symbols.extend(
                extract_constant_symbols((node.target,), path, module_name, node.lineno)
            )
    return tuple(symbols)


def extract_method_symbols(
    node: ast.ClassDef,
    path: str,
    module_name: str,
) -> tuple[RepositorySymbolRecord, ...]:
    symbols: list[RepositorySymbolRecord] = []
    for child in node.body:
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            symbols.append(
                RepositorySymbolRecord(
                    path=path,
                    qualified_name=f"{module_name}.{node.name}.{child.name}",
                    kind=RepositoryNodeKind.METHOD,
                    line=child.lineno,
                    column=child.col_offset,
                    metadata={
                        "async": isinstance(child, ast.AsyncFunctionDef),
                        "class": node.name,
                        "decorators": decorator_names(child.decorator_list),
                    },
                )
            )
    return tuple(symbols)


def extract_constant_symbols(
    targets: tuple[ast.expr, ...] | list[ast.expr],
    path: str,
    module_name: str,
    lineno: int,
) -> tuple[RepositorySymbolRecord, ...]:
    symbols: list[RepositorySymbolRecord] = []
    for target in targets:
        for name in assignment_target_names(target):
            if name.isupper():
                symbols.append(
                    RepositorySymbolRecord(
                        path=path,
                        qualified_name=f"{module_name}.{name}",
                        kind=RepositoryNodeKind.CONSTANT,
                        line=lineno,
                    )
                )
    return tuple(symbols)


def assignment_target_names(target: ast.expr) -> tuple[str, ...]:
    if isinstance(target, ast.Name):
        return (target.id,)
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for element in target.elts:
            names.extend(assignment_target_names(element))
        return tuple(names)
    return ()


def extract_python_import_edges(
    tree: ast.Module,
    *,
    source_path: str,
    source_module: str,
    module_path_by_name: dict[str, str],
) -> tuple[RepositoryGraphEdge, ...]:
    edges: list[RepositoryGraphEdge] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                target_module = alias.name
                edges.append(
                    build_import_edge(
                        source_path=source_path,
                        source_module=source_module,
                        target_module=target_module,
                        imported_name=None,
                        module_path_by_name=module_path_by_name,
                        line=node.lineno,
                        alias=alias.asname,
                        import_kind="import",
                        level=0,
                    )
                )
        elif isinstance(node, ast.ImportFrom):
            target_module = resolve_from_import_module(
                source_module=source_module,
                raw_module=node.module,
                level=node.level,
            )
            for alias in node.names:
                edges.append(
                    build_import_edge(
                        source_path=source_path,
                        source_module=source_module,
                        target_module=target_module,
                        imported_name=alias.name,
                        module_path_by_name=module_path_by_name,
                        line=node.lineno,
                        alias=alias.asname,
                        import_kind="from_import",
                        level=node.level,
                    )
                )
    return tuple(edges)


def build_import_edge(
    *,
    source_path: str,
    source_module: str,
    target_module: str,
    imported_name: str | None,
    module_path_by_name: dict[str, str],
    line: int,
    alias: str | None,
    import_kind: str,
    level: int,
) -> RepositoryGraphEdge:
    resolved_module = resolve_imported_module(
        target_module,
        imported_name,
        module_path_by_name,
    )
    resolved_path = module_path_by_name.get(resolved_module)
    is_internal = is_internal_module(resolved_module) or resolved_path is not None
    return RepositoryGraphEdge(
        source=source_module,
        target=resolved_module,
        kind=RepositoryEdgeKind.IMPORTS,
        scope=(
            RepositoryDependencyScope.INTERNAL
            if is_internal
            else RepositoryDependencyScope.UNKNOWN
        ),
        reason=f"{import_kind} at {source_path}:{line}",
        metadata={
            "alias": alias,
            "imported_name": imported_name,
            "level": level,
            "line": line,
            "resolved_path": resolved_path,
            "source_path": source_path,
            "target_module": target_module,
        },
    )


def resolve_imported_module(
    target_module: str,
    imported_name: str | None,
    module_path_by_name: dict[str, str],
) -> str:
    if target_module in module_path_by_name:
        return target_module
    if imported_name:
        candidate = f"{target_module}.{imported_name}"
        if candidate in module_path_by_name:
            return candidate
    return target_module


def resolve_from_import_module(
    *,
    source_module: str,
    raw_module: str | None,
    level: int,
) -> str:
    if level == 0:
        return raw_module or "unknown"

    source_parts = source_module.split(".")
    package_parts = source_parts[:-1]
    base_count = max(0, len(package_parts) - level + 1)
    base_parts = package_parts[:base_count]
    if raw_module:
        base_parts.extend(raw_module.split("."))
    return ".".join(part for part in base_parts if part) or "unknown"


def module_name_from_path(relative_path: str) -> str:
    path = PurePosixPath(relative_path.strip().replace("\\", "/"))
    if path.suffix == ".py":
        path = path.with_suffix("")
    parts = list(path.parts)
    if parts and parts[0] == "src":
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) or "__root__"


def decorator_names(decorators: list[ast.expr]) -> tuple[str, ...]:
    return tuple(filter(None, (dotted_name(decorator) for decorator in decorators)))


def dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return dotted_name(node.func)
    return None


def is_internal_module(module_name: str) -> bool:
    return any(
        module_name == prefix or module_name.startswith(f"{prefix}.")
        for prefix in INTERNAL_MODULE_PREFIXES
    )


def deduplicate_edges(edges: list[RepositoryGraphEdge]) -> tuple[RepositoryGraphEdge, ...]:
    deduped: list[RepositoryGraphEdge] = []
    seen: set[tuple[str, str, str, str]] = set()
    for edge in edges:
        key = (edge.source, edge.target, edge.reason, str(edge.metadata.get("line", "")))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(edge)
    return tuple(deduped)
