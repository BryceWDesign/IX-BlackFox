from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from ix_blackfox.forge.file_graph import FileGraphSnapshot, FileNode


@dataclass(frozen=True, slots=True)
class PythonImportSymbol:
    """
    One discovered Python import symbol.

    Attributes
    ----------
    module:
        Imported module path, if any.
    name:
        Imported symbol name.
    alias:
        Optional alias used in the import statement.
    is_from_import:
        Whether the import originated from a ``from ... import ...`` statement.
    level:
        Relative import level for ``from`` imports.
    """

    module: str | None
    name: str
    alias: str | None = None
    is_from_import: bool = False
    level: int = 0


@dataclass(frozen=True, slots=True)
class PythonFunctionSymbol:
    """
    One discovered Python function symbol.
    """

    name: str
    lineno: int
    end_lineno: int | None
    is_async: bool = False


@dataclass(frozen=True, slots=True)
class PythonClassSymbol:
    """
    One discovered Python class symbol.
    """

    name: str
    lineno: int
    end_lineno: int | None
    method_names: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class PythonModuleAnalysis:
    """
    Structured analysis result for one Python module.
    """

    relative_path: str
    module_name: str
    absolute_path: Path
    line_count: int
    import_count: int
    function_count: int
    class_count: int
    imports: tuple[PythonImportSymbol, ...] = field(default_factory=tuple)
    functions: tuple[PythonFunctionSymbol, ...] = field(default_factory=tuple)
    classes: tuple[PythonClassSymbol, ...] = field(default_factory=tuple)
    docstring: str | None = None
    syntax_error: str | None = None

    @property
    def is_valid_python(self) -> bool:
        """
        Return True when the module parsed without syntax errors.
        """
        return self.syntax_error is None


@dataclass(frozen=True, slots=True)
class CodeAnalysisSnapshot:
    """
    Immutable view of forge code-analysis results.
    """

    python_modules: tuple[PythonModuleAnalysis, ...] = field(default_factory=tuple)

    def module_count(self) -> int:
        """
        Return the total number of analyzed Python modules.
        """
        return len(self.python_modules)

    def valid_module_count(self) -> int:
        """
        Return the number of Python modules without syntax errors.
        """
        return sum(1 for module in self.python_modules if module.is_valid_python)

    def get_module(self, relative_path: str) -> PythonModuleAnalysis | None:
        """
        Retrieve one analyzed module by relative path.
        """
        normalized_path = _normalize_relative_path(relative_path)
        for module in self.python_modules:
            if module.relative_path == normalized_path:
                return module
        return None


class ForgeCodeAnalyzer:
    """
    Static code analyzer for forge workspace inventories.

    The first pass focuses on Python modules only. It extracts imports,
    top-level functions, classes, and docstrings without mutating files
    or executing any code.
    """

    def analyze_graph(self, graph: FileGraphSnapshot) -> CodeAnalysisSnapshot:
        """
        Analyze all supported files in a file-graph snapshot.
        """
        modules: list[PythonModuleAnalysis] = []

        for node in graph.files:
            if node.suffix != ".py":
                continue
            modules.append(self.analyze_python_file(node))

        modules.sort(key=lambda module: module.relative_path)
        return CodeAnalysisSnapshot(python_modules=tuple(modules))

    def analyze_python_file(self, node: FileNode) -> PythonModuleAnalysis:
        """
        Analyze one Python source file from a file graph.
        """
        if node.suffix != ".py":
            raise ValueError(
                f"Forge code analysis only supports Python files, got: {node.relative_path}"
            )

        source_text = node.absolute_path.read_text(encoding="utf-8")
        line_count = len(source_text.splitlines())
        module_name = _module_name_from_relative_path(node.relative_path)

        try:
            tree = ast.parse(source_text, filename=node.relative_path)
        except SyntaxError as exc:
            return PythonModuleAnalysis(
                relative_path=node.relative_path,
                module_name=module_name,
                absolute_path=node.absolute_path,
                line_count=line_count,
                import_count=0,
                function_count=0,
                class_count=0,
                docstring=None,
                syntax_error=_format_syntax_error(exc),
            )

        imports = _extract_imports(tree)
        functions = _extract_functions(tree)
        classes = _extract_classes(tree)
        docstring = ast.get_docstring(tree)

        return PythonModuleAnalysis(
            relative_path=node.relative_path,
            module_name=module_name,
            absolute_path=node.absolute_path,
            line_count=line_count,
            import_count=len(imports),
            function_count=len(functions),
            class_count=len(classes),
            imports=imports,
            functions=functions,
            classes=classes,
            docstring=docstring,
            syntax_error=None,
        )


def _extract_imports(tree: ast.Module) -> tuple[PythonImportSymbol, ...]:
    imports: list[PythonImportSymbol] = []

    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(
                    PythonImportSymbol(
                        module=None,
                        name=alias.name,
                        alias=alias.asname,
                        is_from_import=False,
                        level=0,
                    )
                )
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imports.append(
                    PythonImportSymbol(
                        module=node.module,
                        name=alias.name,
                        alias=alias.asname,
                        is_from_import=True,
                        level=node.level,
                    )
                )

    return tuple(imports)


def _extract_functions(tree: ast.Module) -> tuple[PythonFunctionSymbol, ...]:
    functions: list[PythonFunctionSymbol] = []

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(
                PythonFunctionSymbol(
                    name=node.name,
                    lineno=node.lineno,
                    end_lineno=node.end_lineno,
                    is_async=isinstance(node, ast.AsyncFunctionDef),
                )
            )

    return tuple(functions)


def _extract_classes(tree: ast.Module) -> tuple[PythonClassSymbol, ...]:
    classes: list[PythonClassSymbol] = []

    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue

        method_names = tuple(
            child.name
            for child in node.body
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
        classes.append(
            PythonClassSymbol(
                name=node.name,
                lineno=node.lineno,
                end_lineno=node.end_lineno,
                method_names=method_names,
            )
        )

    return tuple(classes)


def _module_name_from_relative_path(relative_path: str) -> str:
    normalized = _normalize_relative_path(relative_path)
    path = Path(normalized)
    without_suffix = path.with_suffix("")
    parts = without_suffix.parts
    return ".".join(parts)


def _format_syntax_error(error: SyntaxError) -> str:
    lineno = "?" if error.lineno is None else str(error.lineno)
    offset = "?" if error.offset is None else str(error.offset)
    message = error.msg.strip()
    return f"line {lineno}, column {offset}: {message}"


def _normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("Forge relative path must not be empty.")
    return cleaned
