from __future__ import annotations

from pathlib import Path

import pytest

from ix_blackfox.config import load_runtime_config
from ix_blackfox.forge import (
    ForgeFileGraphScanner,
    ForgeWorkspaceError,
    ForgeWorkspaceManager,
)


def test_file_graph_scanner_discovers_directories_and_files(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="scan")

    manager.materialize_file(
        workspace=workspace,
        relative_path="input/src/main.py",
        content="print('hello')\n",
    )
    manager.materialize_file(
        workspace=workspace,
        relative_path="output/report.json",
        content='{"ok": true}\n',
    )
    manager.materialize_file(
        workspace=workspace,
        relative_path="scratch/blob.bin",
        content="binary-ish",
    )

    scanner = ForgeFileGraphScanner()
    graph = scanner.scan(workspace)

    assert graph.root_path == workspace.root_path
    assert graph.file_count() == 3
    assert graph.directory_count() >= 3
    assert graph.get_file("input/src/main.py") is not None
    assert graph.get_file("output/report.json") is not None
    assert graph.total_size_bytes() > 0


def test_file_graph_scanner_classifies_text_files_by_suffix(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="classify")

    manager.materialize_file(
        workspace=workspace,
        relative_path="input/a.py",
        content="print('a')\n",
    )
    manager.materialize_file(
        workspace=workspace,
        relative_path="input/b.txt",
        content="hello\n",
    )
    manager.materialize_file(
        workspace=workspace,
        relative_path="input/c.bin",
        content="opaque",
    )

    graph = ForgeFileGraphScanner().scan(workspace)

    py_files = graph.files_by_suffix(".py")
    txt_files = graph.files_by_suffix("txt")
    text_relative_paths = tuple(node.relative_path for node in graph.text_files())

    assert len(py_files) == 1
    assert py_files[0].relative_path == "input/a.py"
    assert len(txt_files) == 1
    assert txt_files[0].relative_path == "input/b.txt"
    assert "input/a.py" in text_relative_paths
    assert "input/b.txt" in text_relative_paths
    assert "input/c.bin" not in text_relative_paths


def test_file_graph_scanner_preserves_sorted_relative_paths(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="order")

    manager.materialize_file(
        workspace=workspace,
        relative_path="input/zeta.py",
        content="print('z')\n",
    )
    manager.materialize_file(
        workspace=workspace,
        relative_path="input/alpha.py",
        content="print('a')\n",
    )
    manager.materialize_file(
        workspace=workspace,
        relative_path="input/mid/config.toml",
        content='name = "blackfox"\n',
    )

    graph = ForgeFileGraphScanner().scan(workspace)

    assert tuple(node.relative_path for node in graph.files) == (
        "input/alpha.py",
        "input/mid/config.toml",
        "input/zeta.py",
    )


def test_file_graph_scanner_requires_existing_workspace_root(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="missing")

    manager.remove(workspace)

    with pytest.raises(ForgeWorkspaceError, match="Workspace root does not exist"):
        ForgeFileGraphScanner().scan(workspace)


@pytest.mark.parametrize(
    ("suffix", "message"),
    [
        ("", "Forge file suffix must not be empty"),
        ("   ", "Forge file suffix must not be empty"),
    ],
)
def test_file_graph_snapshot_rejects_empty_suffix_queries(
    tmp_path: Path,
    suffix: str,
    message: str,
) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="suffix")

    manager.materialize_file(
        workspace=workspace,
        relative_path="input/example.py",
        content="print('x')\n",
    )

    graph = ForgeFileGraphScanner().scan(workspace)

    with pytest.raises(ValueError, match=message):
        graph.files_by_suffix(suffix)
