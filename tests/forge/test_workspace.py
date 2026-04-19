from __future__ import annotations

from pathlib import Path

import pytest

from ix_blackfox.config import load_runtime_config
from ix_blackfox.forge import (
    ForgeWorkspaceError,
    ForgeWorkspaceManager,
)


def test_workspace_reservation_creates_directory_tree(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)

    workspace = manager.reserve(prefix="patch")

    assert workspace.workspace_id.startswith("patch-")
    assert workspace.root_path.is_dir()
    assert workspace.input_path.is_dir()
    assert workspace.output_path.is_dir()
    assert workspace.scratch_path.is_dir()
    assert workspace.root_path.parent == manager.base_dir


def test_materialize_and_read_text_round_trip(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="analysis")

    written = manager.materialize_file(
        workspace=workspace,
        relative_path="output/report.txt",
        content="hello blackfox",
    )
    content = manager.read_text(
        workspace=workspace,
        relative_path="output/report.txt",
    )

    assert written == workspace.output_path / "report.txt"
    assert content == "hello blackfox"


def test_copy_into_workspace_handles_files_and_directories(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve()

    source_file = tmp_path / "example.py"
    source_file.write_text("print('x')\n", encoding="utf-8")

    source_dir = tmp_path / "fixtures"
    source_dir.mkdir()
    (source_dir / "data.txt").write_text("fixture\n", encoding="utf-8")

    copied_file = manager.copy_into_workspace(
        workspace=workspace,
        source_path=source_file,
    )
    copied_dir = manager.copy_into_workspace(
        workspace=workspace,
        source_path=source_dir,
    )

    assert copied_file.read_text(encoding="utf-8") == "print('x')\n"
    assert (copied_dir / "data.txt").read_text(encoding="utf-8") == "fixture\n"


def test_resolve_path_blocks_workspace_escape(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve()

    with pytest.raises(ForgeWorkspaceError, match="escapes the reserved workspace"):
        manager.resolve_path(
            workspace=workspace,
            relative_path="../../outside.txt",
        )


def test_remove_and_clear_delete_managed_workspaces(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)

    first = manager.reserve(prefix="one")
    second = manager.reserve(prefix="two")

    assert len(manager.list_workspaces()) == 2
    assert manager.remove(first) is True
    assert manager.remove(first) is False

    manager.clear()

    assert manager.list_workspaces() == ()
    assert second.root_path.exists() is False


def test_copy_into_workspace_requires_existing_source(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve()

    with pytest.raises(ForgeWorkspaceError, match="does not exist"):
        manager.copy_into_workspace(
            workspace=workspace,
            source_path=tmp_path / "missing.txt",
        )


def test_read_text_requires_existing_file(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve()

    with pytest.raises(ForgeWorkspaceError, match="does not exist"):
        manager.read_text(
            workspace=workspace,
            relative_path="output/missing.txt",
        )


@pytest.mark.parametrize(
    ("prefix", "message"),
    [
        ("", "Forge workspace prefix must not be empty"),
        ("   ", "Forge workspace prefix must not be empty"),
    ],
)
def test_reserve_rejects_empty_prefix(
    tmp_path: Path,
    prefix: str,
    message: str,
) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)

    with pytest.raises(ValueError, match=message):
        manager.reserve(prefix=prefix)
