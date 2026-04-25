from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from ix_blackfox.tools import (
    ToolCapability,
    ToolFailureKind,
    ToolInvocationRequest,
    ToolInvocationStatus,
    ToolPathPolicy,
    WorkspaceDirectoryListTool,
    WorkspaceFileReadTool,
    WorkspacePathResolver,
    WorkspacePathViolation,
    build_workspace_directory_list_manifest,
    build_workspace_file_read_manifest,
)


def test_workspace_path_resolver_allows_paths_inside_allowed_roots(tmp_path: Path) -> None:
    workspace = _make_workspace(tmp_path)
    resolver = WorkspacePathResolver(
        workspace_root=workspace,
        path_policy=ToolPathPolicy(
            allowed_roots=("src", "tests"),
            blocked_roots=(".git", "secrets"),
            allow_absolute_paths=False,
        ),
    )

    resolved = resolver.resolve("src/ix_blackfox/runtime/orchestrator.py")

    assert resolved == workspace / "src/ix_blackfox/runtime/orchestrator.py"
    assert resolver.relative_path(resolved) == "src/ix_blackfox/runtime/orchestrator.py"


def test_workspace_path_resolver_allows_workspace_root_as_control_entrypoint(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path)
    resolver = WorkspacePathResolver(
        workspace_root=workspace,
        path_policy=ToolPathPolicy(
            allowed_roots=("src", "tests"),
            blocked_roots=(".git", "secrets"),
            allow_absolute_paths=False,
        ),
    )

    resolved = resolver.resolve(".")

    assert resolved == workspace
    assert resolver.relative_path(resolved) == "."


def test_workspace_path_resolver_treats_dot_allowed_root_as_full_workspace_scope(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path)
    resolver = WorkspacePathResolver(
        workspace_root=workspace,
        path_policy=ToolPathPolicy(
            allowed_roots=(".",),
            blocked_roots=(".git", "secrets"),
            allow_absolute_paths=False,
        ),
    )

    resolved = resolver.resolve("docs/notes.md")

    assert resolved == workspace / "docs/notes.md"
    assert resolver.relative_path(resolved) == "docs/notes.md"


def test_workspace_path_resolver_rejects_path_traversal(tmp_path: Path) -> None:
    workspace = _make_workspace(tmp_path)
    resolver = WorkspacePathResolver(
        workspace_root=workspace,
        path_policy=ToolPathPolicy(
            allowed_roots=("src", "tests"),
            blocked_roots=(".git", "secrets"),
            allow_absolute_paths=False,
        ),
    )

    with pytest.raises(WorkspacePathViolation, match="escapes the governed workspace"):
        resolver.resolve("../outside.txt")

    with pytest.raises(WorkspacePathViolation, match="escapes the governed workspace"):
        resolver.resolve("src/../../outside.txt")


def test_workspace_path_resolver_rejects_absolute_paths_by_default(tmp_path: Path) -> None:
    workspace = _make_workspace(tmp_path)
    absolute_path = workspace / "src/ix_blackfox/runtime/orchestrator.py"
    resolver = WorkspacePathResolver(
        workspace_root=workspace,
        path_policy=ToolPathPolicy(
            allowed_roots=("src",),
            blocked_roots=(),
            allow_absolute_paths=False,
        ),
    )

    with pytest.raises(WorkspacePathViolation, match="Absolute paths are not allowed"):
        resolver.resolve(absolute_path)


def test_workspace_path_resolver_can_allow_absolute_paths_inside_workspace(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path)
    absolute_path = workspace / "src/ix_blackfox/runtime/orchestrator.py"
    resolver = WorkspacePathResolver(
        workspace_root=workspace,
        path_policy=ToolPathPolicy(
            allowed_roots=("src",),
            blocked_roots=(".git", "secrets"),
            allow_absolute_paths=True,
        ),
    )

    resolved = resolver.resolve(absolute_path)

    assert resolved == absolute_path
    assert resolver.relative_path(resolved) == "src/ix_blackfox/runtime/orchestrator.py"


def test_workspace_path_resolver_rejects_blocked_roots(tmp_path: Path) -> None:
    workspace = _make_workspace(tmp_path)
    resolver = WorkspacePathResolver(
        workspace_root=workspace,
        path_policy=ToolPathPolicy(
            allowed_roots=(),
            blocked_roots=(".git", "secrets"),
            allow_absolute_paths=False,
        ),
    )

    with pytest.raises(WorkspacePathViolation, match="Path is blocked"):
        resolver.resolve(".git/config")

    with pytest.raises(WorkspacePathViolation, match="Path is blocked"):
        resolver.resolve("secrets/token.txt")


def test_workspace_path_resolver_rejects_paths_outside_allowed_roots(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path)
    resolver = WorkspacePathResolver(
        workspace_root=workspace,
        path_policy=ToolPathPolicy(
            allowed_roots=("src", "tests"),
            blocked_roots=(".git", "secrets"),
            allow_absolute_paths=False,
        ),
    )

    with pytest.raises(WorkspacePathViolation, match="outside allowed workspace roots"):
        resolver.resolve("docs/notes.md")


def test_workspace_file_read_tool_reads_file_and_reports_hash(tmp_path: Path) -> None:
    workspace = _make_workspace(tmp_path)
    target = workspace / "src/ix_blackfox/runtime/orchestrator.py"
    expected_bytes = target.read_bytes()
    expected_text = expected_bytes.decode("utf-8")
    expected_sha256 = hashlib.sha256(expected_bytes).hexdigest()

    tool = WorkspaceFileReadTool(
        workspace_root=workspace,
        path_policy=ToolPathPolicy(
            allowed_roots=("src",),
            blocked_roots=(".git", "secrets"),
            allow_absolute_paths=False,
        ),
    )
    request = ToolInvocationRequest.create(
        tool_id="blackfox.workspace.read_file",
        capability=ToolCapability.FILE_READ,
        arguments={"path": "src/ix_blackfox/runtime/orchestrator.py"},
        task_id="task-read",
        run_id="run-read",
    )

    result = tool.invoke(request)

    assert result.status is ToolInvocationStatus.SUCCEEDED
    assert result.failure is None
    assert result.output["path"] == "src/ix_blackfox/runtime/orchestrator.py"
    assert result.output["size_bytes"] == len(expected_bytes)
    assert result.output["sha256"] == expected_sha256
    assert result.output["encoding"] == "utf-8"
    assert result.output["text"] == expected_text
    assert len(result.artifacts) == 1
    assert result.artifacts[0].name == "orchestrator.py"
    assert result.artifacts[0].uri == "src/ix_blackfox/runtime/orchestrator.py"
    assert result.artifacts[0].sha256 == expected_sha256


def test_workspace_file_read_tool_blocks_traversal_without_reading(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path)
    tool = WorkspaceFileReadTool(workspace_root=workspace)
    request = ToolInvocationRequest.create(
        tool_id="blackfox.workspace.read_file",
        capability=ToolCapability.FILE_READ,
        arguments={"path": "../outside.txt"},
    )

    result = tool.invoke(request)

    assert result.status is ToolInvocationStatus.BLOCKED
    assert result.failure is not None
    assert result.failure.kind is ToolFailureKind.PATH_VIOLATION
    assert "escapes the governed workspace root" in result.failure.message


def test_workspace_file_read_tool_blocks_manifest_blocked_roots(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path)
    tool = WorkspaceFileReadTool(
        workspace_root=workspace,
        path_policy=ToolPathPolicy(
            allowed_roots=(),
            blocked_roots=(".git", "secrets"),
            allow_absolute_paths=False,
        ),
    )
    request = ToolInvocationRequest.create(
        tool_id="blackfox.workspace.read_file",
        capability=ToolCapability.FILE_READ,
        arguments={"path": "secrets/token.txt"},
    )

    result = tool.invoke(request)

    assert result.status is ToolInvocationStatus.BLOCKED
    assert result.failure is not None
    assert result.failure.kind is ToolFailureKind.PATH_VIOLATION
    assert "Path is blocked by workspace policy" in result.failure.message


def test_workspace_file_read_tool_rejects_wrong_tool_id_and_capability(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path)
    tool = WorkspaceFileReadTool(workspace_root=workspace)

    wrong_tool_request = ToolInvocationRequest.create(
        tool_id="blackfox.workspace.list_directory",
        capability=ToolCapability.FILE_READ,
        arguments={"path": "src/ix_blackfox/runtime/orchestrator.py"},
    )
    wrong_capability_request = ToolInvocationRequest.create(
        tool_id="blackfox.workspace.read_file",
        capability=ToolCapability.DIRECTORY_LIST,
        arguments={"path": "src/ix_blackfox/runtime/orchestrator.py"},
    )

    wrong_tool_result = tool.invoke(wrong_tool_request)
    wrong_capability_result = tool.invoke(wrong_capability_request)

    assert wrong_tool_result.status is ToolInvocationStatus.FAILED
    assert wrong_tool_result.failure is not None
    assert wrong_tool_result.failure.kind is ToolFailureKind.INVALID_REQUEST

    assert wrong_capability_result.status is ToolInvocationStatus.FAILED
    assert wrong_capability_result.failure is not None
    assert wrong_capability_result.failure.kind is ToolFailureKind.UNSUPPORTED_CAPABILITY


def test_workspace_file_read_tool_rejects_files_above_size_limit(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path)
    tool = WorkspaceFileReadTool(workspace_root=workspace, max_bytes=8)
    request = ToolInvocationRequest.create(
        tool_id="blackfox.workspace.read_file",
        capability=ToolCapability.FILE_READ,
        arguments={"path": "src/ix_blackfox/runtime/orchestrator.py"},
    )

    result = tool.invoke(request)

    assert result.status is ToolInvocationStatus.FAILED
    assert result.failure is not None
    assert result.failure.kind is ToolFailureKind.INVALID_REQUEST
    assert "exceeds max_bytes limit" in result.failure.message
    assert result.failure.metadata["max_bytes"] == 8


def test_workspace_directory_list_tool_lists_non_hidden_entries_by_default(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path)
    tool = WorkspaceDirectoryListTool(
        workspace_root=workspace,
        path_policy=ToolPathPolicy(
            allowed_roots=("src", "tests", "docs"),
            blocked_roots=(".git", "secrets"),
            allow_absolute_paths=False,
        ),
    )
    request = ToolInvocationRequest.create(
        tool_id="blackfox.workspace.list_directory",
        capability=ToolCapability.DIRECTORY_LIST,
        arguments={
            "path": ".",
            "recursive": False,
            "include_hidden": False,
        },
    )

    result = tool.invoke(request)

    assert result.status is ToolInvocationStatus.SUCCEEDED
    assert result.output["path"] == "."
    assert result.output["recursive"] is False
    assert result.output["include_hidden"] is False
    assert result.output["truncated"] is False

    entries = {entry["path"]: entry for entry in result.output["entries"]}

    assert "src" in entries
    assert "tests" in entries
    assert "docs" in entries
    assert ".git" not in entries
    assert "secrets" not in entries
    assert entries["src"]["entry_type"] == "directory"


def test_workspace_directory_list_tool_filters_disallowed_root_entries(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path)
    tool = WorkspaceDirectoryListTool(
        workspace_root=workspace,
        path_policy=ToolPathPolicy(
            allowed_roots=("src",),
            blocked_roots=(".git", "secrets"),
            allow_absolute_paths=False,
        ),
    )
    request = ToolInvocationRequest.create(
        tool_id="blackfox.workspace.list_directory",
        capability=ToolCapability.DIRECTORY_LIST,
        arguments={"path": ".", "recursive": False},
    )

    result = tool.invoke(request)

    assert result.status is ToolInvocationStatus.SUCCEEDED

    entries = {entry["path"]: entry for entry in result.output["entries"]}

    assert set(entries) == {"src"}


def test_workspace_directory_list_tool_lists_recursive_entries_and_hashes_files(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path)
    target = workspace / "src/ix_blackfox/runtime/orchestrator.py"
    expected_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
    tool = WorkspaceDirectoryListTool(
        workspace_root=workspace,
        include_file_hashes=True,
    )
    request = ToolInvocationRequest.create(
        tool_id="blackfox.workspace.list_directory",
        capability=ToolCapability.DIRECTORY_LIST,
        arguments={
            "path": "src",
            "recursive": True,
            "include_hidden": False,
            "max_entries": 20,
        },
    )

    result = tool.invoke(request)

    assert result.status is ToolInvocationStatus.SUCCEEDED
    assert result.output["path"] == "src"
    assert result.output["recursive"] is True

    entries = {entry["path"]: entry for entry in result.output["entries"]}

    assert "src/ix_blackfox" in entries
    assert "src/ix_blackfox/runtime" in entries
    assert "src/ix_blackfox/runtime/orchestrator.py" in entries
    assert entries["src/ix_blackfox/runtime/orchestrator.py"]["entry_type"] == "file"
    assert entries["src/ix_blackfox/runtime/orchestrator.py"]["sha256"] == expected_sha256


def test_workspace_directory_list_tool_blocks_disallowed_directory(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path)
    tool = WorkspaceDirectoryListTool(
        workspace_root=workspace,
        path_policy=ToolPathPolicy(
            allowed_roots=("src", "tests"),
            blocked_roots=(".git", "secrets"),
            allow_absolute_paths=False,
        ),
    )
    request = ToolInvocationRequest.create(
        tool_id="blackfox.workspace.list_directory",
        capability=ToolCapability.DIRECTORY_LIST,
        arguments={"path": "docs"},
    )

    result = tool.invoke(request)

    assert result.status is ToolInvocationStatus.BLOCKED
    assert result.failure is not None
    assert result.failure.kind is ToolFailureKind.PATH_VIOLATION
    assert "outside allowed workspace roots" in result.failure.message


def test_workspace_directory_list_tool_honors_max_entries_truncation(
    tmp_path: Path,
) -> None:
    workspace = _make_workspace(tmp_path)
    for index in range(5):
        (workspace / "src" / f"file_{index}.py").write_text(
            f"# file {index}\n",
            encoding="utf-8",
        )

    tool = WorkspaceDirectoryListTool(workspace_root=workspace)
    request = ToolInvocationRequest.create(
        tool_id="blackfox.workspace.list_directory",
        capability=ToolCapability.DIRECTORY_LIST,
        arguments={
            "path": "src",
            "recursive": False,
            "max_entries": 2,
        },
    )

    result = tool.invoke(request)

    assert result.status is ToolInvocationStatus.SUCCEEDED
    assert result.output["entry_count"] == 2
    assert result.output["truncated"] is True


def test_workspace_tool_manifests_declare_read_only_workspace_scope() -> None:
    read_manifest = build_workspace_file_read_manifest()
    list_manifest = build_workspace_directory_list_manifest()

    assert read_manifest.tool_id == "blackfox.workspace.read_file"
    assert read_manifest.capabilities == (ToolCapability.FILE_READ,)
    assert read_manifest.has_side_effects is True
    assert read_manifest.path_policy is not None
    assert ".git" in read_manifest.path_policy.blocked_roots
    assert read_manifest.path_policy.allow_absolute_paths is False

    assert list_manifest.tool_id == "blackfox.workspace.list_directory"
    assert list_manifest.capabilities == (ToolCapability.DIRECTORY_LIST,)
    assert list_manifest.has_side_effects is True
    assert list_manifest.path_policy is not None
    assert "secrets" in list_manifest.path_policy.blocked_roots
    assert list_manifest.path_policy.allow_absolute_paths is False


def _make_workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    (workspace / "src/ix_blackfox/runtime").mkdir(parents=True)
    (workspace / "tests/runtime").mkdir(parents=True)
    (workspace / "docs").mkdir(parents=True)
    (workspace / ".git").mkdir(parents=True)
    (workspace / "secrets").mkdir(parents=True)

    (workspace / "src/ix_blackfox/runtime/orchestrator.py").write_text(
        "from __future__ import annotations\n\n"
        "def run() -> str:\n"
        "    return 'blackfox'\n",
        encoding="utf-8",
    )
    (workspace / "tests/runtime/test_orchestrator.py").write_text(
        "def test_placeholder() -> None:\n"
        "    assert True\n",
        encoding="utf-8",
    )
    (workspace / "docs/notes.md").write_text(
        "# Notes\n",
        encoding="utf-8",
    )
    (workspace / ".git/config").write_text(
        "[core]\n",
        encoding="utf-8",
    )
    (workspace / "secrets/token.txt").write_text(
        "do-not-read\n",
        encoding="utf-8",
    )
    (tmp_path / "outside.txt").write_text(
        "outside workspace\n",
        encoding="utf-8",
    )

    return workspace
