from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from ix_blackfox.sandbox import (
    SandboxBackendKind,
    SandboxFilesystemPolicy,
    SandboxMount,
    SandboxMountAccess,
    SandboxNetworkPolicy,
    SandboxProfile,
    SandboxResourceLimits,
    SandboxWorkspaceManager,
)


def test_wave6_workspace_manager_stages_read_only_source_without_writeback(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    source = repo / "src"
    source.mkdir(parents=True)
    original = source / "module.py"
    original.write_text("print('original')\n", encoding="utf-8")
    manager = SandboxWorkspaceManager(tmp_path / "workspaces")

    workspace = manager.create_workspace(
        _profile(source_mount="src"),
        repo_root=repo,
        workspace_id="wave6-workspace-1",
    )

    staged_file = workspace.resolve_sandbox_path("/workspace/src/module.py")
    assert staged_file.read_text(encoding="utf-8") == "print('original')\n"
    staged_file.write_text("print('changed only in workspace')\n", encoding="utf-8")
    assert original.read_text(encoding="utf-8") == "print('original')\n"


def test_wave6_workspace_manager_creates_optional_writable_mounts(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    manager = SandboxWorkspaceManager(tmp_path / "workspaces")

    workspace = manager.create_workspace(
        _profile(source_mount="src"),
        repo_root=repo,
        workspace_id="wave6-workspace-optional-rw",
    )

    out_path = workspace.resolve_sandbox_path("/workspace/out")
    tmp_path_inside = workspace.resolve_sandbox_path("/workspace/tmp")

    assert out_path.is_dir()
    assert tmp_path_inside.is_dir()
    assert workspace.to_dict()["target_map"]["/workspace/out"].endswith("workspace/out")


def test_wave6_workspace_manager_collects_output_artifact_manifest(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    manager = SandboxWorkspaceManager(tmp_path / "workspaces")
    workspace = manager.create_workspace(
        _profile(source_mount="src"),
        repo_root=repo,
        workspace_id="wave6-workspace-manifest",
    )
    out_path = workspace.resolve_sandbox_path("/workspace/out")
    (out_path / "nested").mkdir()
    (out_path / "nested" / "result.txt").write_text("sandbox artifact\n", encoding="utf-8")
    (out_path / "summary.json").write_text('{"passed":true}\n', encoding="utf-8")

    manifest = manager.collect_artifacts(workspace)

    assert manifest.artifact_count == 2
    assert manifest.total_size_bytes == len("sandbox artifact\n".encode("utf-8")) + len('{"passed":true}\n'.encode("utf-8"))
    assert tuple(record.path for record in manifest.artifacts) == ("nested/result.txt", "summary.json")
    assert manifest.artifacts[0].sha256 == hashlib.sha256(b"sandbox artifact\n").hexdigest()
    assert len(manifest.digest) == 64
    assert manifest.to_dict()["digest"] == manifest.digest


def test_wave6_workspace_manager_rejects_symlinked_mount_source(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (repo / "src").symlink_to(outside, target_is_directory=True)
    manager = SandboxWorkspaceManager(tmp_path / "workspaces")

    with pytest.raises(ValueError, match="must not be a symlink"):
        manager.create_workspace(
            _profile(source_mount="src"),
            repo_root=repo,
            workspace_id="wave6-workspace-symlink-source",
        )


def test_wave6_workspace_manager_rejects_symlinked_outputs(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    target = tmp_path / "outside.txt"
    target.write_text("outside\n", encoding="utf-8")
    manager = SandboxWorkspaceManager(tmp_path / "workspaces")
    workspace = manager.create_workspace(
        _profile(source_mount="src"),
        repo_root=repo,
        workspace_id="wave6-workspace-symlink-output",
    )
    out_path = workspace.resolve_sandbox_path("/workspace/out")
    (out_path / "escape.txt").symlink_to(target)

    with pytest.raises(ValueError, match="refuses symlinked outputs"):
        manager.collect_artifacts(workspace)


def test_wave6_workspace_manager_blocks_unmapped_sandbox_path(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    manager = SandboxWorkspaceManager(tmp_path / "workspaces")
    workspace = manager.create_workspace(
        _profile(source_mount="src"),
        repo_root=repo,
        workspace_id="wave6-workspace-unmapped",
    )

    with pytest.raises(ValueError, match="not covered"):
        workspace.resolve_sandbox_path("/unmapped/file.txt")


def test_wave6_workspace_manager_blocks_path_escape(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    manager = SandboxWorkspaceManager(tmp_path / "workspaces")
    workspace = manager.create_workspace(
        _profile(source_mount="src"),
        repo_root=repo,
        workspace_id="wave6-workspace-escape",
    )

    with pytest.raises(ValueError, match="must not contain"):
        workspace.resolve_sandbox_path("/workspace/src/../out")


def test_wave6_workspace_manager_rejects_artifact_manifest_over_limit(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    profile = _profile(source_mount="src", max_artifact_bytes=4)
    manager = SandboxWorkspaceManager(tmp_path / "workspaces")
    workspace = manager.create_workspace(
        profile,
        repo_root=repo,
        workspace_id="wave6-workspace-artifact-limit",
    )
    out_path = workspace.resolve_sandbox_path("/workspace/out")
    (out_path / "too-large.txt").write_text("12345", encoding="utf-8")

    with pytest.raises(ValueError, match="max_artifact_bytes"):
        manager.collect_artifacts(workspace)


def test_wave6_workspace_manager_cleanup_removes_workspace_root(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    manager = SandboxWorkspaceManager(tmp_path / "workspaces")
    workspace = manager.create_workspace(
        _profile(source_mount="src"),
        repo_root=repo,
        workspace_id="wave6-workspace-cleanup",
    )

    assert workspace.root_path.exists()
    manager.cleanup_workspace(workspace)
    assert not workspace.root_path.exists()


def _profile(*, source_mount: str, max_artifact_bytes: int = 1_048_576) -> SandboxProfile:
    return SandboxProfile(
        profile_id="wave6.workspace.test",
        backend=SandboxBackendKind.LOCAL_AUDIT,
        filesystem=SandboxFilesystemPolicy(
            mounts=(
                SandboxMount(
                    source=source_mount,
                    target="/workspace/src",
                    access=SandboxMountAccess.READ_ONLY,
                ),
                SandboxMount(
                    source=".blackfox-workspace/out",
                    target="/workspace/out",
                    access=SandboxMountAccess.READ_WRITE,
                    required=False,
                ),
                SandboxMount(
                    source=".blackfox-workspace/tmp",
                    target="/workspace/tmp",
                    access=SandboxMountAccess.READ_WRITE,
                    required=False,
                ),
            )
        ),
        resources=SandboxResourceLimits(
            timeout_seconds=30,
            max_memory_mb=256,
            max_processes=16,
            max_output_bytes=65_536,
            max_artifact_bytes=max_artifact_bytes,
        ),
        network=SandboxNetworkPolicy(),
        allowed_commands=("python",),
        metadata={"claim": "workspace-lifecycle-only"},
    )
