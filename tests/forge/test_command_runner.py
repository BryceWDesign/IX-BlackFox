from __future__ import annotations

import sys
from pathlib import Path

import pytest

from ix_blackfox.config import load_runtime_config
from ix_blackfox.forge import (
    CommandSpec,
    ForgeCommandError,
    ForgeCommandRunner,
    ForgeWorkspaceManager,
)


def test_command_runner_executes_command_and_captures_output(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="run")

    result = ForgeCommandRunner().run(
        workspace=workspace,
        spec=CommandSpec(
            argv=(
                sys.executable,
                "-c",
                "print('hello blackfox')",
            )
        ),
    )

    assert result.argv[0] == sys.executable
    assert result.cwd_path == workspace.root_path
    assert result.exit_code == 0
    assert result.stdout == "hello blackfox\n"
    assert result.stderr == ""
    assert result.succeeded is True
    assert result.duration_seconds >= 0.0


def test_command_runner_honors_workspace_cwd_and_env(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="env")
    workspace.input_path.mkdir(parents=True, exist_ok=True)

    result = ForgeCommandRunner().run(
        workspace=workspace,
        spec=CommandSpec(
            argv=(
                sys.executable,
                "-c",
                (
                    "import os, pathlib; "
                    "print(pathlib.Path.cwd().name); "
                    "print(os.environ['BLACKFOX_MODE'])"
                ),
            ),
            cwd_relative_path="input",
            env_overrides={"BLACKFOX_MODE": "strict"},
        ),
    )

    assert result.cwd_path == workspace.input_path
    assert result.stdout == "input\nstrict\n"


def test_command_runner_returns_nonzero_exit_without_raising(
    tmp_path: Path,
) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="nonzero")

    result = ForgeCommandRunner().run(
        workspace=workspace,
        spec=CommandSpec(
            argv=(
                sys.executable,
                "-c",
                (
                    "import sys; "
                    "print('about to fail'); "
                    "print('bad', file=sys.stderr); "
                    "raise SystemExit(3)"
                ),
            )
        ),
    )

    assert result.exit_code == 3
    assert result.stdout == "about to fail\n"
    assert result.stderr == "bad\n"
    assert result.succeeded is False


def test_command_runner_rejects_workspace_escape(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="escape")

    with pytest.raises(ForgeCommandError, match="escapes the workspace boundary"):
        ForgeCommandRunner().run(
            workspace=workspace,
            spec=CommandSpec(
                argv=(sys.executable, "-c", "print('x')"),
                cwd_relative_path="../../outside",
            ),
        )


def test_command_runner_raises_on_timeout(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="timeout")

    with pytest.raises(ForgeCommandError, match="timed out"):
        ForgeCommandRunner().run(
            workspace=workspace,
            spec=CommandSpec(
                argv=(
                    sys.executable,
                    "-c",
                    "import time; time.sleep(0.5)",
                ),
                timeout_seconds=0.01,
            ),
        )


@pytest.mark.parametrize(
    ("argv", "timeout_seconds", "message"),
    [
        ((), 30.0, "Forge command argv must not be empty"),
        (("   ",), 30.0, "Forge command argv must not be empty"),
        ((sys.executable,), 0.0, "Forge command timeout must be greater than zero"),
    ],
)
def test_command_spec_rejects_invalid_inputs(
    argv: tuple[str, ...],
    timeout_seconds: float,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        CommandSpec(
            argv=argv,
            timeout_seconds=timeout_seconds,
        )
