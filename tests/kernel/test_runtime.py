from __future__ import annotations

from pathlib import Path

import pytest

from ix_blackfox.config import load_runtime_config
from ix_blackfox.kernel import BlackFoxKernel, KernelStatus


def test_kernel_initializes_runtime_paths(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    kernel = BlackFoxKernel(config)

    kernel.initialize()

    assert kernel.status == KernelStatus.READY
    assert config.paths.state_dir.is_dir()
    assert config.paths.runtime_dir.is_dir()
    assert config.paths.artifacts_dir.is_dir()
    assert config.paths.logs_dir.is_dir()
    assert config.paths.temp_dir.is_dir()


def test_kernel_start_auto_initializes_and_runs(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    kernel = BlackFoxKernel(config)

    kernel.start()

    snapshot = kernel.snapshot()
    assert snapshot.status == KernelStatus.RUNNING
    assert snapshot.started_at is not None
    assert snapshot.stopped_at is None
    assert kernel.is_ready() is True


def test_kernel_stop_from_created_state_is_allowed(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    kernel = BlackFoxKernel(config)

    kernel.stop()

    snapshot = kernel.snapshot()
    assert snapshot.status == KernelStatus.STOPPED
    assert snapshot.started_at is None
    assert snapshot.stopped_at is not None


def test_kernel_cannot_restart_after_stop(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    kernel = BlackFoxKernel(config)

    kernel.start()
    kernel.stop()

    with pytest.raises(RuntimeError, match="stopping or stopped"):
        kernel.start()


def test_kernel_id_is_stable(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    kernel = BlackFoxKernel(config)

    first = kernel.kernel_id
    second = kernel.snapshot().kernel_id

    assert first == second
    assert first.startswith("bfk-")
