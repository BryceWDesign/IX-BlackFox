from __future__ import annotations

from pathlib import Path

import pytest

from ix_blackfox.config import load_runtime_config
from ix_blackfox.forge import (
    ForgeTestRunner,
    ForgeWorkspaceManager,
    TestRunSpec,
)


def test_test_run_spec_normalizes_values() -> None:
    spec = TestRunSpec(
        framework=" PyTest ",
        target_paths=(" tests/test_example.py ", "tests\\test_other.py"),
        cwd_relative_path=" input ",
        timeout_seconds=10.0,
        max_failures=2,
        extra_args=(" -q ", "", " -k=smoke "),
    )

    assert spec.framework == "pytest"
    assert spec.target_paths == ("tests/test_example.py", "tests/test_other.py")
    assert spec.cwd_relative_path == "input"
    assert spec.timeout_seconds == 10.0
    assert spec.max_failures == 2
    assert spec.extra_args == ("-q", "-k=smoke")


def test_forge_test_runner_executes_passing_pytest_suite(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="pytest-pass")

    manager.materialize_file(
        workspace=workspace,
        relative_path="input/tests/test_sample.py",
        content="""def test_truth() -> None:
    assert 1 + 1 == 2
""",
    )

    result = ForgeTestRunner().run(workspace=workspace)

    assert result.framework == "pytest"
    assert result.succeeded is True
    assert result.command_result.exit_code == 0
    assert result.junit_xml_path.is_file()
    assert "test_sample.py" in result.command_result.stdout or result.command_result.stdout == ""


def test_forge_test_runner_returns_nonzero_for_failing_suite(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="pytest-fail")

    manager.materialize_file(
        workspace=workspace,
        relative_path="input/tests/test_failure.py",
        content="""def test_failure() -> None:
    assert False
""",
    )

    result = ForgeTestRunner().run(
        workspace=workspace,
        spec=TestRunSpec(
            max_failures=1,
            extra_args=("-q",),
        ),
    )

    assert result.succeeded is False
    assert result.command_result.exit_code != 0
    assert result.junit_xml_path.is_file()


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {"framework": "nose"},
            "Forge test framework must currently be 'pytest'",
        ),
        (
            {"timeout_seconds": 0.0},
            "Forge test timeout must be greater than zero",
        ),
        (
            {"max_failures": 0},
            "Forge test max_failures must be greater than or equal to 1",
        ),
        (
            {"target_paths": ("../outside.py",)},
            "Forge test target path must not escape the workspace",
        ),
        (
            {"target_paths": ("-k=bad",)},
            "Forge test target path must not begin with '-'",
        ),
        (
            {"cwd_relative_path": "   "},
            "Forge test working directory must not be empty",
        ),
    ],
)
def test_test_run_spec_rejects_invalid_inputs(
    kwargs: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        TestRunSpec(**kwargs)
