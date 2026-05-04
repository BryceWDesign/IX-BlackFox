from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

from ix_blackfox.forge.command_runner import (
    CommandResult,
    CommandSpec,
    ForgeCommandRunner,
)
from ix_blackfox.forge.workspace import WorkspaceReservation


@dataclass(frozen=True, slots=True)
class TestRunSpec:
    """
    Specification for one forge test run.

    Attributes
    ----------
    framework:
        Test framework identifier. The initial implementation supports pytest.
    target_paths:
        Optional workspace-relative test targets.
    cwd_relative_path:
        Workspace-relative working directory where tests should run.
    timeout_seconds:
        Maximum allowed test execution time.
    max_failures:
        Optional pytest max-failure limit.
    extra_args:
        Extra framework arguments appended after built-in flags.
    """

    __test__ = False

    framework: str = "pytest"
    target_paths: tuple[str, ...] = field(default_factory=tuple)
    cwd_relative_path: str = "input"
    timeout_seconds: float = 120.0
    max_failures: int | None = None
    extra_args: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        normalized_framework = self.framework.strip().lower()
        if normalized_framework != "pytest":
            raise ValueError("Forge test framework must currently be 'pytest'.")
        if self.timeout_seconds <= 0:
            raise ValueError("Forge test timeout must be greater than zero.")
        if self.max_failures is not None and self.max_failures < 1:
            raise ValueError(
                "Forge test max_failures must be greater than or equal to 1."
            )

        normalized_targets = tuple(
            _normalize_target_path(path) for path in self.target_paths
        )
        normalized_cwd = _normalize_relative_path(self.cwd_relative_path)
        normalized_extra_args = tuple(
            argument.strip() for argument in self.extra_args if argument.strip()
        )

        object.__setattr__(self, "framework", normalized_framework)
        object.__setattr__(self, "target_paths", normalized_targets)
        object.__setattr__(self, "cwd_relative_path", normalized_cwd)
        object.__setattr__(self, "extra_args", normalized_extra_args)


@dataclass(frozen=True, slots=True)
class TestRunResult:
    """
    Result of one forge test run.
    """

    __test__ = False

    framework: str
    target_paths: tuple[str, ...]
    junit_xml_path: Path
    command_result: CommandResult

    @property
    def succeeded(self) -> bool:
        """
        Return True when the underlying test command succeeded.
        """
        return self.command_result.succeeded


class ForgeTestRunner:
    """
    Controlled test runner for forge workspaces.

    The initial implementation targets pytest and records a JUnit XML
    report path for downstream verification and trace collection.
    """

    def __init__(
        self,
        *,
        command_runner: ForgeCommandRunner | None = None,
    ) -> None:
        self._command_runner = command_runner or ForgeCommandRunner()

    def run(
        self,
        *,
        workspace: WorkspaceReservation,
        spec: TestRunSpec | None = None,
    ) -> TestRunResult:
        """
        Execute a test run inside a reserved workspace.
        """
        active_spec = spec or TestRunSpec()
        if active_spec.framework != "pytest":
            raise ValueError("Forge test framework must currently be 'pytest'.")

        junit_xml_path = (
            workspace.output_path / "test-results" / "pytest-junit.xml"
        ).resolve()
        junit_xml_path.parent.mkdir(parents=True, exist_ok=True)

        argv = self._build_pytest_argv(
            target_paths=active_spec.target_paths,
            junit_xml_path=junit_xml_path,
            max_failures=active_spec.max_failures,
            extra_args=active_spec.extra_args,
        )

        command_result = self._command_runner.run(
            workspace=workspace,
            spec=CommandSpec(
                argv=argv,
                cwd_relative_path=active_spec.cwd_relative_path,
                timeout_seconds=active_spec.timeout_seconds,
            ),
        )

        return TestRunResult(
            framework=active_spec.framework,
            target_paths=active_spec.target_paths,
            junit_xml_path=junit_xml_path,
            command_result=command_result,
        )

    def _build_pytest_argv(
        self,
        *,
        target_paths: tuple[str, ...],
        junit_xml_path: Path,
        max_failures: int | None,
        extra_args: tuple[str, ...],
    ) -> tuple[str, ...]:
        argv: list[str] = [
            sys.executable,
            "-m",
            "pytest",
            "-ra",
            "--junitxml",
            str(junit_xml_path),
        ]

        if max_failures is not None:
            argv.extend(["--maxfail", str(max_failures)])

        argv.extend(extra_args)

        if target_paths:
            argv.extend(target_paths)
        else:
            argv.append(".")

        return tuple(argv)


def _normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("Forge test working directory must not be empty.")
    if Path(cleaned).is_absolute():
        raise ValueError("Forge test working directory must be relative.")
    return cleaned


def _normalize_target_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("Forge test target path must not be empty.")
    if cleaned.startswith("-"):
        raise ValueError("Forge test target path must not begin with '-'.")
    path = Path(cleaned)
    if path.is_absolute():
        raise ValueError("Forge test target path must be relative.")
    if ".." in path.parts:
        raise ValueError("Forge test target path must not escape the workspace.")
    return cleaned
