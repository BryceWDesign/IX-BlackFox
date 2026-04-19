from __future__ import annotations

from pathlib import Path

from ix_blackfox.config import load_runtime_config
from ix_blackfox.forge import (
    ForgeRegressionCollector,
    ForgeTestRunner,
    ForgeWorkspaceManager,
    RegressionStatus,
)


def test_regression_collector_reports_passing_suite(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="regr-pass")

    manager.materialize_file(
        workspace=workspace,
        relative_path="input/tests/test_ok.py",
        content="""def test_ok() -> None:
    assert True
""",
    )

    test_result = ForgeTestRunner().run(workspace=workspace)
    report = ForgeRegressionCollector().collect(test_result)

    assert report.report_id.startswith("regr-")
    assert report.framework == "pytest"
    assert report.status == RegressionStatus.PASSED
    assert report.succeeded is True
    assert report.exit_code == 0
    assert report.tests == 1
    assert report.failures == 0
    assert report.errors == 0
    assert report.skipped == 0
    assert len(report.suites) >= 1


def test_regression_collector_reports_failing_suite(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="regr-fail")

    manager.materialize_file(
        workspace=workspace,
        relative_path="input/tests/test_fail.py",
        content="""def test_fail() -> None:
    assert False
""",
    )

    test_result = ForgeTestRunner().run(workspace=workspace)
    report = ForgeRegressionCollector().collect(test_result)

    assert report.status == RegressionStatus.FAILED
    assert report.succeeded is False
    assert report.exit_code != 0
    assert report.tests == 1
    assert report.failures >= 1


def test_regression_collector_reports_missing_junit_xml(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="regr-missing")

    manager.materialize_file(
        workspace=workspace,
        relative_path="input/tests/test_ok.py",
        content="""def test_ok() -> None:
    assert True
""",
    )

    test_result = ForgeTestRunner().run(workspace=workspace)
    test_result.junit_xml_path.unlink()

    report = ForgeRegressionCollector().collect(test_result)

    assert report.status == RegressionStatus.ERROR
    assert report.tests == 0
    assert report.suites == ()
    assert report.notes == ("JUnit XML report is missing.",)


def test_regression_collector_reports_malformed_junit_xml(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    manager = ForgeWorkspaceManager(config)
    workspace = manager.reserve(prefix="regr-badxml")

    manager.materialize_file(
        workspace=workspace,
        relative_path="input/tests/test_ok.py",
        content="""def test_ok() -> None:
    assert True
""",
    )

    test_result = ForgeTestRunner().run(workspace=workspace)
    test_result.junit_xml_path.write_text("<testsuite>", encoding="utf-8")

    report = ForgeRegressionCollector().collect(test_result)

    assert report.status == RegressionStatus.ERROR
    assert report.tests == 0
    assert report.suites == ()
    assert len(report.notes) == 1
    assert report.notes[0].startswith("JUnit XML could not be parsed:")
