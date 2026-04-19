from __future__ import annotations

import pytest

from ix_blackfox.eval import (
    BenchmarkCase,
    BenchmarkSuite,
    BenchmarkSuiteRegistry,
)


def test_benchmark_case_create_normalizes_fields() -> None:
    case = BenchmarkCase.create(
        title="  Patch broken module  ",
        prompt="  Repair the syntax error and run tests.  ",
        expected_artifacts=(" report.json ", "report.json", "trace.log"),
        minimum_score=0.8,
        tags=(" Forge ", "patch", "forge"),
        metadata={"priority": "high"},
    )

    assert case.case_id.startswith("bench-")
    assert case.title == "Patch broken module"
    assert case.prompt == "Repair the syntax error and run tests."
    assert case.expected_artifacts == ("report.json", "trace.log")
    assert case.minimum_score == 0.8
    assert case.tags == ("forge", "patch")
    assert case.metadata == {"priority": "high"}


def test_benchmark_suite_filters_and_case_lookup() -> None:
    first = BenchmarkCase.create(
        title="Case one",
        prompt="Analyze the repo.",
        tags=("analysis",),
    )
    second = BenchmarkCase.create(
        title="Case two",
        prompt="Patch the repo.",
        tags=("forge", "patch"),
    )

    suite = BenchmarkSuite(
        suite_name=" Programming Core ",
        version=" 0.1.0 ",
        cases=(first, second),
        description="  Core programming validation.  ",
    )

    assert suite.suite_name == "programming core"
    assert suite.version == "0.1.0"
    assert suite.description == "Core programming validation."
    assert suite.case_count() == 2
    assert suite.get_case(first.case_id) == first
    assert suite.filter_by_tag("forge") == (second,)


def test_benchmark_suite_registry_registers_replaces_and_retrieves() -> None:
    registry = BenchmarkSuiteRegistry()
    first = BenchmarkSuite(
        suite_name="core",
        version="0.1.0",
    )
    second = BenchmarkSuite(
        suite_name="core",
        version="0.2.0",
    )

    registry.register(first)
    registry.register(second)

    snapshot = registry.snapshot()

    assert snapshot.names() == ("core",)
    assert snapshot.get("core") == second
    assert registry.get("core") == second
    assert registry.unregister("core") is True
    assert registry.unregister("core") is False


@pytest.mark.parametrize(
    ("builder", "message"),
    [
        (
            lambda: BenchmarkCase(
                case_id="   ",
                title="Title",
                prompt="Prompt",
            ),
            "Benchmark case id must not be empty",
        ),
        (
            lambda: BenchmarkCase(
                case_id="bench-1",
                title="   ",
                prompt="Prompt",
            ),
            "Benchmark case title must not be empty",
        ),
        (
            lambda: BenchmarkCase(
                case_id="bench-1",
                title="Title",
                prompt="   ",
            ),
            "Benchmark case prompt must not be empty",
        ),
        (
            lambda: BenchmarkCase(
                case_id="bench-1",
                title="Title",
                prompt="Prompt",
                minimum_score=1.2,
            ),
            "Benchmark minimum score must be between 0.0 and 1.0",
        ),
        (
            lambda: BenchmarkSuite(
                suite_name="core",
                version="0.1.0",
                cases=(
                    BenchmarkCase(
                        case_id="dup",
                        title="A",
                        prompt="One",
                    ),
                    BenchmarkCase(
                        case_id="dup",
                        title="B",
                        prompt="Two",
                    ),
                ),
            ),
            "Benchmark suite case ids must be unique",
        ),
    ],
)
def test_benchmark_models_reject_invalid_inputs(builder, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        builder()
