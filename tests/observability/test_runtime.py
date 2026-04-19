from __future__ import annotations

from pathlib import Path

import pytest

from ix_blackfox.config import load_runtime_config
from ix_blackfox.observability import (
    JsonlStructuredLogger,
    LogLevel,
)


def test_structured_logger_writes_and_reads_records(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    logger = JsonlStructuredLogger(config)

    first = logger.log(
        level=LogLevel.INFO,
        event="kernel.started",
        message="Kernel entered running state.",
        source="kernel",
        correlation_id="task-001",
        data={"status": "running"},
    )
    second = logger.log(
        level=LogLevel.WARNING,
        event="sentinel.warning",
        message="Potential failure loop detected.",
        source="sentinel",
        correlation_id="task-001",
        data={"failures": 3},
    )

    snapshot = logger.read()

    assert logger.path.is_file()
    assert logger.count() == 2
    assert snapshot.records == (first, second)
    assert snapshot.filter_by_level(LogLevel.WARNING) == (second,)
    assert snapshot.filter_by_source("sentinel") == (second,)
    assert snapshot.filter_by_event("kernel.started") == (first,)


def test_structured_logger_read_limit_returns_recent_records(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    logger = JsonlStructuredLogger(config)

    logger.log(
        level=LogLevel.DEBUG,
        event="forge.plan",
        message="Created patch plan.",
    )
    second = logger.log(
        level=LogLevel.ERROR,
        event="forge.failure",
        message="Patch application failed.",
    )

    snapshot = logger.read(limit=1)

    assert snapshot.records == (second,)


def test_structured_logger_clear_removes_log_file(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    logger = JsonlStructuredLogger(config)

    logger.log(
        level=LogLevel.INFO,
        event="kernel.ready",
        message="Kernel is ready.",
    )

    assert logger.path.exists() is True

    logger.clear()

    assert logger.path.exists() is False
    assert logger.read().records == ()


@pytest.mark.parametrize(
    ("builder", "message"),
    [
        (
            lambda config: JsonlStructuredLogger(config, filename="   "),
            "Structured log filename must not be empty",
        ),
        (
            lambda config: JsonlStructuredLogger(config, filename="nested/log.jsonl"),
            "must not include path separators",
        ),
    ],
)
def test_structured_logger_rejects_invalid_filename(
    tmp_path: Path,
    builder,
    message: str,
) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})

    with pytest.raises(ValueError, match=message):
        builder(config)


def test_structured_logger_rejects_invalid_json_payload(tmp_path: Path) -> None:
    config = load_runtime_config(root_dir=tmp_path, env={})
    logger = JsonlStructuredLogger(config)

    with pytest.raises(ValueError, match="not JSON-serializable"):
        logger.log(
            level=LogLevel.INFO,
            event="kernel.ready",
            message="Kernel is ready.",
            data={"bad": object()},
        )
