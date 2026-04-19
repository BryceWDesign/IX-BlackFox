from __future__ import annotations

import pytest

from ix_blackfox.memory import TraceMemoryStore


def test_trace_memory_append_and_get() -> None:
    store = TraceMemoryStore()

    record = store.append(
        correlation_id="task-001",
        stage="Routing",
        message="Selected programming pack.",
        level="Info",
        source="switchboard",
        tags=("route", "pack", "route"),
        data={"capability": "programming"},
    )

    fetched = store.get(record.trace_id)

    assert record.trace_id.startswith("tr-")
    assert record.correlation_id == "task-001"
    assert record.stage == "routing"
    assert record.message == "Selected programming pack."
    assert record.level == "info"
    assert record.source == "switchboard"
    assert record.tags == ("route", "pack")
    assert record.data == {"capability": "programming"}
    assert fetched == record


def test_trace_memory_snapshot_filters() -> None:
    store = TraceMemoryStore()
    first = store.append(
        correlation_id="task-001",
        stage="intake",
        message="Accepted user request.",
        level="info",
        tags=("request",),
    )
    second = store.append(
        correlation_id="task-001",
        stage="routing",
        message="Matched programming pack.",
        level="debug",
        tags=("route", "pack"),
    )
    third = store.append(
        correlation_id="task-002",
        stage="forge",
        message="Patch execution failed.",
        level="error",
        tags=("failure", "patch"),
    )

    snapshot = store.snapshot()

    assert snapshot.filter_by_correlation("task-001") == (first, second)
    assert snapshot.filter_by_stage("routing") == (second,)
    assert snapshot.filter_by_level("error") == (third,)
    assert snapshot.filter_by_tag("pack") == (second,)


def test_trace_record_with_message_returns_updated_copy() -> None:
    store = TraceMemoryStore()
    record = store.append(
        correlation_id="task-001",
        stage="eval",
        message="Evaluation started.",
    )

    updated = record.with_message("Evaluation completed.")

    assert record.message == "Evaluation started."
    assert updated.message == "Evaluation completed."
    assert updated.trace_id == record.trace_id


def test_trace_memory_clear_removes_all_records() -> None:
    store = TraceMemoryStore()
    store.append(
        correlation_id="task-001",
        stage="intake",
        message="Started.",
    )
    store.append(
        correlation_id="task-002",
        stage="forge",
        message="Running.",
    )

    assert store.count() == 2

    store.clear()

    assert store.count() == 0
    assert store.snapshot().records == ()


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {
                "correlation_id": "   ",
                "stage": "routing",
                "message": "Selected route.",
            },
            "Trace memory correlation id must not be empty",
        ),
        (
            {
                "correlation_id": "task-001",
                "stage": "   ",
                "message": "Selected route.",
            },
            "Trace memory stage must not be empty",
        ),
        (
            {
                "correlation_id": "task-001",
                "stage": "routing",
                "message": "   ",
            },
            "Trace memory message must not be empty",
        ),
    ],
)
def test_trace_memory_rejects_invalid_inputs(
    kwargs: dict[str, str],
    message: str,
) -> None:
    store = TraceMemoryStore()

    with pytest.raises(ValueError, match=message):
        store.append(**kwargs)
