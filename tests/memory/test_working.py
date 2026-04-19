from __future__ import annotations

from time import sleep

import pytest

from ix_blackfox.memory import WorkingMemoryStore


def test_working_memory_put_get_and_update() -> None:
    store = WorkingMemoryStore()

    first = store.put(
        "planner",
        "current_step",
        {"step": 1},
        source="kernel",
        tags=("plan", "active"),
    )
    sleep(0.001)
    second = store.put(
        "planner",
        "current_step",
        {"step": 2},
        source="switchboard",
        tags=("plan", "active", "plan"),
    )

    assert first.item_id == second.item_id
    assert second.value == {"step": 2}
    assert second.source == "switchboard"
    assert second.tags == ("plan", "active")
    assert second.updated_at >= first.updated_at

    fetched = store.get("planner", "current_step")
    assert fetched == second


def test_working_memory_snapshot_filtering() -> None:
    store = WorkingMemoryStore()
    store.put("planner", "step", "route task", tags=("plan", "active"))
    store.put("forge", "target", "src/", tags=("execution",))
    store.put("planner", "risk", "missing test", tags=("plan", "risk"))

    snapshot = store.snapshot()
    planner_snapshot = store.snapshot(namespace="planner")

    assert snapshot.namespaces() == ("forge", "planner")
    assert planner_snapshot.get("planner", "step") is not None
    assert [item.key for item in snapshot.filter_by_tag("plan")] == ["risk", "step"]


def test_working_memory_delete_and_clear_namespace() -> None:
    store = WorkingMemoryStore()
    store.put("planner", "step", 1)
    store.put("planner", "risk", 2)
    store.put("forge", "target", 3)

    assert store.delete("planner", "step") is True
    assert store.delete("planner", "step") is False
    assert store.clear_namespace("planner") == 1
    assert store.count() == 1


@pytest.mark.parametrize(
    ("namespace", "key"),
    [
        ("", "current"),
        ("planner", ""),
        ("   ", "current"),
        ("planner", "   "),
    ],
)
def test_working_memory_rejects_empty_identifiers(
    namespace: str,
    key: str,
) -> None:
    store = WorkingMemoryStore()

    with pytest.raises(ValueError, match="must not be empty"):
        store.put(namespace, key, "value")
