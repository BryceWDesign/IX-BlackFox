from __future__ import annotations

import pytest

from ix_blackfox.kernel import SharedStateStore


def test_put_get_and_version_increment() -> None:
    store = SharedStateStore()

    first = store.put("Kernel", "Status", "ready", source="bootstrap")
    second = store.put("kernel", "status", "running", source="runtime")

    assert first.namespace == "kernel"
    assert first.key == "status"
    assert first.version == 1
    assert first.source == "bootstrap"

    assert second.version == 2
    assert second.value == "running"
    assert second.source == "runtime"

    fetched = store.get("kernel", "status")
    assert fetched == second


def test_compare_and_set_updates_only_on_matching_version() -> None:
    store = SharedStateStore()
    first = store.put("task", "active", {"count": 1})

    missed = store.compare_and_set(
        "task",
        "active",
        expected_version=999,
        value={"count": 2},
    )
    updated = store.compare_and_set(
        "task",
        "active",
        expected_version=first.version,
        value={"count": 2},
        source="scheduler",
    )

    assert missed is None
    assert updated is not None
    assert updated.version == 2
    assert updated.value == {"count": 2}
    assert updated.source == "scheduler"


def test_snapshot_is_sorted_and_filterable() -> None:
    store = SharedStateStore()
    store.put("packs", "loaded", ["programming"])
    store.put("kernel", "status", "ready")
    store.put("kernel", "mode", "interactive")

    snapshot = store.snapshot()
    kernel_snapshot = store.snapshot(namespace="kernel")

    assert [(entry.namespace, entry.key) for entry in snapshot.entries] == [
        ("kernel", "mode"),
        ("kernel", "status"),
        ("packs", "loaded"),
    ]
    assert [(entry.namespace, entry.key) for entry in kernel_snapshot.entries] == [
        ("kernel", "mode"),
        ("kernel", "status"),
    ]
    assert kernel_snapshot.as_nested_dict() == {
        "kernel": {
            "mode": "interactive",
            "status": "ready",
        }
    }


def test_delete_and_clear_work() -> None:
    store = SharedStateStore()
    store.put("memory", "tier", "working")

    assert store.delete("memory", "tier") is True
    assert store.delete("memory", "tier") is False

    store.put("kernel", "status", "ready")
    store.put("task", "count", 1)
    store.clear()

    assert store.snapshot().entries == ()
    assert store.namespaces() == ()


@pytest.mark.parametrize(
    ("namespace", "key"),
    [
        ("", "status"),
        ("kernel", ""),
        ("   ", "status"),
        ("kernel", "   "),
    ],
)
def test_empty_identifiers_raise(namespace: str, key: str) -> None:
    store = SharedStateStore()

    with pytest.raises(ValueError, match="must not be empty"):
        store.put(namespace, key, "value")


def test_compare_and_set_rejects_invalid_expected_version() -> None:
    store = SharedStateStore()
    store.put("kernel", "status", "ready")

    with pytest.raises(ValueError, match="greater than or equal to 1"):
        store.compare_and_set(
            "kernel",
            "status",
            expected_version=0,
            value="running",
        )
