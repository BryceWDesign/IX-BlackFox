from __future__ import annotations

from time import sleep

import pytest

from ix_blackfox.memory import SemanticMemoryStore


def test_semantic_memory_upsert_get_and_alias_resolution() -> None:
    store = SemanticMemoryStore()

    first = store.upsert(
        key="Primary Runtime",
        value="kernel",
        fact_type="constraint",
        confidence=0.9,
        source="bootstrap",
        tags=("Core", "Runtime"),
        aliases=("runtime core", "Kernel"),
    )
    sleep(0.001)
    second = store.upsert(
        key="primary runtime",
        value="kernel-v2",
        fact_type="constraint",
        confidence=1.0,
        source="kernel",
        tags=("core", "runtime", "core"),
        aliases=("Runtime Core", "Kernel"),
    )

    assert first.key == "primary runtime"
    assert first.aliases == ("runtime core", "kernel")
    assert first.tags == ("core", "runtime")
    assert second.concept_id == first.concept_id
    assert second.value == "kernel-v2"
    assert second.updated_at >= first.updated_at

    assert store.get("primary runtime") == second
    assert store.get("runtime core") == second
    assert store.get("kernel") == second


def test_semantic_memory_snapshot_filters() -> None:
    store = SemanticMemoryStore()
    first = store.upsert(
        key="patch rule",
        value="tests must run after changes",
        fact_type="rule",
        tags=("verification", "policy"),
    )
    second = store.upsert(
        key="project codename",
        value="blackfox",
        fact_type="fact",
        tags=("identity",),
    )
    third = store.upsert(
        key="safety boundary",
        value="no destructive host mutation by default",
        fact_type="constraint",
        tags=("policy", "safety"),
    )

    snapshot = store.snapshot()

    assert snapshot.get("patch rule") == first
    assert snapshot.filter_by_fact_type("rule") == (first,)
    assert snapshot.filter_by_tag("policy") == (first, third)
    assert snapshot.get("project codename") == second


def test_semantic_memory_delete_and_clear() -> None:
    store = SemanticMemoryStore()
    store.upsert(
        key="planner mode",
        value="strict",
        aliases=("routing mode",),
    )

    assert store.delete("planner mode") is True
    assert store.delete("planner mode") is False
    assert store.get("routing mode") is None

    store.upsert(key="a", value=1)
    store.upsert(key="b", value=2)
    store.clear()

    assert store.count() == 0
    assert store.snapshot().records == ()


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {"key": "   ", "value": 1},
            "Semantic memory key must not be empty",
        ),
        (
            {"key": "rule", "value": 1, "fact_type": "   "},
            "Semantic memory fact type must not be empty",
        ),
        (
            {"key": "rule", "value": 1, "confidence": 1.5},
            "confidence must be between 0.0 and 1.0",
        ),
    ],
)
def test_semantic_memory_rejects_invalid_inputs(
    kwargs: dict[str, object],
    message: str,
) -> None:
    store = SemanticMemoryStore()

    with pytest.raises(ValueError, match=message):
        store.upsert(**kwargs)
