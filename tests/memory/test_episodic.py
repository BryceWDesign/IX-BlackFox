from __future__ import annotations

import pytest

from ix_blackfox.memory import EpisodicMemoryStore


def test_episodic_memory_create_and_get() -> None:
    store = EpisodicMemoryStore()

    episode = store.create(
        session_id="session-001",
        task_id="task-123",
        title="Initial repo scan",
        summary="Scanned the codebase and found unstable tests.",
        outcome="Success",
        tags=("scan", "repo", "scan"),
        metadata={"failures": 3},
    )

    fetched = store.get(episode.episode_id)

    assert episode.episode_id.startswith("ep-")
    assert episode.outcome == "success"
    assert episode.tags == ("scan", "repo")
    assert episode.metadata == {"failures": 3}
    assert fetched == episode


def test_episodic_memory_snapshot_filters() -> None:
    store = EpisodicMemoryStore()
    first = store.create(
        session_id="session-a",
        title="Discovery",
        summary="Mapped the runtime surface.",
        outcome="success",
        tags=("mapping", "analysis"),
    )
    second = store.create(
        session_id="session-a",
        title="Patch plan",
        summary="Prepared patch steps.",
        outcome="success",
        tags=("planning",),
    )
    third = store.create(
        session_id="session-b",
        title="Failure review",
        summary="Captured the failing branch.",
        outcome="failure",
        tags=("analysis", "risk"),
    )

    snapshot = store.snapshot()

    assert snapshot.get(first.episode_id) == first
    assert snapshot.filter_by_session("session-a") == (first, second)
    assert snapshot.filter_by_tag("analysis") == (first, third)


def test_episodic_memory_replace_updates_existing_record() -> None:
    store = EpisodicMemoryStore()
    episode = store.create(
        session_id="session-001",
        title="Task run",
        summary="Execution started.",
        outcome="success",
    )

    updated = episode.with_summary("Execution started and completed cleanly.")
    store.replace(updated)

    fetched = store.get(episode.episode_id)
    assert fetched is not None
    assert fetched.summary == "Execution started and completed cleanly."


def test_episodic_memory_replace_requires_existing_record() -> None:
    store = EpisodicMemoryStore()
    episode = store.create(
        session_id="session-001",
        title="Task run",
        summary="Execution started.",
        outcome="success",
    )

    store.clear()

    with pytest.raises(KeyError, match="does not exist"):
        store.replace(episode)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {
                "session_id": "   ",
                "title": "Title",
                "summary": "Summary",
                "outcome": "success",
            },
            "session id must not be empty",
        ),
        (
            {
                "session_id": "session-1",
                "title": "   ",
                "summary": "Summary",
                "outcome": "success",
            },
            "title must not be empty",
        ),
        (
            {
                "session_id": "session-1",
                "title": "Title",
                "summary": "   ",
                "outcome": "success",
            },
            "summary must not be empty",
        ),
        (
            {
                "session_id": "session-1",
                "title": "Title",
                "summary": "Summary",
                "outcome": "   ",
            },
            "outcome must not be empty",
        ),
    ],
)
def test_episodic_memory_rejects_empty_required_fields(
    kwargs: dict[str, str],
    message: str,
) -> None:
    store = EpisodicMemoryStore()

    with pytest.raises(ValueError, match=message):
        store.create(**kwargs)
