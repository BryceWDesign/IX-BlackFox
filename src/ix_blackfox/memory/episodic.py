from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from threading import RLock
from typing import Any
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class EpisodeRecord:
    """
    One episodic-memory record.

    Attributes
    ----------
    episode_id:
        Stable unique episode identifier.
    session_id:
        Logical session identifier for grouping related episodes.
    task_id:
        Optional task identifier associated with the episode.
    title:
        Short human-readable title for the episode.
    summary:
        Concise summary of what happened.
    outcome:
        Outcome classification such as success, failure, or canceled.
    created_at:
        UTC timestamp when the episode was created.
    tags:
        Optional normalized tags for lookup and grouping.
    metadata:
        Optional structured metadata payload.
    """

    episode_id: str
    session_id: str
    task_id: str | None
    title: str
    summary: str
    outcome: str
    created_at: datetime
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def with_summary(self, summary: str) -> EpisodeRecord:
        """
        Return a copy with an updated summary.
        """
        normalized_summary = _normalize_text(summary, label="summary")
        return replace(self, summary=normalized_summary)


@dataclass(frozen=True, slots=True)
class EpisodicMemorySnapshot:
    """
    Immutable view of episodic-memory records.
    """

    episodes: tuple[EpisodeRecord, ...]

    def get(self, episode_id: str) -> EpisodeRecord | None:
        """
        Retrieve an episode by its stable identifier.
        """
        normalized_episode_id = _normalize_text(episode_id, label="episode id")
        for episode in self.episodes:
            if episode.episode_id == normalized_episode_id:
                return episode
        return None

    def filter_by_session(self, session_id: str) -> tuple[EpisodeRecord, ...]:
        """
        Return all episodes for a given session.
        """
        normalized_session_id = _normalize_text(session_id, label="session id")
        return tuple(
            episode
            for episode in self.episodes
            if episode.session_id == normalized_session_id
        )

    def filter_by_tag(self, tag: str) -> tuple[EpisodeRecord, ...]:
        """
        Return all episodes containing the given tag.
        """
        normalized_tag = _normalize_text(tag, label="tag").lower()
        return tuple(
            episode for episode in self.episodes if normalized_tag in episode.tags
        )


class EpisodicMemoryStore:
    """
    Thread-safe episodic-memory store.

    Episodic memory captures what happened during prior interactions and
    runtime operations without collapsing them into generic long-term facts.
    """

    def __init__(self) -> None:
        self._episodes: dict[str, EpisodeRecord] = {}
        self._lock = RLock()

    def create(
        self,
        *,
        session_id: str,
        title: str,
        summary: str,
        outcome: str,
        task_id: str | None = None,
        tags: tuple[str, ...] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> EpisodeRecord:
        """
        Create and store a new episodic-memory record.
        """
        normalized_session_id = _normalize_text(session_id, label="session id")
        normalized_title = _normalize_text(title, label="title")
        normalized_summary = _normalize_text(summary, label="summary")
        normalized_outcome = _normalize_text(outcome, label="outcome").lower()
        normalized_task_id = _normalize_optional_text(task_id)
        normalized_tags = _normalize_tags(tags or ())

        episode = EpisodeRecord(
            episode_id=f"ep-{uuid4().hex}",
            session_id=normalized_session_id,
            task_id=normalized_task_id,
            title=normalized_title,
            summary=normalized_summary,
            outcome=normalized_outcome,
            created_at=_utc_now(),
            tags=normalized_tags,
            metadata=dict(metadata or {}),
        )

        with self._lock:
            self._episodes[episode.episode_id] = episode

        return episode

    def get(self, episode_id: str) -> EpisodeRecord | None:
        """
        Retrieve an episode by identifier.
        """
        normalized_episode_id = _normalize_text(episode_id, label="episode id")
        with self._lock:
            return self._episodes.get(normalized_episode_id)

    def replace(self, episode: EpisodeRecord) -> None:
        """
        Replace an existing episode record by its identifier.
        """
        with self._lock:
            if episode.episode_id not in self._episodes:
                raise KeyError(f"Episode '{episode.episode_id}' does not exist.")
            self._episodes[episode.episode_id] = episode

    def snapshot(self) -> EpisodicMemorySnapshot:
        """
        Return an immutable snapshot of episodic memory in creation order.
        """
        with self._lock:
            episodes = tuple(
                sorted(
                    self._episodes.values(),
                    key=lambda item: (item.created_at, item.episode_id),
                )
            )
        return EpisodicMemorySnapshot(episodes=episodes)

    def count(self) -> int:
        """
        Return the total number of episodes stored.
        """
        with self._lock:
            return len(self._episodes)

    def clear(self) -> None:
        """
        Remove all episodic-memory records.
        """
        with self._lock:
            self._episodes.clear()


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"Episodic memory {label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _normalize_tags(tags: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for tag in tags:
        cleaned = tag.strip().lower()
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
