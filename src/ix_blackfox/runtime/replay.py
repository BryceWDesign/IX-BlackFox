from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import dataclass
from threading import RLock
from typing import Deque

from ix_blackfox.kernel import TaskRequest


@dataclass(frozen=True, slots=True)
class ReplayObservation:
    """
    One observation from the task replay guard.

    Attributes
    ----------
    fingerprint:
        Stable fingerprint for the normalized task shape.
    duplicate_detected:
        Whether the same task fingerprint was observed recently.
    seen_count:
        Number of times this fingerprint has been observed in the live window.
    window_size:
        Current replay window size.
    """

    fingerprint: str
    duplicate_detected: bool
    seen_count: int
    window_size: int


class TaskReplayGuard:
    """
    Sliding replay guard for recently observed task fingerprints.

    This guard applies replay-window discipline to BlackFox task intake so
    repeated identical requests can be surfaced explicitly instead of
    disappearing into the runtime.
    """

    def __init__(self, *, window_size: int = 128) -> None:
        if window_size < 1:
            raise ValueError("Task replay window size must be greater than zero.")
        self._window_size = window_size
        self._recent: Deque[str] = deque(maxlen=window_size)
        self._counts: dict[str, int] = {}
        self._lock = RLock()

    @property
    def window_size(self) -> int:
        return self._window_size

    def observe(self, task: TaskRequest) -> ReplayObservation:
        """
        Observe one task request and report whether it is a recent duplicate.
        """
        fingerprint = fingerprint_task_request(task)

        with self._lock:
            duplicate_detected = fingerprint in self._counts
            self._recent.append(fingerprint)
            self._counts[fingerprint] = self._counts.get(fingerprint, 0) + 1
            self._recount_if_needed()
            seen_count = self._counts[fingerprint]

        return ReplayObservation(
            fingerprint=fingerprint,
            duplicate_detected=duplicate_detected,
            seen_count=seen_count,
            window_size=self._window_size,
        )

    def clear(self) -> None:
        with self._lock:
            self._recent.clear()
            self._counts.clear()

    def unique_fingerprint_count(self) -> int:
        with self._lock:
            return len(self._counts)

    def _recount_if_needed(self) -> None:
        if len(self._recent) < self._window_size:
            return

        self._counts = {}
        for fingerprint in self._recent:
            self._counts[fingerprint] = self._counts.get(fingerprint, 0) + 1


def fingerprint_task_request(task: TaskRequest) -> str:
    """
    Build a stable digest for the semantic task shape.
    """
    payload = {
        "kind": task.kind.value,
        "priority": int(task.priority),
        "prompt": task.input.prompt.strip(),
        "labels": task.labels,
        "attachments": task.input.attachments,
        "metadata": _normalized_metadata(task.input.metadata),
    }
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalized_metadata(metadata: dict[str, object]) -> dict[str, object]:
    return {str(key): metadata[key] for key in sorted(metadata)}
