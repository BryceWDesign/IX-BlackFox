from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from threading import RLock

from ix_blackfox.bus.messages import EventEnvelope, EventTopic

EventHandler = Callable[[EventEnvelope], None]


@dataclass(frozen=True, slots=True)
class EventDispatchResult:
    """
    Outcome of dispatching one envelope to one subscriber.

    Attributes
    ----------
    topic:
        Topic under which the handler was subscribed.
    handler_name:
        Best-effort handler display name.
    success:
        Whether the handler completed without raising.
    error:
        Stringified exception message when dispatch failed.
    """

    topic: EventTopic
    handler_name: str
    success: bool
    error: str | None = None


class InMemoryEventBus:
    """
    Thread-safe in-memory event bus for early BlackFox runtime wiring.

    This bus is intentionally simple but typed and auditable. Later
    revisions can add richer filtering, replay, persistence, backpressure,
    or async transport without changing the core envelope model.
    """

    def __init__(self) -> None:
        self._subscribers: dict[EventTopic, list[EventHandler]] = defaultdict(list)
        self._history: list[EventEnvelope] = []
        self._lock = RLock()

    def subscribe(self, topic: EventTopic, handler: EventHandler) -> None:
        """
        Register a handler for a specific event topic.

        Duplicate registrations of the same callable for the same topic are
        ignored to keep dispatch deterministic.
        """
        with self._lock:
            handlers = self._subscribers[topic]
            if handler not in handlers:
                handlers.append(handler)

    def publish(self, envelope: EventEnvelope) -> tuple[EventDispatchResult, ...]:
        """
        Publish an event to all subscribers of its topic.

        Dispatch failures are isolated per handler and reported in the
        returned results. One failing handler does not block others.
        """
        with self._lock:
            self._history.append(envelope)
            handlers = tuple(self._subscribers.get(envelope.topic, ()))

        results: list[EventDispatchResult] = []
        for handler in handlers:
            try:
                handler(envelope)
            except Exception as exc:  # pragma: no cover - exercised in tests
                results.append(
                    EventDispatchResult(
                        topic=envelope.topic,
                        handler_name=_handler_name(handler),
                        success=False,
                        error=str(exc),
                    )
                )
            else:
                results.append(
                    EventDispatchResult(
                        topic=envelope.topic,
                        handler_name=_handler_name(handler),
                        success=True,
                    )
                )

        return tuple(results)

    def history(self, *, limit: int | None = None) -> tuple[EventEnvelope, ...]:
        """
        Return an immutable snapshot of published event history.
        """
        with self._lock:
            if limit is None:
                return tuple(self._history)
            if limit < 0:
                raise ValueError("History limit must be greater than or equal to zero.")
            if limit == 0:
                return ()
            return tuple(self._history[-limit:])

    def subscription_count(self, topic: EventTopic) -> int:
        """
        Return the number of handlers subscribed to a topic.
        """
        with self._lock:
            return len(self._subscribers.get(topic, ()))

    def clear(self) -> None:
        """
        Remove all subscribers and in-memory history.
        """
        with self._lock:
            self._subscribers.clear()
            self._history.clear()


def _handler_name(handler: EventHandler) -> str:
    return getattr(handler, "__name__", handler.__class__.__name__)
