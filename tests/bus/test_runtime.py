from __future__ import annotations

import pytest

from ix_blackfox.bus import EventEnvelope, EventTopic, InMemoryEventBus


def test_event_envelope_create_normalizes_fields() -> None:
    envelope = EventEnvelope.create(
        topic=EventTopic.TASK,
        source=" kernel ",
        payload={"state": "ready"},
        correlation_id="  task-123  ",
        tags=(" Task ", "ready", "task", "", " READY "),
    )

    assert envelope.event_id.startswith("evt-")
    assert envelope.topic == EventTopic.TASK
    assert envelope.source == "kernel"
    assert envelope.payload == {"state": "ready"}
    assert envelope.correlation_id == "task-123"
    assert envelope.tags == ("task", "ready")


def test_event_envelope_requires_source() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        EventEnvelope.create(topic=EventTopic.SYSTEM, source="   ")


def test_event_bus_dispatches_to_subscribers() -> None:
    bus = InMemoryEventBus()
    received: list[EventEnvelope] = []

    def handler(envelope: EventEnvelope) -> None:
        received.append(envelope)

    bus.subscribe(EventTopic.KERNEL, handler)
    bus.subscribe(EventTopic.KERNEL, handler)

    envelope = EventEnvelope.create(
        topic=EventTopic.KERNEL,
        source="runtime",
        payload={"status": "running"},
    )
    results = bus.publish(envelope)

    assert bus.subscription_count(EventTopic.KERNEL) == 1
    assert received == [envelope]
    assert len(results) == 1
    assert results[0].success is True
    assert results[0].handler_name == "handler"


def test_event_bus_isolates_handler_failures() -> None:
    bus = InMemoryEventBus()
    received: list[str] = []

    def broken_handler(envelope: EventEnvelope) -> None:
        raise RuntimeError(f"boom: {envelope.source}")

    def healthy_handler(envelope: EventEnvelope) -> None:
        received.append(envelope.source)

    bus.subscribe(EventTopic.SENTINEL, broken_handler)
    bus.subscribe(EventTopic.SENTINEL, healthy_handler)

    envelope = EventEnvelope.create(topic=EventTopic.SENTINEL, source="sentinel")
    results = bus.publish(envelope)

    assert received == ["sentinel"]
    assert len(results) == 2
    assert [result.success for result in results] == [False, True]
    assert results[0].error == "boom: sentinel"


def test_event_bus_history_limit_validation() -> None:
    bus = InMemoryEventBus()
    bus.publish(EventEnvelope.create(topic=EventTopic.SYSTEM, source="system"))
    bus.publish(EventEnvelope.create(topic=EventTopic.SYSTEM, source="kernel"))

    assert len(bus.history()) == 2
    assert len(bus.history(limit=1)) == 1
    assert bus.history(limit=0) == ()

    with pytest.raises(ValueError, match="greater than or equal to zero"):
        bus.history(limit=-1)
