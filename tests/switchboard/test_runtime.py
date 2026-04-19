from __future__ import annotations

import pytest

from ix_blackfox.kernel import TaskKind, TaskRequest
from ix_blackfox.switchboard import (
    CapabilityRoute,
    CapabilitySwitchboard,
    RoutingDecisionReason,
    score_route,
)


def test_capability_route_normalizes_name_labels_and_description() -> None:
    route = CapabilityRoute(
        capability_name=" Programming ",
        supported_kinds=(TaskKind.PROGRAMMING,),
        labels=(" Code ", "patching", "code", ""),
        description="  Handles code tasks.  ",
    )

    assert route.capability_name == "programming"
    assert route.labels == ("code", "patching")
    assert route.description == "Handles code tasks."


def test_score_route_prefers_exact_kind_match() -> None:
    route = CapabilityRoute(
        capability_name="architecture",
        supported_kinds=(TaskKind.ARCHITECTURE,),
        labels=("design",),
    )
    task = TaskRequest.create(
        prompt="Design a modular runtime.",
        kind=TaskKind.ARCHITECTURE,
        labels=("design",),
    )

    decision = score_route(route, task)

    assert decision is not None
    assert decision.reason == RoutingDecisionReason.EXACT_KIND_MATCH
    assert decision.confidence == 1.0
    assert decision.capability_name == "architecture"


def test_score_route_can_match_by_labels() -> None:
    route = CapabilityRoute(
        capability_name="programming",
        labels=("code", "patching", "tests"),
    )
    task = TaskRequest.create(
        prompt="Inspect this repo and patch it.",
        labels=("security", "code"),
    )

    decision = score_route(route, task)

    assert decision is not None
    assert decision.reason == RoutingDecisionReason.LABEL_MATCH
    assert decision.matched_labels == ("code",)
    assert 0.35 <= decision.confidence <= 0.95


def test_switchboard_routes_to_best_match_over_fallback() -> None:
    switchboard = CapabilitySwitchboard()
    switchboard.register(
        CapabilityRoute(
            capability_name="generalist",
            is_fallback=True,
        )
    )
    switchboard.register(
        CapabilityRoute(
            capability_name="programming",
            supported_kinds=(TaskKind.PROGRAMMING,),
            labels=("code", "patching"),
        )
    )

    task = TaskRequest.create(
        prompt="Patch the failing tests.",
        kind=TaskKind.PROGRAMMING,
        labels=("code",),
    )

    decision = switchboard.route(task)

    assert decision is not None
    assert decision.capability_name == "programming"
    assert decision.reason == RoutingDecisionReason.EXACT_KIND_MATCH
    assert decision.confidence == 1.0


def test_switchboard_register_replaces_existing_route_by_name() -> None:
    switchboard = CapabilitySwitchboard()
    switchboard.register(
        CapabilityRoute(
            capability_name="programming",
            labels=("code",),
        )
    )
    switchboard.register(
        CapabilityRoute(
            capability_name="programming",
            labels=("patching",),
        )
    )

    snapshot = switchboard.snapshot()
    assert snapshot.capability_names() == ("programming",)
    assert snapshot.routes[0].labels == ("patching",)


def test_switchboard_unregister_validates_name() -> None:
    switchboard = CapabilitySwitchboard()

    with pytest.raises(ValueError, match="must not be empty"):
        switchboard.unregister("   ")
