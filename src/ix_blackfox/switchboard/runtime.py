from __future__ import annotations

from dataclasses import dataclass
from threading import RLock

from ix_blackfox.kernel import TaskRequest
from ix_blackfox.switchboard.models import CapabilityRoute, RoutingDecision, score_route


@dataclass(frozen=True, slots=True)
class SwitchboardSnapshot:
    """
    Immutable view of registered switchboard routes.
    """

    routes: tuple[CapabilityRoute, ...]

    def capability_names(self) -> tuple[str, ...]:
        """
        Return registered capability names in insertion order.
        """
        return tuple(route.capability_name for route in self.routes)


class CapabilitySwitchboard:
    """
    Deterministic internal capability router for IX-BlackFox.

    This first version keeps routing transparent and testable. More advanced
    arbitration layers can build on this contract later without replacing the
    route registry or decision model.
    """

    def __init__(self) -> None:
        self._routes: list[CapabilityRoute] = []
        self._lock = RLock()

    def register(self, route: CapabilityRoute) -> None:
        """
        Register or replace a capability route by capability name.
        """
        with self._lock:
            for index, existing in enumerate(self._routes):
                if existing.capability_name == route.capability_name:
                    self._routes[index] = route
                    return
            self._routes.append(route)

    def unregister(self, capability_name: str) -> bool:
        """
        Remove a capability route by name.
        """
        normalized_name = capability_name.strip().lower()
        if not normalized_name:
            raise ValueError("Capability name must not be empty.")

        with self._lock:
            for index, route in enumerate(self._routes):
                if route.capability_name == normalized_name:
                    del self._routes[index]
                    return True
            return False

    def route(self, task: TaskRequest) -> RoutingDecision | None:
        """
        Select the best capability route for a task request.
        """
        with self._lock:
            routes = tuple(self._routes)

        best_decision: RoutingDecision | None = None
        for route in routes:
            decision = score_route(route, task)
            if decision is None:
                continue
            if best_decision is None or decision.confidence > best_decision.confidence:
                best_decision = decision

        return best_decision

    def snapshot(self) -> SwitchboardSnapshot:
        """
        Return an immutable snapshot of registered routes.
        """
        with self._lock:
            return SwitchboardSnapshot(routes=tuple(self._routes))

    def clear(self) -> None:
        """
        Remove all registered capability routes.
        """
        with self._lock:
            self._routes.clear()
