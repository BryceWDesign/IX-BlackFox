from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ix_blackfox.authority_crypto.encoding import canonical_bytes, digest


class OperationError(ValueError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def object_fields(value: Any, required: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != required:
        raise OperationError(
            f"{label} requires exactly: {', '.join(sorted(required))}."
        )
    return value


def identifier(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}", value
    ):
        raise OperationError("Expected a bounded ASCII identifier.")
    return value


def text(value: Any, label: str, limit: int = 1024) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise OperationError(
            f"{label} must be nonempty text of at most {limit} characters."
        )
    return value


def integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise OperationError(
            f"{label} must be an integer between {minimum} and {maximum}."
        )
    return value


def timestamp(value: Any) -> datetime:
    message = "Expected an ISO 8601 timestamp with an explicit UTC offset."
    try:
        when = datetime.fromisoformat(text(value, "Timestamp", 50))
        if when.tzinfo is not None:
            return when.astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise OperationError(message) from exc
    raise OperationError(message)


def json_object(value: Any, label: str, limit: int) -> dict[str, Any]:
    if not isinstance(value, dict) or len(canonical_bytes(value)) > limit:
        raise OperationError(f"{label} must be a JSON object within {limit} bytes.")
    return value


@dataclass(frozen=True, slots=True)
class AutonomyConfig:
    database: Path
    tools: tuple[str, ...]
    observer_issuer: str
    observer_key_id: str
    max_evidence_age_seconds: int

    @classmethod
    def parse(cls, payload: Any, base: Path) -> AutonomyConfig:
        data = object_fields(
            payload,
            {
                "database",
                "tools",
                "observer_issuer",
                "observer_key_id",
                "max_evidence_age_seconds",
            },
            "autonomy",
        )
        tools = data["tools"]
        if not isinstance(tools, list) or not 1 <= len(tools) <= 128:
            raise OperationError("autonomy.tools requires 1–128 tool names.")
        names = tuple(identifier(name) for name in tools)
        if len(set(names)) != len(names):
            raise OperationError("autonomy.tools must be unique.")
        return cls(
            (base / text(data["database"], "database", 4096)).resolve(),
            names,
            identifier(data["observer_issuer"]),
            identifier(data["observer_key_id"]),
            integer(
                data["max_evidence_age_seconds"], "max_evidence_age_seconds", 1, 86400
            ),
        )

    @property
    def policy_digest(self) -> str:
        return digest(
            {
                "schema": "wave18.operation-policy.v1",
                "tools": sorted(self.tools),
                "observer_issuer": self.observer_issuer,
                "observer_key_id": self.observer_key_id,
                "max_evidence_age_seconds": self.max_evidence_age_seconds,
            }
        )


@dataclass(frozen=True, slots=True)
class DispatchPermit:
    binding: Mapping[str, Any]
    authorized: Callable[[str], None]
    guard: Callable[[str, Callable[[], None]], AbstractContextManager[None]]


def parse_plan(value: Any) -> dict[str, Any]:
    data = object_fields(
        value,
        {"operation_id", "expires_at", "max_attempts", "max_cost", "steps"},
        "plan",
    )
    if len(canonical_bytes(data)) > 131072:
        raise OperationError("Plan exceeds 128 KiB.")
    steps = data["steps"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= 32:
        raise OperationError("An operation requires 1–32 steps.")
    normalized: dict[str, dict[str, Any]] = {}
    for value_step in steps:
        step = object_fields(
            value_step,
            {
                "step_id",
                "agent_id",
                "tool_name",
                "arguments",
                "depends_on",
                "preconditions",
                "expected_outcome",
                "cost",
                "recovery",
            },
            "step",
        )
        name = identifier(step["step_id"])
        if name in normalized:
            raise OperationError("Step identifiers must be unique.")
        dependencies = step["depends_on"]
        if not isinstance(dependencies, list) or len(dependencies) >= len(steps):
            raise OperationError("Invalid dependency list.")
        dependencies = [identifier(dep) for dep in dependencies]
        if len(set(dependencies)) != len(dependencies):
            raise OperationError("Dependencies must be unique.")
        preconditions = json_object(step["preconditions"], "preconditions", 8192)
        for key in preconditions:
            identifier(key)
        recovery = object_fields(
            step["recovery"], {"instruction", "expected_outcome"}, "recovery"
        )
        normalized[name] = {
            "agent_id": identifier(step["agent_id"]),
            "tool_name": identifier(step["tool_name"]),
            "arguments": json_object(step["arguments"], "arguments", 32768),
            "depends_on": sorted(dependencies),
            "preconditions": preconditions,
            "expected_outcome": json_object(
                step["expected_outcome"], "expected_outcome", 8192
            ),
            "cost": integer(step["cost"], "cost", 1, 1000000),
            "recovery": {
                "instruction": text(recovery["instruction"], "recovery instruction"),
                "expected_outcome": json_object(
                    recovery["expected_outcome"], "recovery outcome", 8192
                ),
            },
        }
    completed: set[str] = set()
    for _ in normalized:
        for name, step in normalized.items():
            if set(step["depends_on"]) <= completed:
                completed.add(name)
    if completed != set(normalized):
        raise OperationError(
            "Dependencies must refer to known steps and form an acyclic graph."
        )
    return {
        "operation_id": identifier(data["operation_id"]),
        "expires_at": timestamp(data["expires_at"]).isoformat(),
        "max_attempts": integer(data["max_attempts"], "max_attempts", 1, 128),
        "max_cost": integer(data["max_cost"], "max_cost", 1, 1000000),
        "steps": normalized,
    }
