from __future__ import annotations

from ix_blackfox.kernel import TaskKind, TaskRequest
from ix_blackfox.runtime import TaskReplayGuard, fingerprint_task_request


def test_fingerprint_is_stable_for_equivalent_requests() -> None:
    first = TaskRequest.create(
        prompt="Fix the failing tests.",
        kind=TaskKind.PROGRAMMING,
        labels=("code", "tests"),
    )
    second = TaskRequest.create(
        prompt="Fix the failing tests.",
        kind=TaskKind.PROGRAMMING,
        labels=("code", "tests"),
    )

    assert fingerprint_task_request(first) == fingerprint_task_request(second)


def test_replay_guard_flags_recent_duplicate_requests() -> None:
    guard = TaskReplayGuard(window_size=4)
    request = TaskRequest.create(
        prompt="Fix the failing tests.",
        kind=TaskKind.PROGRAMMING,
        labels=("code",),
    )

    first = guard.observe(request)
    second = guard.observe(request)

    assert first.duplicate_detected is False
    assert second.duplicate_detected is True
    assert second.seen_count == 2
