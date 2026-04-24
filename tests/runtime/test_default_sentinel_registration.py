from __future__ import annotations

from pathlib import Path

from ix_blackfox.runtime import BlackFoxRuntime
from ix_blackfox.sentinel import SentinelContext


def test_default_runtime_registers_builtin_sentinel_checks(
    tmp_path: Path,
) -> None:
    runtime = BlackFoxRuntime.create_default(root_dir=tmp_path)

    snapshot = runtime._sentinel.snapshot()  # noqa: SLF001

    assert snapshot.contains("governance-contradiction-check") is True
    assert snapshot.contains("approval-gate-consistency-check") is True
    assert snapshot.contains("task-state-trace-contradiction-check") is True

    report = runtime._sentinel.evaluate(  # noqa: SLF001
        SentinelContext(
            metadata={
                "governance_observations": (
                    {
                        "decision": "block",
                        "executed": True,
                        "approval_required": False,
                        "approval_satisfied": False,
                    },
                )
            }
        )
    )

    assert report.check_count == 3
    assert report.has_issue_code("sentinel.governance_execution_contradiction") is True
    assert report.has_contradiction_signal() is True
