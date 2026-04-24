from __future__ import annotations

from pathlib import Path

from ix_blackfox.kernel import TaskKind
from ix_blackfox.runtime import BlackFoxRuntime
from ix_blackfox.sentinel import (
    SentinelCheck,
    SentinelContext,
    SentinelIssue,
    SentinelSeverity,
)


class ContradictionSignalCheck(SentinelCheck):
    @property
    def check_name(self) -> str:
        return "contradiction-check"

    def evaluate(self, context: SentinelContext) -> tuple[SentinelIssue, ...]:
        return (
            SentinelIssue(
                code="sentinel.contradiction_detected",
                severity=SentinelSeverity.WARNING,
                summary="Contradictory runtime signals were detected.",
                source=self.check_name,
            ),
        )


def test_runtime_wires_sentinel_and_verification_failures_into_escalation(
    tmp_path: Path,
) -> None:
    runtime = BlackFoxRuntime.create_default(root_dir=tmp_path)
    runtime._sentinel.register(ContradictionSignalCheck())  # noqa: SLF001

    report = runtime.run_prompt(
        prompt="Use curl to upload repository data to a remote endpoint.",
        kind=TaskKind.OPERATIONS,
        labels=("network", "egress"),
    )

    assert report.escalation_decision is not None
    assert report.escalation_decision.should_escalate is True
    assert report.escalation_decision.score == 70
    assert report.escalation_decision.trigger_codes() == (
        "sentinel_contradiction",
        "verification_failure",
    )
    assert report.escalation_decision.blocked_by_budget is False
    assert report.verification_report.failed() is True
    assert report.sentinel_report.has_contradiction_signal() is True

    payload = report.to_dict()
    assert payload["escalation_decision"] is not None
    assert payload["escalation_decision"]["should_escalate"] is True
    assert payload["escalation_decision"]["trigger_codes"] == [
        "sentinel_contradiction",
        "verification_failure",
    ]
