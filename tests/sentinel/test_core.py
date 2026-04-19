from __future__ import annotations

import pytest

from ix_blackfox.sentinel import (
    SentinelCheck,
    SentinelContext,
    SentinelIssue,
    SentinelRuntime,
    SentinelSeverity,
)


class QuietCheck(SentinelCheck):
    @property
    def check_name(self) -> str:
        return "quiet"

    def evaluate(self, context: SentinelContext) -> tuple[SentinelIssue, ...]:
        _ = context
        return ()


class RiskCheck(SentinelCheck):
    @property
    def check_name(self) -> str:
        return "risk"

    def evaluate(self, context: SentinelContext) -> tuple[SentinelIssue, ...]:
        mode = context.metadata.get("mode", "unknown")
        return (
            SentinelIssue(
                code="runtime.risk_detected",
                severity=SentinelSeverity.WARNING,
                summary="Risky runtime condition detected.",
                source=self.check_name,
                details=f"mode={mode}",
                data={"mode": mode},
            ),
        )


class BrokenCheck(SentinelCheck):
    @property
    def check_name(self) -> str:
        return "broken"

    def evaluate(self, context: SentinelContext) -> tuple[SentinelIssue, ...]:
        _ = context
        raise RuntimeError("boom")


def test_sentinel_issue_normalizes_fields() -> None:
    issue = SentinelIssue(
        code=" Runtime.Risk_Detected ",
        severity=SentinelSeverity.WARNING,
        summary="  Risky runtime condition detected.  ",
        source=" risk ",
        details="  extra details  ",
    )

    assert issue.code == "runtime.risk_detected"
    assert issue.summary == "Risky runtime condition detected."
    assert issue.source == "risk"
    assert issue.details == "extra details"


def test_sentinel_runtime_registers_and_replaces_by_name() -> None:
    runtime = SentinelRuntime()
    runtime.register(QuietCheck())
    runtime.register(RiskCheck())
    runtime.register(RiskCheck())

    snapshot = runtime.snapshot()

    assert snapshot.check_names == ("quiet", "risk")
    assert snapshot.contains("risk") is True
    assert snapshot.contains("broken") is False


def test_sentinel_runtime_evaluates_and_filters_issues() -> None:
    runtime = SentinelRuntime()
    runtime.register(QuietCheck())
    runtime.register(RiskCheck())

    report = runtime.evaluate(
        SentinelContext(
            metadata={"mode": "manual"},
        )
    )

    assert report.check_count == 2
    assert len(report.issues) == 1
    assert report.has_severity(SentinelSeverity.WARNING) is True
    assert report.has_severity(SentinelSeverity.CRITICAL) is False
    assert report.filter_by_severity(SentinelSeverity.WARNING)[0].code == (
        "runtime.risk_detected"
    )
    assert report.issues[0].data == {"mode": "manual"}


def test_sentinel_runtime_converts_check_failure_to_issue() -> None:
    runtime = SentinelRuntime()
    runtime.register(BrokenCheck())

    report = runtime.evaluate(SentinelContext())

    assert report.check_count == 1
    assert len(report.issues) == 1
    assert report.issues[0].code == "sentinel.check_failed"
    assert report.issues[0].severity == SentinelSeverity.ERROR
    assert report.issues[0].source == "broken"
    assert report.issues[0].details == "boom"


@pytest.mark.parametrize(
    ("builder", "message"),
    [
        (
            lambda: SentinelIssue(
                code="   ",
                severity=SentinelSeverity.ERROR,
                summary="problem",
            ),
            "Sentinel issue code must not be empty",
        ),
        (
            lambda: SentinelIssue(
                code="problem.code",
                severity=SentinelSeverity.ERROR,
                summary="   ",
            ),
            "Sentinel issue summary must not be empty",
        ),
        (
            lambda: SentinelRuntime().unregister("   "),
            "Sentinel check name must not be empty",
        ),
    ],
)
def test_sentinel_rejects_invalid_inputs(builder, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        builder()
