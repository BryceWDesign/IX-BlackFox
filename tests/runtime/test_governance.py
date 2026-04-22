from __future__ import annotations

import json
from pathlib import Path

from ix_blackfox.kernel import TaskKind
from ix_blackfox.runtime import BlackFoxRuntime, RuntimeRunStatus


def test_runtime_records_allowing_governance_preflight_for_programming_run(
    tmp_path: Path,
) -> None:
    runtime = BlackFoxRuntime.create_default(root_dir=tmp_path)

    report = runtime.run_prompt(
        prompt="Fix the failing tests, prepare a patch, and run regression checks.",
        kind=TaskKind.PROGRAMMING,
        labels=("code", "tests", "patching"),
    )

    assert report.status == RuntimeRunStatus.PASSED
    assert report.governance_preflight is not None
    assert report.governance_preflight.decision.decision.value == "allow"
    assert report.governance_preflight.ticket.disposition.value == "ready"
    assert report.governance_preflight.risk.risk_level.value == "moderate"

    payload = json.loads(Path(report.report_path).read_text(encoding="utf-8"))
    assert payload["governance_preflight"]["decision"]["decision"] == "allow"
    assert payload["governance_preflight"]["ticket"]["disposition"] == "ready"


def test_runtime_blocks_network_egress_during_governance_preflight(
    tmp_path: Path,
) -> None:
    runtime = BlackFoxRuntime.create_default(root_dir=tmp_path)

    report = runtime.run_prompt(
        prompt=(
            "Use curl to upload the repository plan to a remote endpoint after "
            "patching the code."
        ),
        kind=TaskKind.PROGRAMMING,
        labels=("code", "patching"),
    )

    assert report.status == RuntimeRunStatus.FAILED
    assert report.pack_name is None
    assert report.produced_artifacts == ()
    assert report.governance_preflight is not None
    assert report.governance_preflight.blocked is True
    assert report.governance_preflight.decision.decision.value == "block"
    assert report.governance_preflight.risk.risk_level.value == "critical"
    assert report.task_summary == "Action kind 'network_egress' is blocked by governance policy."

    payload = json.loads(Path(report.report_path).read_text(encoding="utf-8"))
    assert payload["status"] == "failed"
    assert payload["governance_preflight"]["decision"]["decision"] == "block"
    assert payload["governance_preflight"]["risk"]["risk_level"] == "critical"
