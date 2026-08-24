from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from ix_blackfox.assurance.models import AssuranceEvidenceKind
from ix_blackfox.assurance.quality import (
    QualityGateSpec,
    default_wave12_quality_gates,
    quality_gates_passed,
    run_quality_gate,
    run_wave12_quality_gates,
)
from tests.assurance.helpers import FIXED_TIME, REVISION


def test_default_quality_gates_cover_test_lint_type_and_compile() -> None:
    gates = default_wave12_quality_gates(python_executable="python")
    assert [gate.gate_id for gate in gates] == [
        "wave12-pytest",
        "wave12-ruff",
        "wave12-mypy",
        "wave12-compileall",
    ]
    assert all(gate.argv[0] == "python" for gate in gates)
    assert {gate.evidence_kind for gate in gates} == {
        AssuranceEvidenceKind.TEST_RESULT,
        AssuranceEvidenceKind.STATIC_ANALYSIS,
        AssuranceEvidenceKind.TYPE_CHECK,
    }


def test_quality_gate_runs_fixed_argv_without_shell(tmp_path: Path) -> None:
    root = _root(tmp_path)
    spec = QualityGateSpec(
        gate_id="success",
        title="Successful gate",
        evidence_kind=AssuranceEvidenceKind.TEST_RESULT,
        argv=(sys.executable, "-c", "print('gate passed')"),
    )
    result = run_quality_gate(
        root=root,
        spec=spec,
        head_sha=REVISION,
        generated_at=FIXED_TIME,
    )
    assert result.passed
    assert result.stdout == "gate passed\n"
    assert result.metadata["shell"] is False
    assert result.to_dict()["digest"] == result.digest


def test_quality_gate_preserves_failure_output(tmp_path: Path) -> None:
    root = _root(tmp_path)
    spec = QualityGateSpec(
        gate_id="failure",
        title="Failing gate",
        evidence_kind=AssuranceEvidenceKind.STATIC_ANALYSIS,
        argv=(
            sys.executable,
            "-c",
            "import sys; print('bad', file=sys.stderr); raise SystemExit(7)",
        ),
    )
    result = run_quality_gate(
        root=root,
        spec=spec,
        head_sha=REVISION,
        generated_at=FIXED_TIME,
    )
    assert not result.passed
    assert result.exit_code == 7
    assert result.stderr == "bad\n"


def test_quality_gate_records_timeout(tmp_path: Path) -> None:
    root = _root(tmp_path)
    spec = QualityGateSpec(
        gate_id="timeout",
        title="Timeout gate",
        evidence_kind=AssuranceEvidenceKind.TEST_RESULT,
        argv=(sys.executable, "-c", "import time; time.sleep(2)"),
        timeout_seconds=1,
    )
    result = run_quality_gate(
        root=root,
        spec=spec,
        head_sha=REVISION,
        generated_at=FIXED_TIME,
    )
    assert result.timed_out
    assert result.exit_code == 124
    assert not result.passed


def test_quality_gate_requires_blackfox_workspace_marker(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    spec = QualityGateSpec(
        gate_id="success",
        title="Successful gate",
        evidence_kind=AssuranceEvidenceKind.TEST_RESULT,
        argv=(sys.executable, "-c", "raise SystemExit(0)"),
    )
    with pytest.raises(ValueError, match="blackfox-workspace"):
        run_quality_gate(
            root=root,
            spec=spec,
            head_sha=REVISION,
            generated_at=FIXED_TIME,
        )


def test_quality_campaign_writes_revision_bound_json(tmp_path: Path) -> None:
    root = _root(tmp_path)
    specs = (
        QualityGateSpec(
            gate_id="first",
            title="First gate",
            evidence_kind=AssuranceEvidenceKind.TEST_RESULT,
            argv=(sys.executable, "-c", "print('first')"),
        ),
        QualityGateSpec(
            gate_id="second",
            title="Second gate",
            evidence_kind=AssuranceEvidenceKind.TYPE_CHECK,
            argv=(sys.executable, "-c", "print('second')"),
        ),
    )
    results = run_wave12_quality_gates(
        root=root,
        head_sha=REVISION,
        generated_at=FIXED_TIME,
        output_dir=root / ".blackfox-artifacts/wave12/quality",
        specs=specs,
    )
    assert quality_gates_passed(results)
    for result, path in results:
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["head_sha"] == REVISION
        assert payload["passed"] is True
        assert payload["digest"] == result.digest


def test_quality_campaign_reports_any_failure(tmp_path: Path) -> None:
    root = _root(tmp_path)
    specs = (
        QualityGateSpec(
            gate_id="failure",
            title="Failure",
            evidence_kind=AssuranceEvidenceKind.TEST_RESULT,
            argv=(sys.executable, "-c", "raise SystemExit(1)"),
        ),
    )
    results = run_wave12_quality_gates(
        root=root,
        head_sha=REVISION,
        generated_at=FIXED_TIME,
        output_dir=root / "quality",
        specs=specs,
    )
    assert not quality_gates_passed(results)


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".blackfox-workspace").write_text("\n", encoding="utf-8")
    return root
