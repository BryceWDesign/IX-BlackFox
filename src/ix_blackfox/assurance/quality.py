from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ix_blackfox.assurance.models import AssuranceEvidenceKind, digest_payload
from ix_blackfox.operating.models import normalize_identifier, normalize_text

WAVE12_QUALITY_GATE_SCHEMA_VERSION = "wave12.quality_gate_evidence.v1"


@dataclass(frozen=True, slots=True)
class QualityGateSpec:
    """Fixed argv quality gate captured as revision-bound JSON evidence."""

    gate_id: str
    title: str
    evidence_kind: AssuranceEvidenceKind
    argv: tuple[str, ...]
    timeout_seconds: int = 600

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "gate_id",
            normalize_identifier(self.gate_id, label="gate_id"),
        )
        object.__setattr__(self, "title", normalize_text(self.title, label="title"))
        if not self.argv or any(not argument for argument in self.argv):
            raise ValueError("QualityGateSpec argv must contain non-empty arguments.")
        if self.timeout_seconds <= 0:
            raise ValueError("QualityGateSpec timeout_seconds must be positive.")


@dataclass(frozen=True, slots=True)
class QualityGateResult:
    """Captured command outcome with a digest over its complete payload."""

    gate_id: str
    title: str
    evidence_kind: AssuranceEvidenceKind
    head_sha: str
    generated_at: str
    argv: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    @property
    def digest(self) -> str:
        return digest_payload(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": WAVE12_QUALITY_GATE_SCHEMA_VERSION,
            "gate_id": self.gate_id,
            "title": self.title,
            "evidence_kind": self.evidence_kind.value,
            "head_sha": self.head_sha,
            "generated_at": self.generated_at,
            "argv": list(self.argv),
            "exit_code": self.exit_code,
            "passed": self.passed,
            "timed_out": self.timed_out,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "metadata": dict(self.metadata),
            "scope_note": (
                "This record captures one local command outcome for the bound "
                "revision. It is not external certification or authorization."
            ),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


def default_wave12_quality_gates(
    *,
    python_executable: str | None = None,
) -> tuple[QualityGateSpec, ...]:
    python = python_executable or sys.executable
    return (
        QualityGateSpec(
            gate_id="wave12-pytest",
            title="Full pytest suite",
            evidence_kind=AssuranceEvidenceKind.TEST_RESULT,
            argv=(python, "-m", "pytest", "-q"),
        ),
        QualityGateSpec(
            gate_id="wave12-ruff",
            title="Ruff static analysis",
            evidence_kind=AssuranceEvidenceKind.STATIC_ANALYSIS,
            argv=(python, "-m", "ruff", "check", "."),
        ),
        QualityGateSpec(
            gate_id="wave12-mypy",
            title="Strict mypy type check",
            evidence_kind=AssuranceEvidenceKind.TYPE_CHECK,
            argv=(python, "-m", "mypy", "src"),
        ),
        QualityGateSpec(
            gate_id="wave12-compileall",
            title="Python compileall syntax check",
            evidence_kind=AssuranceEvidenceKind.STATIC_ANALYSIS,
            argv=(python, "-m", "compileall", "-q", "src", "scripts", "tests"),
        ),
    )


def run_quality_gate(
    *,
    root: Path,
    spec: QualityGateSpec,
    head_sha: str,
    generated_at: str,
    environment: Mapping[str, str] | None = None,
) -> QualityGateResult:
    """Run one fixed argv command without a shell and capture complete output."""

    resolved_root = root.resolve(strict=True)
    if not (resolved_root / ".blackfox-workspace").is_file():
        raise ValueError("Quality-gate root must contain .blackfox-workspace.")
    env = os.environ.copy()
    env.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "PYTHONUNBUFFERED": "1",
        }
    )
    if environment:
        env.update(dict(environment))

    try:
        completed = subprocess.run(
            spec.argv,
            cwd=resolved_root,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=spec.timeout_seconds,
            check=False,
        )
        return QualityGateResult(
            gate_id=spec.gate_id,
            title=spec.title,
            evidence_kind=spec.evidence_kind,
            head_sha=head_sha,
            generated_at=generated_at,
            argv=spec.argv,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            metadata={"shell": False, "cwd": "."},
        )
    except subprocess.TimeoutExpired as exc:
        return QualityGateResult(
            gate_id=spec.gate_id,
            title=spec.title,
            evidence_kind=spec.evidence_kind,
            head_sha=head_sha,
            generated_at=generated_at,
            argv=spec.argv,
            exit_code=124,
            stdout=_timeout_text(exc.stdout),
            stderr=_timeout_text(exc.stderr),
            timed_out=True,
            metadata={"shell": False, "cwd": "."},
        )


def run_wave12_quality_gates(
    *,
    root: Path,
    head_sha: str,
    generated_at: str,
    output_dir: Path,
    specs: Sequence[QualityGateSpec] | None = None,
) -> tuple[tuple[QualityGateResult, Path], ...]:
    """Run every Wave 12 quality gate and write revision-bound JSON evidence."""

    selected_specs = tuple(specs or default_wave12_quality_gates())
    if not selected_specs:
        raise ValueError("At least one quality gate is required.")
    output_dir.mkdir(parents=True, exist_ok=True)
    results: list[tuple[QualityGateResult, Path]] = []
    for spec in selected_specs:
        result = run_quality_gate(
            root=root,
            spec=spec,
            head_sha=head_sha,
            generated_at=generated_at,
        )
        path = output_dir / f"{spec.gate_id}.json"
        if path.is_symlink():
            raise ValueError("Quality-gate evidence output must not be a symlink.")
        path.write_text(
            json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        results.append((result, path))
    return tuple(results)


def quality_gates_passed(
    results: Sequence[tuple[QualityGateResult, Path]],
) -> bool:
    return bool(results) and all(result.passed for result, _ in results)


def _timeout_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
