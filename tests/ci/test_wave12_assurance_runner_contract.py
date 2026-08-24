from __future__ import annotations

from pathlib import Path


def test_wave12_runner_has_no_partial_campaign_switches() -> None:
    text = _runner_text()
    assert "--skip-prerequisites" not in text
    assert "--skip-quality-gates" not in text
    assert "run_prerequisites" not in text
    assert "run_quality=" not in text


def test_wave12_runner_regenerates_all_available_prerequisite_evidence() -> None:
    text = _runner_text()
    for script in (
        "scripts/run_wave6_sandbox_ci.py",
        "scripts/run_wave7_model_repair_ci.py",
        "scripts/run_wave8_repository_intelligence_ci.py",
        "scripts/run_wave9_compliance_audit_ci.py",
        "scripts/run_wave11_agent_identity_ci.py",
    ):
        assert script in text
    assert '"blocked"' in text
    assert '"warning"' in text


def test_wave12_runner_always_executes_and_requires_quality_gates() -> None:
    text = _runner_text()
    assert "run_wave12_quality_gates(" in text
    assert "if not quality_gates_passed(quality_results):" in text
    assert '"quality_gates_run": True' in text
    assert '"quality_gates_passed": quality_gates_passed(quality_results)' in text


def test_wave12_runner_builds_then_reopens_the_serialized_package() -> None:
    text = _runner_text()
    build_position = text.index("build_assurance_package(")
    verify_position = text.index("verify_assurance_package(")
    write_position = text.index("write_package_verification(")
    assert build_position < verify_position < write_position
    assert "verification.passed" in text
    assert "verification.readiness_status == expected_status.value" in text


def test_wave12_runner_declares_complete_change_impact_surface() -> None:
    text = _runner_text()
    for path in (
        ".github/workflows/wave12-assurance-evidence.yml",
        "README.md",
        "docs/wave12-certification-ready-evidence.md",
        "schemas",
        "scripts/run_wave12_assurance_ci.py",
        "src/ix_blackfox/assurance",
        "src/ix_blackfox/interface/cli.py",
        "tests/assurance",
        "tests/docs/test_wave12_assurance_docs.py",
    ):
        assert f'"{path}"' in text


def test_wave12_runner_uses_argv_subprocesses_without_shell_or_credentials() -> None:
    text = _runner_text()
    assert "subprocess.run(" in text
    assert "shell=True" not in text
    assert "OPENAI_API_KEY" not in text
    assert "ANTHROPIC_API_KEY" not in text
    assert "AWS_ACCESS_KEY" not in text
    assert "secrets." not in text


def _runner_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "run_wave12_assurance_ci.py"
    )


def _runner_text() -> str:
    return _runner_path().read_text(encoding="utf-8")
