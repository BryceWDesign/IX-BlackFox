from __future__ import annotations

from pathlib import Path


def test_wave9_compliance_audit_docs_exist() -> None:
    path = _doc_path()

    assert path.exists()
    assert path.name == "wave9-compliance-audit-attestation.md"


def test_wave9_compliance_audit_docs_cover_implemented_pipeline() -> None:
    text = _doc_text()

    required_terms = [
        "policy pack",
        "evidence manifest",
        "control evaluation",
        "reviewer signoff validation",
        "deterministic governance report",
        "human-authority gate",
        "Wave 5 PR evidence-pack bridge",
        "Wave 6 sandbox evidence bridge",
        "Wave 7 model-repair evidence bridge",
        "Wave 8 repository-intelligence evidence bridge",
    ]

    for term in required_terms:
        assert term in text


def test_wave9_compliance_audit_docs_include_commands_and_artifacts() -> None:
    text = _doc_text()

    assert "blackfox audit report" in text
    assert "blackfox audit validate" in text
    assert "blackfox audit gate" in text
    assert "python scripts/run_wave9_compliance_audit_ci.py --head-sha local" in text
    assert ".github/workflows/wave9-compliance-audit.yml" in text
    assert ".blackfox-artifacts/wave9/wave9-compliance-audit-report.json" in text
    assert ".blackfox-artifacts/wave9/wave9-ci-engine-evidence.json" in text
    assert ".blackfox-artifacts/wave9/wave9-compliance-audit-ci-summary.json" in text


def test_wave9_compliance_audit_docs_include_schema_versions_and_controls() -> None:
    text = _doc_text()

    assert "wave9.evidence_manifest.v1" in text
    assert "wave9.compliance_audit_attestation.v1" in text
    for index in range(1, 16):
        assert f"BF-W9-{index:03d}" in text


def test_wave9_compliance_audit_docs_preserve_human_authority_boundary() -> None:
    text = _doc_text()

    assert "AI proposes. Humans decide." in text
    assert "model output as untrusted input" in text
    assert "model self-approval" in text
    assert "Model and system signoffs are allowed as advisory records" in text
    assert "They do not satisfy human authority" in text


def test_wave9_compliance_audit_docs_explain_expected_blocked_ci_report() -> None:
    text = _doc_text()

    assert "The default GitHub Actions workflow intentionally expects a `blocked` disposition." in text
    assert "CI must not fabricate a human reviewer" in text
    assert "valid blocked report" in text


def test_wave9_compliance_audit_docs_preserve_non_claims() -> None:
    text = _doc_text()

    non_claims = [
        "does not certify correctness",
        "does not replace human review",
        "does not mean the repository is production-ready",
        "does not mean the code is formally verified",
        "does not mean the code is certified",
        "does not mean the code is approved by any government or defense organization",
        "does not grant ATO, cATO, procurement approval, deployment authority, operational authority, or release authority",
        "does not prove DoD endorsement, affiliation, acceptance, or certification",
        "does not make AI coding autonomous",
        "does not authorize autonomous code changes or autonomous release decisions",
        "does not treat model confidence as evidence",
        "does not allow model or system self-approval to satisfy human authority",
        "does not treat recorded provenance metadata as verified provenance unless verification evidence is actually present",
    ]

    for non_claim in non_claims:
        assert non_claim in text


def test_wave9_compliance_audit_docs_explicitly_label_overclaim_examples_as_avoid_language() -> None:
    text = _doc_text()

    assert "Avoid wording like:" in text
    assert "Wave 9 makes IX-BlackFox compliant." in text
    assert "Wave 9 makes the repo DoD-ready." in text
    assert "Wave 9 proves patches are safe." in text
    assert "Wave 9 provides ATO or cATO evidence automatically." in text
    assert "Wave 9 lets AI approve code changes." in text
    assert "Wave 9 verifies Sigstore/SLSA provenance by default." in text
    assert "The correct positioning is:" in text
    assert (
        "Wave 9 makes AI-assisted code-change governance more auditable by "
        "binding policy packs, evidence manifests, control results, reviewer signoff, "
        "non-claims, and deterministic governance reports into one inspectable "
        "audit-attestation layer."
    ) in text


def _doc_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "docs"
        / "wave9-compliance-audit-attestation.md"
    )


def _doc_text() -> str:
    return _doc_path().read_text(encoding="utf-8")
