from __future__ import annotations

from ix_blackfox.assurance.models import (
    AssuranceControl,
    AssuranceEvidenceKind,
    AssuranceProfile,
    EvidenceVerificationState,
)

DEFAULT_WAVE12_PROFILE_ID = "ix-blackfox-wave12-core"
DEFAULT_WAVE12_PROFILE_VERSION = "1.0.0"


def default_wave12_assurance_profile() -> AssuranceProfile:
    """Build the bounded Wave 12 evidence-readiness profile.

    External-framework entries are evidence crosswalks. They do not assert that
    the package is conformant with, validated by, or approved under those
    frameworks.
    """

    return AssuranceProfile(
        profile_id=DEFAULT_WAVE12_PROFILE_ID,
        version=DEFAULT_WAVE12_PROFILE_VERSION,
        title="IX-BlackFox Wave 12 certification-ready evidence profile",
        description=(
            "A fail-closed profile for packaging quality, policy, isolation, "
            "repository, provenance, agent-identity, and human-review evidence "
            "for independent external assessment."
        ),
        claim_boundary=(
            "A satisfied profile means the declared evidence package is complete, "
            "content-addressed, internally coherent, and ready to be assessed by "
            "a separate authority. It does not mean certification or compliance."
        ),
        controls=(
            AssuranceControl(
                control_id="bf-w12-001-quality-gates",
                framework="IX-BlackFox Wave 12",
                reference_id="BF-W12-001",
                title="Executable quality-gate evidence",
                evidence_kinds=(
                    AssuranceEvidenceKind.TEST_RESULT,
                    AssuranceEvidenceKind.STATIC_ANALYSIS,
                    AssuranceEvidenceKind.TYPE_CHECK,
                ),
                statement=(
                    "Require separately inspectable test, static-analysis, and "
                    "strict type-check evidence for the bound revision."
                ),
                reference_uri=(
                    "https://github.com/BryceWDesign/IX-BlackFox/blob/main/"
                    "docs/wave12-certification-ready-evidence.md#quality-evidence"
                ),
            ),
            AssuranceControl(
                control_id="bf-w12-002-policy-evaluation",
                framework="IX-BlackFox Wave 12",
                reference_id="BF-W12-002",
                title="Policy and audit evaluation evidence",
                evidence_kinds=(AssuranceEvidenceKind.POLICY_EVALUATION,),
                statement=(
                    "Require a content-bound policy or audit evaluation that "
                    "preserves explicit non-claims and fail-closed findings."
                ),
                reference_uri=(
                    "https://github.com/BryceWDesign/IX-BlackFox/blob/main/"
                    "docs/wave12-certification-ready-evidence.md#policy-evidence"
                ),
            ),
            AssuranceControl(
                control_id="bf-w12-003-sandbox-boundary",
                framework="IX-BlackFox Wave 12",
                reference_id="BF-W12-003",
                title="Sandbox and execution-boundary evidence",
                evidence_kinds=(AssuranceEvidenceKind.SANDBOX_EVIDENCE,),
                statement=(
                    "Require evidence that bounded execution and deny-by-default "
                    "egress controls were evaluated for the packaged revision."
                ),
                reference_uri=(
                    "https://github.com/BryceWDesign/IX-BlackFox/blob/main/"
                    "docs/wave12-certification-ready-evidence.md#sandbox-evidence"
                ),
            ),
            AssuranceControl(
                control_id="bf-w12-004-repository-impact",
                framework="IX-BlackFox Wave 12",
                reference_id="BF-W12-004",
                title="Repository-impact evidence",
                evidence_kinds=(
                    AssuranceEvidenceKind.REPOSITORY_INTELLIGENCE,
                ),
                statement=(
                    "Require inspectable repository-boundary and change-impact "
                    "evidence rather than relying on a model description."
                ),
                reference_uri=(
                    "https://github.com/BryceWDesign/IX-BlackFox/blob/main/"
                    "docs/wave12-certification-ready-evidence.md#repository-evidence"
                ),
            ),
            AssuranceControl(
                control_id="bf-w12-005-identity-provenance-authority",
                framework="IX-BlackFox Wave 12",
                reference_id="BF-W12-005",
                title="Agent identity, provenance, and separate authority",
                evidence_kinds=(
                    AssuranceEvidenceKind.AGENT_IDENTITY,
                    AssuranceEvidenceKind.PROVENANCE,
                ),
                statement=(
                    "Bind package production and evidence provenance to explicit "
                    "actors while reserving final external-assessment approval for "
                    "a separately authenticated human authority."
                ),
                reference_uri=(
                    "https://github.com/BryceWDesign/IX-BlackFox/blob/main/"
                    "docs/wave12-certification-ready-evidence.md#authority-evidence"
                ),
                requires_human_review=True,
            ),
            AssuranceControl(
                control_id="nist-ssdf-ps-3-2-provenance-alignment",
                framework="NIST SP 800-218 SSDF 1.1",
                reference_id="PS.3.2",
                title="Software-release provenance alignment",
                evidence_kinds=(AssuranceEvidenceKind.PROVENANCE,),
                statement=(
                    "Map content-addressed BlackFox provenance evidence to the "
                    "SSDF practice of collecting, safeguarding, maintaining, and "
                    "sharing release provenance."
                ),
                reference_uri="https://csrc.nist.gov/pubs/sp/800/218/final",
                metadata={"mapping_only": True},
            ),
            AssuranceControl(
                control_id="nist-ai-rmf-govern-measure-alignment",
                framework="NIST AI RMF 1.0",
                reference_id="GOVERN and MEASURE",
                title="Governance and measurement evidence alignment",
                evidence_kinds=(
                    AssuranceEvidenceKind.POLICY_EVALUATION,
                    AssuranceEvidenceKind.TEST_RESULT,
                ),
                statement=(
                    "Map explicit authority, policy findings, and measurement "
                    "artifacts to AI RMF governance and measurement outcomes."
                ),
                reference_uri="https://airc.nist.gov/airmf-resources/airmf/",
                metadata={"mapping_only": True},
            ),
            AssuranceControl(
                control_id="oscal-assessment-results-alignment",
                framework="NIST OSCAL Assessment Results",
                reference_id="Assessment Results conceptual alignment",
                title="Assessment scope, activity, finding, and risk alignment",
                evidence_kinds=(AssuranceEvidenceKind.RISK_ASSESSMENT,),
                statement=(
                    "Allow optional risk-assessment evidence to be packaged in a "
                    "shape that can support a later, separately validated OSCAL "
                    "Assessment Results transformation."
                ),
                reference_uri=(
                    "https://pages.nist.gov/OSCAL/learn/concepts/layer/"
                    "assessment/assessment-results/"
                ),
                mandatory=False,
                metadata={
                    "mapping_only": True,
                    "not_an_oscal_assessment_results_document": True,
                },
            ),
            AssuranceControl(
                control_id="slsa-1-2-provenance-alignment",
                framework="SLSA 1.2",
                reference_id="Provenance and verification summary alignment",
                title="Supply-chain provenance alignment",
                evidence_kinds=(
                    AssuranceEvidenceKind.PROVENANCE,
                    AssuranceEvidenceKind.SUPPLY_CHAIN_ATTESTATION,
                ),
                statement=(
                    "Allow optional externally verified supply-chain attestations "
                    "to strengthen the package beyond local integrity evidence."
                ),
                reference_uri="https://slsa.dev/spec/v1.2/",
                minimum_verification=EvidenceVerificationState.EXTERNALLY_VERIFIED,
                mandatory=False,
                metadata={
                    "mapping_only": True,
                    "does_not_claim_a_slsa_level": True,
                },
            ),
        ),
        metadata={
            "wave": 12,
            "offline": True,
            "external_framework_entries_are_mappings_only": True,
        },
    )
