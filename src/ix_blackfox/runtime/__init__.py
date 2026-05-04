"""
End-to-end runtime orchestration for IX-BlackFox.

The runtime package exposes a stable public import surface without eagerly
importing every runtime subsystem at package import time. Keeping this module
lazy prevents unrelated runtime modules from forming circular imports during
pytest collection and ordinary package loading.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_ALIAS_ATTRS = {
    "control_plane_cli_main": "main",
    "runtime_doctor_main": "main",
    "wave3_cli_main": "main",
}

_EXPORTS: dict[str, str] = {
    "AuthoredEngineeringControlPlaneReport": "ix_blackfox.runtime.control_plane",
    "AuthoredRepairRunReport": "ix_blackfox.runtime.authoring_repair",
    "AuthoredRepairRuntime": "ix_blackfox.runtime.authoring_repair",
    "AuthoredRepairRuntimeConfig": "ix_blackfox.runtime.authoring_repair",
    "AuthoredRepairStatus": "ix_blackfox.runtime.authoring_repair",
    "BlackFoxRuntime": "ix_blackfox.runtime.orchestrator",
    "ControlPlaneCliError": "ix_blackfox.runtime.control_plane_cli",
    "ControlPlaneCliResult": "ix_blackfox.runtime.control_plane_cli",
    "DeterministicTaskClassifier": "ix_blackfox.runtime.inference",
    "EngineeringControlPlane": "ix_blackfox.runtime.control_plane",
    "EngineeringControlPlaneConfig": "ix_blackfox.runtime.control_plane",
    "EngineeringControlPlaneReport": "ix_blackfox.runtime.control_plane",
    "EscalatedReasoningOutcome": "ix_blackfox.runtime.reasoning",
    "EscalatedReasoningPlan": "ix_blackfox.runtime.reasoning",
    "EscalatedReasoningRuntime": "ix_blackfox.runtime.reasoning",
    "NullPatchProposalProvider": "ix_blackfox.runtime.authoring_repair",
    "OperatorSummaryDocument": "ix_blackfox.runtime.operator_summary",
    "OperatorSummaryFinding": "ix_blackfox.runtime.operator_summary",
    "OperatorSummaryFindingSeverity": "ix_blackfox.runtime.operator_summary",
    "OperatorSummaryRenderer": "ix_blackfox.runtime.operator_summary",
    "OperatorSummarySection": "ix_blackfox.runtime.operator_summary",
    "PatchProposalProvider": "ix_blackfox.runtime.authoring_repair",
    "PolicyReasoningOutcome": "ix_blackfox.runtime.policy_reasoning",
    "PolicyReasoningPlan": "ix_blackfox.runtime.policy_reasoning",
    "PolicyReasoningRuntime": "ix_blackfox.runtime.policy_reasoning",
    "PrimaryBrainOutcome": "ix_blackfox.runtime.inference",
    "PrimaryBrainPlan": "ix_blackfox.runtime.inference",
    "PrimaryBrainRuntime": "ix_blackfox.runtime.inference",
    "ProgrammingRepairRunReport": "ix_blackfox.runtime.programming_repair",
    "ProgrammingRepairRuntime": "ix_blackfox.runtime.programming_repair",
    "RepairLoopAttempt": "ix_blackfox.runtime.repair_loop",
    "RepairLoopAttemptStatus": "ix_blackfox.runtime.repair_loop",
    "RepairLoopConfig": "ix_blackfox.runtime.repair_loop",
    "RepairLoopFinding": "ix_blackfox.runtime.repair_loop",
    "RepairLoopFindingSeverity": "ix_blackfox.runtime.repair_loop",
    "RepairLoopReceipt": "ix_blackfox.runtime.repair_receipts",
    "RepairLoopReceiptEventType": "ix_blackfox.runtime.repair_receipts",
    "RepairLoopReceiptLedger": "ix_blackfox.runtime.repair_receipts",
    "RepairLoopReceiptSnapshot": "ix_blackfox.runtime.repair_receipts",
    "RepairLoopState": "ix_blackfox.runtime.repair_loop",
    "RepairLoopStatus": "ix_blackfox.runtime.repair_loop",
    "RepairLoopTerminalReason": "ix_blackfox.runtime.repair_loop",
    "ReplayObservation": "ix_blackfox.runtime.replay",
    "RunBundleArtifact": "ix_blackfox.runtime.run_bundle",
    "RunBundleArtifactKind": "ix_blackfox.runtime.run_bundle",
    "RunBundleExportFormat": "ix_blackfox.runtime.run_bundle_export",
    "RunBundleExportRequest": "ix_blackfox.runtime.run_bundle_export",
    "RunBundleExportResult": "ix_blackfox.runtime.run_bundle_export",
    "RunBundleExporter": "ix_blackfox.runtime.run_bundle_export",
    "RunBundleLayout": "ix_blackfox.runtime.run_bundle",
    "RunBundleManifest": "ix_blackfox.runtime.run_bundle",
    "RunBundleWriter": "ix_blackfox.runtime.run_bundle",
    "RuntimeApprovalResolution": "ix_blackfox.runtime.approval",
    "RuntimeApprovalResolver": "ix_blackfox.runtime.approval",
    "RuntimeDoctor": "ix_blackfox.runtime.doctor",
    "RuntimeDoctorReport": "ix_blackfox.runtime.doctor",
    "RuntimeGovernancePreflightEngine": "ix_blackfox.runtime.governance",
    "RuntimeGovernancePreflightResult": "ix_blackfox.runtime.governance",
    "RuntimeGovernanceReceiptRecorder": "ix_blackfox.runtime.receipts",
    "RuntimeGovernanceReceiptReport": "ix_blackfox.runtime.receipts",
    "RuntimeLaneReadiness": "ix_blackfox.runtime.readiness",
    "RuntimeReadinessInspector": "ix_blackfox.runtime.readiness",
    "RuntimeReadinessReport": "ix_blackfox.runtime.readiness",
    "RuntimeReadinessStatus": "ix_blackfox.runtime.readiness",
    "RuntimeRunReport": "ix_blackfox.runtime.orchestrator",
    "RuntimeRunStatus": "ix_blackfox.runtime.orchestrator",
    "SafeguardOutcome": "ix_blackfox.runtime.safeguard",
    "SafeguardPlan": "ix_blackfox.runtime.safeguard",
    "SafeguardRuntime": "ix_blackfox.runtime.safeguard",
    "StaticPatchProposalProvider": "ix_blackfox.runtime.authoring_repair",
    "TaskInference": "ix_blackfox.runtime.inference",
    "TaskInferenceReason": "ix_blackfox.runtime.inference",
    "TaskReplayGuard": "ix_blackfox.runtime.replay",
    "VerificationEvidence": "ix_blackfox.runtime.verification_summary",
    "VerificationEvidenceKind": "ix_blackfox.runtime.verification_summary",
    "VerificationFinding": "ix_blackfox.runtime.verification_summary",
    "VerificationFindingSeverity": "ix_blackfox.runtime.verification_summary",
    "VerificationSummary": "ix_blackfox.runtime.verification_summary",
    "VerificationSummaryRenderer": "ix_blackfox.runtime.verification_summary",
    "VerificationSummaryStatus": "ix_blackfox.runtime.verification_summary",
    "VisionOutcome": "ix_blackfox.runtime.vision",
    "VisionPlan": "ix_blackfox.runtime.vision",
    "VisionRuntime": "ix_blackfox.runtime.vision",
    "Wave2AcceptanceFinding": "ix_blackfox.runtime.acceptance",
    "Wave2AcceptanceFindingSeverity": "ix_blackfox.runtime.acceptance",
    "Wave2AcceptanceReport": "ix_blackfox.runtime.acceptance",
    "Wave2AcceptanceStatus": "ix_blackfox.runtime.acceptance",
    "Wave2AcceptanceValidator": "ix_blackfox.runtime.acceptance",
    "Wave3AcceptanceFinding": "ix_blackfox.runtime.wave3_acceptance",
    "Wave3AcceptanceFindingCode": "ix_blackfox.runtime.wave3_acceptance",
    "Wave3AcceptanceFindingSeverity": "ix_blackfox.runtime.wave3_acceptance",
    "Wave3AcceptanceReport": "ix_blackfox.runtime.wave3_acceptance",
    "Wave3AcceptanceStatus": "ix_blackfox.runtime.wave3_acceptance",
    "Wave3AcceptanceValidator": "ix_blackfox.runtime.wave3_acceptance",
    "Wave3AcceptanceValidatorConfig": "ix_blackfox.runtime.wave3_acceptance",
    "Wave3CliError": "ix_blackfox.runtime.wave3_cli",
    "Wave3CliRequest": "ix_blackfox.runtime.wave3_cli",
    "Wave3CliResult": "ix_blackfox.runtime.wave3_cli",
    "Wave3EvidenceArtifact": "ix_blackfox.runtime.wave3_bundle",
    "Wave3EvidenceArtifactKind": "ix_blackfox.runtime.wave3_bundle",
    "Wave3EvidencePackageManifest": "ix_blackfox.runtime.wave3_bundle",
    "Wave3EvidencePackageWriter": "ix_blackfox.runtime.wave3_bundle",
    "Wave3EvidencePackageWriterConfig": "ix_blackfox.runtime.wave3_bundle",
    "build_wave3_cli_parser": "ix_blackfox.runtime.wave3_cli",
    "control_plane_cli_main": "ix_blackfox.runtime.control_plane_cli",
    "fingerprint_task_request": "ix_blackfox.runtime.replay",
    "run_control_plane_cli": "ix_blackfox.runtime.control_plane_cli",
    "run_wave3_cli": "ix_blackfox.runtime.wave3_cli",
    "run_wave3_cli_request": "ix_blackfox.runtime.wave3_cli",
    "runtime_doctor_main": "ix_blackfox.runtime.doctor",
    "wave3_cli_main": "ix_blackfox.runtime.wave3_cli",
}

__all__ = tuple(_EXPORTS)


def __getattr__(name: str) -> Any:
    try:
        module_name = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc

    module = import_module(module_name)
    attr_name = _ALIAS_ATTRS.get(name, name)
    if name == "build_wave3_cli_parser":
        attr_name = "build_parser"
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted((*globals(), *_EXPORTS))
