from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Self

from ix_blackfox.runtime.operator_summary import (
    OperatorSummaryDocument,
    OperatorSummaryRenderer,
)
from ix_blackfox.runtime.programming_repair import (
    ProgrammingRepairRunReport,
    ProgrammingRepairRuntime,
)
from ix_blackfox.runtime.repair_receipts import RepairLoopReceiptLedger
from ix_blackfox.runtime.run_bundle import (
    RunBundleArtifact,
    RunBundleArtifactKind,
    RunBundleLayout,
    RunBundleManifest,
    RunBundleWriter,
)
from ix_blackfox.runtime.verification_summary import (
    VerificationSummary,
    VerificationSummaryRenderer,
)
from ix_blackfox.tools import (
    PatchApplyTool,
    PatchDiff,
    TestRunnerTool,
    ToolArtifactStore,
    ToolInvocationReceiptLedger,
    ToolPathPolicy,
    ToolPolicyDocument,
)


@dataclass(frozen=True, slots=True)
class EngineeringControlPlaneConfig:
    """
    Configuration for the Wave 2 governed engineering control plane.

    This config turns a repository workspace plus ``blackfox.policy.toml`` into
    a controlled local engineering runtime:
    - reserved workspace marker
    - policy-derived path boundaries
    - bounded repair loop attempts
    - governed patch application
    - governed test execution
    - operator summary
    - verification summary
    - run bundle manifest
    """

    workspace_root: Path
    artifact_root: Path
    policy_document: ToolPolicyDocument = field(default_factory=ToolPolicyDocument)
    require_workspace_marker: bool = True
    workspace_marker_name: str = ".blackfox-workspace"
    test_command: tuple[str, ...] | None = None
    test_working_directory: str = "."
    test_timeout_seconds: float = 60.0
    allowed_test_executables: tuple[str, ...] = (
        "python",
        "python3",
        "py",
        "pytest",
    )
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "workspace_root",
            self.workspace_root.expanduser().resolve(),
        )
        object.__setattr__(
            self,
            "artifact_root",
            self.artifact_root.expanduser().resolve(),
        )
        object.__setattr__(
            self,
            "test_command",
            tuple(self.test_command) if self.test_command is not None else None,
        )
        object.__setattr__(
            self,
            "allowed_test_executables",
            _normalize_string_tuple(
                self.allowed_test_executables,
                field_name="allowed_test_executables",
            ),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

        if not self.workspace_marker_name.strip():
            raise ValueError("workspace_marker_name must not be empty.")
        if self.test_timeout_seconds <= 0:
            raise ValueError("test_timeout_seconds must be positive.")

    @classmethod
    def from_workspace(
        cls,
        *,
        workspace_root: Path,
        policy_path: Path | None = None,
        artifact_root: Path | None = None,
        require_workspace_marker: bool = True,
        workspace_marker_name: str = ".blackfox-workspace",
        test_command: tuple[str, ...] | None = None,
        test_working_directory: str = ".",
        test_timeout_seconds: float = 60.0,
        allowed_test_executables: tuple[str, ...] = (
            "python",
            "python3",
            "py",
            "pytest",
        ),
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        workspace = workspace_root.expanduser().resolve()
        policy_document = (
            ToolPolicyDocument.from_path(policy_path)
            if policy_path is not None
            else _load_policy_from_workspace(workspace)
        )

        return cls(
            workspace_root=workspace,
            artifact_root=artifact_root or workspace,
            policy_document=policy_document,
            require_workspace_marker=require_workspace_marker,
            workspace_marker_name=workspace_marker_name,
            test_command=test_command,
            test_working_directory=test_working_directory,
            test_timeout_seconds=test_timeout_seconds,
            allowed_test_executables=allowed_test_executables,
            metadata=dict(metadata or {}),
        )

    @property
    def tool_path_policy(self) -> ToolPathPolicy:
        return self.policy_document.to_tool_path_policy()

    @property
    def repair_artifact_root(self) -> Path:
        return self.artifact_root / "artifacts" / "tools"

    def to_dict(self) -> dict[str, Any]:
        return {
            "workspace_root": str(self.workspace_root),
            "artifact_root": str(self.artifact_root),
            "policy_document": self.policy_document.to_dict(),
            "require_workspace_marker": self.require_workspace_marker,
            "workspace_marker_name": self.workspace_marker_name,
            "test_command": list(self.test_command) if self.test_command is not None else None,
            "test_working_directory": self.test_working_directory,
            "test_timeout_seconds": self.test_timeout_seconds,
            "allowed_test_executables": list(self.allowed_test_executables),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class EngineeringControlPlaneReport:
    """
    End-to-end report produced by the governed engineering control plane.
    """

    run_id: str
    task_id: str
    programming_repair_report: ProgrammingRepairRunReport
    operator_summary: OperatorSummaryDocument
    verification_summary: VerificationSummary
    run_bundle_manifest: RunBundleManifest
    run_bundle_manifest_artifact: RunBundleArtifact
    tool_receipt_count: int
    repair_receipt_count: int
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "run_id", _normalize_identifier(self.run_id, label="run_id"))
        object.__setattr__(self, "task_id", _normalize_identifier(self.task_id, label="task_id"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def succeeded(self) -> bool:
        return self.programming_repair_report.succeeded

    @property
    def verification_status(self) -> str:
        return self.verification_summary.status.value

    @property
    def bundle_root(self) -> str:
        return self.run_bundle_manifest.root_path

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "task_id": self.task_id,
            "succeeded": self.succeeded,
            "verification_status": self.verification_status,
            "programming_repair_report": self.programming_repair_report.to_dict(),
            "operator_summary": self.operator_summary.to_dict(),
            "verification_summary": self.verification_summary.to_dict(),
            "run_bundle_manifest": self.run_bundle_manifest.to_dict(),
            "run_bundle_manifest_artifact": self.run_bundle_manifest_artifact.to_dict(),
            "tool_receipt_count": self.tool_receipt_count,
            "repair_receipt_count": self.repair_receipt_count,
            "bundle_root": self.bundle_root,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class EngineeringControlPlane:
    """
    Wave 2 governed AI engineering control plane.

    This class is the highest-level local orchestration object added in Wave 2.
    It does not pretend to be a magic autonomous agent. It coordinates bounded,
    auditable engineering actions:
    - apply supplied patch candidates
    - run allowlisted tests
    - parse test output
    - record tool and repair receipts
    - generate operator and verification summaries
    - write a reviewable run bundle
    """

    config: EngineeringControlPlaneConfig
    tool_receipt_ledger: ToolInvocationReceiptLedger = field(
        default_factory=ToolInvocationReceiptLedger
    )
    repair_receipt_ledger: RepairLoopReceiptLedger = field(
        default_factory=RepairLoopReceiptLedger
    )
    operator_summary_renderer: OperatorSummaryRenderer = field(
        default_factory=OperatorSummaryRenderer
    )
    verification_summary_renderer: VerificationSummaryRenderer = field(
        default_factory=VerificationSummaryRenderer
    )

    @classmethod
    def from_workspace(
        cls,
        *,
        workspace_root: Path,
        policy_path: Path | None = None,
        artifact_root: Path | None = None,
        require_workspace_marker: bool = True,
        workspace_marker_name: str = ".blackfox-workspace",
        test_command: tuple[str, ...] | None = None,
        test_working_directory: str = ".",
        test_timeout_seconds: float = 60.0,
        allowed_test_executables: tuple[str, ...] = (
            "python",
            "python3",
            "py",
            "pytest",
        ),
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            config=EngineeringControlPlaneConfig.from_workspace(
                workspace_root=workspace_root,
                policy_path=policy_path,
                artifact_root=artifact_root,
                require_workspace_marker=require_workspace_marker,
                workspace_marker_name=workspace_marker_name,
                test_command=test_command,
                test_working_directory=test_working_directory,
                test_timeout_seconds=test_timeout_seconds,
                allowed_test_executables=allowed_test_executables,
                metadata=dict(metadata or {}),
            )
        )

    def run_programming_repair(
        self,
        *,
        task_id: str,
        run_id: str,
        objective: str,
        candidate_patches: Iterable[PatchDiff],
        test_command: tuple[str, ...] | None = None,
        test_working_directory: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> EngineeringControlPlaneReport:
        """
        Execute a bounded programming repair run and package the evidence.
        """
        self._validate_workspace()
        candidate_patch_tuple = tuple(candidate_patches)

        artifact_store = ToolArtifactStore(self.config.repair_artifact_root)
        path_policy = self.config.tool_path_policy

        patch_tool = PatchApplyTool(
            workspace_root=self.config.workspace_root,
            path_policy=path_policy,
            require_workspace_marker=self.config.require_workspace_marker,
            workspace_marker_name=self.config.workspace_marker_name,
            artifact_store=artifact_store,
            receipt_ledger=self.tool_receipt_ledger,
        )
        test_runner = TestRunnerTool(
            workspace_root=self.config.workspace_root,
            path_policy=path_policy,
            require_workspace_marker=self.config.require_workspace_marker,
            workspace_marker_name=self.config.workspace_marker_name,
            default_command=test_command
            or self.config.test_command
            or ("python", "-m", "pytest", "-q"),
            allowed_executables=self.config.allowed_test_executables,
            timeout_seconds=self.config.test_timeout_seconds,
            artifact_store=artifact_store,
            receipt_ledger=self.tool_receipt_ledger,
        )
        repair_runtime = ProgrammingRepairRuntime(
            patch_tool=patch_tool,
            test_runner=test_runner,
            config=self.config.policy_document.to_repair_loop_config(),
            repair_receipt_ledger=self.repair_receipt_ledger,
        )

        programming_report = repair_runtime.run(
            task_id=task_id,
            run_id=run_id,
            objective=objective,
            candidate_patches=candidate_patch_tuple,
            test_command=test_command or self.config.test_command,
            test_working_directory=(
                test_working_directory or self.config.test_working_directory
            ),
            metadata={
                "control_plane": "engineering",
                "candidate_patch_count": len(candidate_patch_tuple),
                **dict(metadata or {}),
            },
        )
        operator_summary = self.operator_summary_renderer.render_programming_repair_report(
            report=programming_report
        )
        verification_summary = (
            self.verification_summary_renderer.from_programming_repair_report(
                programming_report
            )
        )

        bundle_writer = RunBundleWriter(
            layout=RunBundleLayout(
                root_dir=self.config.artifact_root,
                run_id=run_id,
            ),
            task_id=task_id,
            metadata={
                "control_plane": "engineering",
                "workspace_root": str(self.config.workspace_root),
                "policy": self.config.policy_document.to_dict(),
                **dict(self.config.metadata),
                **dict(metadata or {}),
            },
        )
        self._write_run_bundle(
            bundle_writer=bundle_writer,
            programming_report=programming_report,
            operator_summary=operator_summary,
            verification_summary=verification_summary,
        )
        manifest_artifact = bundle_writer.persist_manifest()

        return EngineeringControlPlaneReport(
            run_id=run_id,
            task_id=task_id,
            programming_repair_report=programming_report,
            operator_summary=operator_summary,
            verification_summary=verification_summary,
            run_bundle_manifest=bundle_writer.manifest,
            run_bundle_manifest_artifact=manifest_artifact,
            tool_receipt_count=self.tool_receipt_ledger.count(),
            repair_receipt_count=self.repair_receipt_ledger.count(),
            metadata={
                "control_plane": "engineering",
                "candidate_patch_count": len(candidate_patch_tuple),
                "workspace_root": str(self.config.workspace_root),
                "artifact_root": str(self.config.artifact_root),
                **dict(metadata or {}),
            },
        )

    def _validate_workspace(self) -> None:
        root = self.config.workspace_root

        if not root.exists():
            raise FileNotFoundError(f"Engineering workspace does not exist: {root}")
        if not root.is_dir():
            raise NotADirectoryError(f"Engineering workspace is not a directory: {root}")

        if self.config.require_workspace_marker:
            marker_path = root / self.config.workspace_marker_name
            if not marker_path.is_file():
                raise FileNotFoundError(
                    "Engineering control plane requires a reserved workspace marker: "
                    f"{marker_path}"
                )

    def _write_run_bundle(
        self,
        *,
        bundle_writer: RunBundleWriter,
        programming_report: ProgrammingRepairRunReport,
        operator_summary: OperatorSummaryDocument,
        verification_summary: VerificationSummary,
    ) -> None:
        tool_receipts = self.tool_receipt_ledger.snapshot().to_dict()
        repair_receipts = self.repair_receipt_ledger.snapshot().to_dict()

        bundle_writer.write_json(
            kind=RunBundleArtifactKind.RUN_REPORT,
            filename="programming-repair-report.json",
            payload=programming_report.to_dict(),
            metadata={"artifact_kind": "programming_repair_report"},
        )
        bundle_writer.write_text(
            kind=RunBundleArtifactKind.OPERATOR_SUMMARY,
            filename="operator-summary.md",
            text=operator_summary.to_markdown(),
            media_type="text/markdown",
            metadata={"artifact_kind": "operator_summary"},
        )
        bundle_writer.write_json(
            kind=RunBundleArtifactKind.VERIFICATION_SUMMARY,
            filename="verification-summary.json",
            payload=verification_summary.to_dict(),
            metadata={
                "artifact_kind": "verification_summary",
                "verification_status": verification_summary.status.value,
                "verification_digest": verification_summary.digest,
            },
        )
        bundle_writer.write_json(
            kind=RunBundleArtifactKind.TOOL_RECEIPTS,
            filename="tool-receipts.json",
            payload=tool_receipts,
            metadata={
                "artifact_kind": "tool_receipts",
                "receipt_count": tool_receipts["receipt_count"],
            },
        )
        bundle_writer.write_json(
            kind=RunBundleArtifactKind.REPAIR_RECEIPTS,
            filename="repair-receipts.json",
            payload=repair_receipts,
            metadata={
                "artifact_kind": "repair_receipts",
                "receipt_count": repair_receipts["receipt_count"],
            },
        )
        bundle_writer.write_json(
            kind=RunBundleArtifactKind.TRACE,
            filename="control-plane-trace.json",
            payload={
                "run_id": programming_report.loop_state.run_id,
                "task_id": programming_report.loop_state.task_id,
                "loop_id": programming_report.loop_state.loop_id,
                "status": programming_report.loop_state.status.value,
                "terminal_reason": programming_report.terminal_reason,
                "attempts_used": programming_report.attempts_used,
                "attempts_remaining": programming_report.attempts_remaining,
                "patch_result_count": len(programming_report.patch_results),
                "test_result_count": len(programming_report.test_results),
                "parsed_test_run_count": len(programming_report.parsed_test_runs),
                "tool_receipt_count": tool_receipts["receipt_count"],
                "repair_receipt_count": repair_receipts["receipt_count"],
            },
            metadata={"artifact_kind": "control_plane_trace"},
        )


def _load_policy_from_workspace(workspace: Path) -> ToolPolicyDocument:
    policy_path = workspace / "blackfox.policy.toml"
    if policy_path.is_file():
        return ToolPolicyDocument.from_path(policy_path)
    return ToolPolicyDocument()


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_string_tuple(
    values: Iterable[str],
    *,
    field_name: str,
) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = value.strip()
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    if not normalized:
        raise ValueError(f"{field_name} must contain at least one value.")

    return tuple(normalized)
