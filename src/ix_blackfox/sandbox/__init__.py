"""Wave 6 sandbox execution contracts and backends.

This package begins the Wave 6 boundary for IX-BlackFox. The contracts define
how hardened execution should be described, hashed, and validated before later
backends implement actual isolation. Local-audit profiles are compatibility
scaffolding only and must not be treated as a hardened sandbox backend.
"""

from __future__ import annotations

from ix_blackfox.sandbox.contracts import (
    SandboxBackendKind,
    SandboxCommandRequest,
    SandboxCommandResult,
    SandboxEnvironmentPolicy,
    SandboxExecutionStatus,
    SandboxFilesystemPolicy,
    SandboxMount,
    SandboxMountAccess,
    SandboxNetworkAllowRule,
    SandboxNetworkMode,
    SandboxNetworkPolicy,
    SandboxProfile,
    SandboxResourceLimits,
    default_wave6_local_audit_profile,
)
from ix_blackfox.sandbox.local_audit import (
    LocalAuditSandboxBackend,
    LocalAuditSandboxRun,
)
from ix_blackfox.sandbox.workspace import (
    SandboxArtifactManifest,
    SandboxArtifactRecord,
    SandboxWorkspace,
    SandboxWorkspaceManager,
)

__all__ = [
    "LocalAuditSandboxBackend",
    "LocalAuditSandboxRun",
    "SandboxArtifactManifest",
    "SandboxArtifactRecord",
    "SandboxBackendKind",
    "SandboxCommandRequest",
    "SandboxCommandResult",
    "SandboxEnvironmentPolicy",
    "SandboxExecutionStatus",
    "SandboxFilesystemPolicy",
    "SandboxMount",
    "SandboxMountAccess",
    "SandboxNetworkAllowRule",
    "SandboxNetworkMode",
    "SandboxNetworkPolicy",
    "SandboxProfile",
    "SandboxResourceLimits",
    "SandboxWorkspace",
    "SandboxWorkspaceManager",
    "default_wave6_local_audit_profile",
]
