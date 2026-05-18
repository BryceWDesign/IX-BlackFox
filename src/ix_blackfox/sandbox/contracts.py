from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from pathlib import PurePosixPath
from typing import Any

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/#-]*$")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HEX_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")


class SandboxBackendKind(StrEnum):
    LOCAL_AUDIT = auto()
    CONTAINER = auto()
    GVISOR = auto()
    FIRECRACKER = auto()


class SandboxNetworkMode(StrEnum):
    DENY_ALL = auto()
    ALLOWLIST = auto()
    PROXY_LOGGED = auto()
    OFFLINE_PACKAGE_CACHE = auto()


class SandboxMountAccess(StrEnum):
    READ_ONLY = auto()
    READ_WRITE = auto()


class SandboxExecutionStatus(StrEnum):
    CREATED = auto()
    RUNNING = auto()
    SUCCEEDED = auto()
    FAILED = auto()
    TIMED_OUT = auto()
    POLICY_BLOCKED = auto()
    BACKEND_UNAVAILABLE = auto()


@dataclass(frozen=True, slots=True)
class SandboxResourceLimits:
    timeout_seconds: int
    max_memory_mb: int
    max_processes: int
    max_output_bytes: int
    max_artifact_bytes: int
    cpu_count: int = 1

    def __post_init__(self) -> None:
        _require_positive_int(self.timeout_seconds, label="timeout_seconds")
        _require_positive_int(self.max_memory_mb, label="max_memory_mb")
        _require_positive_int(self.max_processes, label="max_processes")
        _require_positive_int(self.max_output_bytes, label="max_output_bytes")
        _require_positive_int(self.max_artifact_bytes, label="max_artifact_bytes")
        _require_positive_int(self.cpu_count, label="cpu_count")

    def to_dict(self) -> dict[str, int]:
        return {
            "timeout_seconds": self.timeout_seconds,
            "max_memory_mb": self.max_memory_mb,
            "max_processes": self.max_processes,
            "max_output_bytes": self.max_output_bytes,
            "max_artifact_bytes": self.max_artifact_bytes,
            "cpu_count": self.cpu_count,
        }


@dataclass(frozen=True, slots=True)
class SandboxEnvironmentPolicy:
    inherit_host_environment: bool = False
    allowed_variables: tuple[str, ...] = field(default_factory=tuple)
    injected_variables: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "allowed_variables",
            _normalize_env_names(self.allowed_variables, label="allowed_variables"),
        )
        object.__setattr__(
            self,
            "injected_variables",
            _normalize_env_mapping(self.injected_variables),
        )
        if self.inherit_host_environment and not self.allowed_variables:
            raise ValueError(
                "inherit_host_environment requires at least one allowed variable."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "inherit_host_environment": self.inherit_host_environment,
            "allowed_variables": list(self.allowed_variables),
            "injected_variables": dict(sorted(self.injected_variables.items())),
        }


@dataclass(frozen=True, slots=True)
class SandboxNetworkAllowRule:
    host: str
    port: int
    protocol: str = "tcp"
    reason: str = "required by approved sandbox profile"

    def __post_init__(self) -> None:
        object.__setattr__(self, "host", _normalize_host(self.host))
        _require_port(self.port)
        object.__setattr__(self, "protocol", _normalize_protocol(self.protocol))
        object.__setattr__(self, "reason", _normalize_text(self.reason, label="reason"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class SandboxNetworkPolicy:
    mode: SandboxNetworkMode = SandboxNetworkMode.DENY_ALL
    allowlist: tuple[SandboxNetworkAllowRule, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowlist", tuple(self.allowlist))
        if self.mode is SandboxNetworkMode.DENY_ALL and self.allowlist:
            raise ValueError("deny_all network policy cannot include allowlist rules.")
        if self.mode in (
            SandboxNetworkMode.ALLOWLIST,
            SandboxNetworkMode.PROXY_LOGGED,
        ) and not self.allowlist:
            raise ValueError(f"{self.mode.value} network policy requires allowlist rules.")
        seen = set()
        for rule in self.allowlist:
            key = (rule.protocol, rule.host, rule.port)
            if key in seen:
                raise ValueError("network allowlist rules must not contain duplicates.")
            seen.add(key)

    @property
    def blocks_all_egress(self) -> bool:
        return self.mode is SandboxNetworkMode.DENY_ALL and not self.allowlist

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "allowlist": [rule.to_dict() for rule in self.allowlist],
        }


@dataclass(frozen=True, slots=True)
class SandboxMount:
    source: str
    target: str
    access: SandboxMountAccess
    required: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", _normalize_relative_path(self.source, label="source"))
        object.__setattr__(self, "target", _normalize_absolute_posix_path(self.target, label="target"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "access": self.access.value,
            "required": self.required,
        }


@dataclass(frozen=True, slots=True)
class SandboxFilesystemPolicy:
    mounts: tuple[SandboxMount, ...]
    writable_paths: tuple[str, ...] = ("/workspace/out", "/workspace/tmp")
    read_only_root: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "mounts", tuple(self.mounts))
        object.__setattr__(
            self,
            "writable_paths",
            _normalize_absolute_paths(self.writable_paths, label="writable_paths"),
        )
        if not self.mounts:
            raise ValueError("filesystem policy requires at least one mount.")
        target_paths = tuple(mount.target for mount in self.mounts)
        if len(set(target_paths)) != len(target_paths):
            raise ValueError("filesystem mount targets must not contain duplicates.")
        for mount in self.mounts:
            if mount.access is SandboxMountAccess.READ_WRITE and mount.target not in self.writable_paths:
                raise ValueError(
                    "read-write mount targets must be listed in writable_paths."
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "mounts": [mount.to_dict() for mount in self.mounts],
            "writable_paths": list(self.writable_paths),
            "read_only_root": self.read_only_root,
        }


@dataclass(frozen=True, slots=True)
class SandboxProfile:
    profile_id: str
    backend: SandboxBackendKind
    filesystem: SandboxFilesystemPolicy
    resources: SandboxResourceLimits
    network: SandboxNetworkPolicy = field(default_factory=SandboxNetworkPolicy)
    environment: SandboxEnvironmentPolicy = field(default_factory=SandboxEnvironmentPolicy)
    allowed_commands: tuple[str, ...] = field(default_factory=tuple)
    denied_command_fragments: tuple[str, ...] = ("curl", "wget", "ssh", "scp")
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "profile_id", _normalize_id(self.profile_id, label="profile_id"))
        object.__setattr__(
            self,
            "allowed_commands",
            _normalize_command_tuple(self.allowed_commands, label="allowed_commands"),
        )
        object.__setattr__(
            self,
            "denied_command_fragments",
            _normalize_command_tuple(
                self.denied_command_fragments,
                label="denied_command_fragments",
            ),
        )
        object.__setattr__(self, "metadata", _normalize_str_mapping(self.metadata, label="metadata"))
        if not self.network.blocks_all_egress and self.backend is SandboxBackendKind.LOCAL_AUDIT:
            raise ValueError("local_audit profiles cannot declare network egress.")

    @property
    def digest(self) -> str:
        return _sha256_json(self.to_dict(include_digest=False))

    def allows_command(self, argv: tuple[str, ...]) -> bool:
        if not argv:
            return False
        command = argv[0]
        if self.allowed_commands and command not in self.allowed_commands:
            return False
        joined = " ".join(argv).lower()
        return not any(fragment.lower() in joined for fragment in self.denied_command_fragments)

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "profile_id": self.profile_id,
            "backend": self.backend.value,
            "filesystem": self.filesystem.to_dict(),
            "resources": self.resources.to_dict(),
            "network": self.network.to_dict(),
            "environment": self.environment.to_dict(),
            "allowed_commands": list(self.allowed_commands),
            "denied_command_fragments": list(self.denied_command_fragments),
            "metadata": dict(sorted(self.metadata.items())),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class SandboxCommandRequest:
    request_id: str
    profile: SandboxProfile
    argv: tuple[str, ...]
    working_directory: str = "/workspace/src"
    stdin_text: str | None = None
    expected_head_sha: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", _normalize_id(self.request_id, label="request_id"))
        object.__setattr__(self, "argv", _normalize_argv(self.argv))
        object.__setattr__(
            self,
            "working_directory",
            _normalize_absolute_posix_path(self.working_directory, label="working_directory"),
        )
        object.__setattr__(
            self,
            "expected_head_sha",
            _normalize_optional_sha(self.expected_head_sha, label="expected_head_sha"),
        )
        object.__setattr__(self, "metadata", _normalize_str_mapping(self.metadata, label="metadata"))
        if self.stdin_text is not None and len(self.stdin_text.encode("utf-8")) > self.profile.resources.max_output_bytes:
            raise ValueError("stdin_text exceeds the sandbox profile output byte limit.")
        if not self.profile.allows_command(self.argv):
            raise ValueError("argv is not allowed by the sandbox profile command policy.")

    @property
    def digest(self) -> str:
        return _sha256_json(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "request_id": self.request_id,
            "profile_digest": self.profile.digest,
            "profile_id": self.profile.profile_id,
            "argv": list(self.argv),
            "working_directory": self.working_directory,
            "stdin_sha256": _sha256_text(self.stdin_text) if self.stdin_text is not None else None,
            "expected_head_sha": self.expected_head_sha,
            "metadata": dict(sorted(self.metadata.items())),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class SandboxCommandResult:
    request_id: str
    status: SandboxExecutionStatus
    exit_code: int | None
    duration_ms: int
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None
    artifact_manifest_sha256: str | None = None
    policy_issue: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", _normalize_id(self.request_id, label="request_id"))
        if self.exit_code is not None and self.exit_code < 0:
            raise ValueError("exit_code must be non-negative when provided.")
        _require_non_negative_int(self.duration_ms, label="duration_ms")
        object.__setattr__(self, "stdout_sha256", _normalize_optional_sha256(self.stdout_sha256, label="stdout_sha256"))
        object.__setattr__(self, "stderr_sha256", _normalize_optional_sha256(self.stderr_sha256, label="stderr_sha256"))
        object.__setattr__(
            self,
            "artifact_manifest_sha256",
            _normalize_optional_sha256(self.artifact_manifest_sha256, label="artifact_manifest_sha256"),
        )
        object.__setattr__(self, "policy_issue", _normalize_optional_text(self.policy_issue, label="policy_issue"))
        object.__setattr__(self, "metadata", _normalize_str_mapping(self.metadata, label="metadata"))
        if self.status in (SandboxExecutionStatus.SUCCEEDED, SandboxExecutionStatus.FAILED) and self.exit_code is None:
            raise ValueError("terminal command results require an exit_code.")
        if self.status is SandboxExecutionStatus.POLICY_BLOCKED and self.policy_issue is None:
            raise ValueError("policy-blocked results require a policy_issue.")

    @property
    def passed(self) -> bool:
        return self.status is SandboxExecutionStatus.SUCCEEDED and self.exit_code == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "status": self.status.value,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "artifact_manifest_sha256": self.artifact_manifest_sha256,
            "policy_issue": self.policy_issue,
            "metadata": dict(sorted(self.metadata.items())),
            "passed": self.passed,
        }


def default_wave6_local_audit_profile() -> SandboxProfile:
    return SandboxProfile(
        profile_id="wave6.local-audit.default",
        backend=SandboxBackendKind.LOCAL_AUDIT,
        filesystem=SandboxFilesystemPolicy(
            mounts=(
                SandboxMount(
                    source=".",
                    target="/workspace/src",
                    access=SandboxMountAccess.READ_ONLY,
                ),
                SandboxMount(
                    source=".blackfox-workspace/out",
                    target="/workspace/out",
                    access=SandboxMountAccess.READ_WRITE,
                    required=False,
                ),
                SandboxMount(
                    source=".blackfox-workspace/tmp",
                    target="/workspace/tmp",
                    access=SandboxMountAccess.READ_WRITE,
                    required=False,
                ),
            )
        ),
        resources=SandboxResourceLimits(
            timeout_seconds=300,
            max_memory_mb=1024,
            max_processes=64,
            max_output_bytes=1_048_576,
            max_artifact_bytes=10_485_760,
            cpu_count=1,
        ),
        allowed_commands=("python", "python3", "pytest"),
        metadata={
            "wave": "6",
            "claim": "contracts-only-local-audit-is-not-isolation",
        },
    )


def _sha256_json(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalize_id(value: str, *, label: str) -> str:
    cleaned = _normalize_text(value, label=label)
    if not _SAFE_ID_RE.fullmatch(cleaned):
        raise ValueError(f"{label} contains unsupported characters.")
    if ".." in cleaned:
        raise ValueError(f"{label} must not contain '..'.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_text(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    return _normalize_text(value, label=label)


def _normalize_relative_path(value: str, *, label: str) -> str:
    cleaned = _normalize_text(value.replace("\\", "/"), label=label)
    if cleaned.startswith("/"):
        raise ValueError(f"{label} must be relative, not absolute.")
    path = PurePosixPath(cleaned)
    if any(part in ("", "..") for part in path.parts):
        raise ValueError(f"{label} must not contain empty or '..' path segments.")
    return path.as_posix()


def _normalize_absolute_posix_path(value: str, *, label: str) -> str:
    cleaned = _normalize_text(value.replace("\\", "/"), label=label)
    if not cleaned.startswith("/"):
        raise ValueError(f"{label} must be an absolute POSIX path.")
    path = PurePosixPath(cleaned)
    if any(part in ("", "..") for part in path.parts):
        raise ValueError(f"{label} must not contain empty or '..' path segments.")
    return path.as_posix()


def _normalize_absolute_paths(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    normalized = tuple(_normalize_absolute_posix_path(value, label=label) for value in values)
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{label} must not contain duplicates.")
    return normalized


def _normalize_env_names(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    normalized = tuple(_normalize_env_name(value, label=label) for value in values)
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{label} must not contain duplicates.")
    return normalized


def _normalize_env_name(value: str, *, label: str) -> str:
    cleaned = _normalize_text(value, label=label)
    if not _ENV_NAME_RE.fullmatch(cleaned):
        raise ValueError(f"{label} contains an invalid environment variable name.")
    return cleaned


def _normalize_env_mapping(values: Mapping[str, str]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in values.items():
        env_key = _normalize_env_name(key, label="injected_variables")
        normalized[env_key] = _normalize_text(value, label="injected_variable_value")
    return dict(sorted(normalized.items()))


def _normalize_str_mapping(values: Mapping[str, str], *, label: str) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in values.items():
        normalized[_normalize_id(key, label=f"{label}_key")] = _normalize_text(value, label=f"{label}_value")
    return dict(sorted(normalized.items()))


def _normalize_command_tuple(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    normalized = tuple(_normalize_text(value, label=label) for value in values)
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{label} must not contain duplicates.")
    return normalized


def _normalize_argv(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized = tuple(_normalize_text(value, label="argv") for value in values)
    if not normalized:
        raise ValueError("argv must not be empty.")
    return normalized


def _normalize_host(value: str) -> str:
    cleaned = _normalize_text(value.lower(), label="host")
    if "://" in cleaned or "/" in cleaned or ".." in cleaned:
        raise ValueError("host must be a hostname, not a URL or path.")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", cleaned):
        raise ValueError("host contains unsupported characters.")
    return cleaned


def _normalize_protocol(value: str) -> str:
    cleaned = _normalize_text(value.lower(), label="protocol")
    if cleaned not in {"tcp", "udp", "https"}:
        raise ValueError("protocol must be tcp, udp, or https.")
    return cleaned


def _normalize_optional_sha(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    cleaned = _normalize_text(value.lower(), label=label)
    if not _HEX_SHA_RE.fullmatch(cleaned):
        raise ValueError(f"{label} must be a hexadecimal commit identifier.")
    return cleaned


def _normalize_optional_sha256(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    cleaned = _normalize_text(value.lower(), label=label)
    if not re.fullmatch(r"[0-9a-f]{64}", cleaned):
        raise ValueError(f"{label} must be a 64-character lowercase SHA-256 digest.")
    return cleaned


def _require_positive_int(value: int, *, label: str) -> None:
    if value <= 0:
        raise ValueError(f"{label} must be greater than zero.")


def _require_non_negative_int(value: int, *, label: str) -> None:
    if value < 0:
        raise ValueError(f"{label} must be non-negative.")


def _require_port(value: int) -> None:
    if value < 1 or value > 65535:
        raise ValueError("port must be in the range 1-65535.")
