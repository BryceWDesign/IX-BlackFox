from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from pathlib import Path
from typing import Any, Self
from uuid import uuid4

from ix_blackfox.authoring.errors import AuthoringCompilationError
from ix_blackfox.authoring.models import (
    AuthoringFinding,
    AuthoringFindingSeverity,
)
from ix_blackfox.authoring.response_parser import (
    PatchAuthoringMutation,
    PatchAuthoringProposal,
    PatchMutationType,
)
from ix_blackfox.tools.manifest import ToolPathPolicy
from ix_blackfox.tools.patch import PatchDiff, PatchFileChange
from ix_blackfox.tools.workspace import WorkspacePathResolver, WorkspacePathViolation


class PatchCompilationStatus(StrEnum):
    """
    Outcome status for compiling a Wave 3 proposal into a Wave 2 PatchDiff.
    """

    COMPILED = auto()
    REJECTED = auto()


class PatchCompilationFindingCode(StrEnum):
    """
    Machine-readable finding codes emitted by the Wave 3 patch compiler.
    """

    COMPILED = auto()
    WORKSPACE_NOT_FOUND = auto()
    WORKSPACE_NOT_DIRECTORY = auto()
    PATH_POLICY_VIOLATION = auto()
    TARGET_NOT_FOUND = auto()
    TARGET_NOT_FILE = auto()
    CREATE_TARGET_EXISTS = auto()
    DECODE_ERROR = auto()
    STALE_BEFORE_TEXT = auto()
    NON_UNIQUE_BEFORE_TEXT = auto()
    EMPTY_RESULT = auto()
    NO_OP_RESULT = auto()
    PATCH_VALIDATION_ERROR = auto()


@dataclass(frozen=True, slots=True)
class PatchCompilationFinding:
    """
    One compiler finding produced while turning a proposal into PatchDiff.
    """

    code: PatchCompilationFindingCode
    severity: AuthoringFindingSeverity
    summary: str
    path: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "path", _normalize_optional_relative_path(self.path))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_authoring_finding(self) -> AuthoringFinding:
        return AuthoringFinding(
            code=f"authoring.patch_compiler.{self.code.value}",
            severity=self.severity,
            summary=self.summary,
            path=self.path,
            metadata=dict(self.metadata),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "severity": self.severity.value,
            "summary": self.summary,
            "path": self.path,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            code=PatchCompilationFindingCode(_require_text(payload, "code")),
            severity=AuthoringFindingSeverity(_require_text(payload, "severity")),
            summary=_require_text(payload, "summary"),
            path=_optional_text_from_payload(payload, "path"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class CompiledPatchCandidate:
    """
    Wave 3 compiler output.

    This object is the handoff artifact from the authoring layer into the
    existing Wave 2 patch-test-verify-bundle runtime. It is not execution
    evidence. It only proves that a parsed proposal compiled into a governed
    PatchDiff candidate.
    """

    candidate_id: str
    status: PatchCompilationStatus
    proposal_id: str
    proposal_digest: str
    patch_diff: PatchDiff
    findings: tuple[PatchCompilationFinding, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "candidate_id",
            _normalize_identifier(self.candidate_id, label="candidate_id"),
        )
        object.__setattr__(
            self,
            "proposal_id",
            _normalize_identifier(self.proposal_id, label="proposal_id"),
        )
        object.__setattr__(self, "proposal_digest", _normalize_sha256(self.proposal_digest))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def patch_id(self) -> str:
        return self.patch_diff.patch_id

    @property
    def patch_digest(self) -> str:
        return self.patch_diff.digest

    @property
    def changed_paths(self) -> tuple[str, ...]:
        return self.patch_diff.changed_paths

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "status": self.status.value,
            "proposal_id": self.proposal_id,
            "proposal_digest": self.proposal_digest,
            "patch_id": self.patch_id,
            "patch_digest": self.patch_digest,
            "changed_paths": list(self.changed_paths),
            "patch_diff": self.patch_diff.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_patch = payload.get("patch_diff")
        if not isinstance(raw_patch, Mapping):
            raise TypeError("patch_diff must be a mapping.")

        return cls(
            candidate_id=_require_text(payload, "candidate_id"),
            status=PatchCompilationStatus(_require_text(payload, "status")),
            proposal_id=_require_text(payload, "proposal_id"),
            proposal_digest=_require_text(payload, "proposal_digest"),
            patch_diff=PatchDiff.from_dict(raw_patch),
            findings=_load_findings(payload.get("findings", ())),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class PatchProposalCompilerConfig:
    """
    Deterministic controls for proposal-to-PatchDiff compilation.
    """

    encoding: str = "utf-8"
    created_by: str = "blackfox-authoring"
    require_unique_replace_text: bool = True
    max_compiled_file_bytes: int = 256_000
    blocked_roots: tuple[str, ...] = (
        ".git",
        ".hg",
        ".svn",
        ".env",
        ".ssh",
        "artifacts",
        "run_bundles",
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "encoding", _normalize_text(self.encoding, label="encoding"))
        object.__setattr__(self, "created_by", _normalize_token(self.created_by, label="created_by"))
        if self.max_compiled_file_bytes <= 0:
            raise ValueError("max_compiled_file_bytes must be positive.")
        object.__setattr__(
            self,
            "blocked_roots",
            _normalize_path_tuple(self.blocked_roots, field_name="blocked_roots"),
        )

    def build_path_policy(self) -> ToolPathPolicy:
        return ToolPathPolicy(
            blocked_roots=self.blocked_roots,
            allow_absolute_paths=False,
        )


@dataclass(frozen=True, slots=True)
class PatchProposalCompiler:
    """
    Compile a validated Wave 3 patch proposal into an existing Wave 2 PatchDiff.

    This compiler is intentionally deterministic and read-only. It verifies
    proposal paths, reads current workspace files, checks before-text freshness,
    expands snippet replacements into whole-file PatchFileChange objects, and
    refuses stale or no-op proposals before Wave 2 execution can occur.
    """

    workspace_root: Path
    config: PatchProposalCompilerConfig = field(default_factory=PatchProposalCompilerConfig)
    path_policy: ToolPathPolicy | None = None

    def __post_init__(self) -> None:
        root = self.workspace_root.expanduser().resolve()
        if not root.exists():
            raise AuthoringCompilationError(
                f"{PatchCompilationFindingCode.WORKSPACE_NOT_FOUND.value}: "
                f"Workspace root does not exist: {root}"
            )
        if not root.is_dir():
            raise AuthoringCompilationError(
                f"{PatchCompilationFindingCode.WORKSPACE_NOT_DIRECTORY.value}: "
                f"Workspace root is not a directory: {root}"
            )

        object.__setattr__(self, "workspace_root", root)

    @property
    def resolver(self) -> WorkspacePathResolver:
        return WorkspacePathResolver(
            workspace_root=self.workspace_root,
            path_policy=self.path_policy or self.config.build_path_policy(),
        )

    def compile(self, proposal: PatchAuthoringProposal) -> CompiledPatchCandidate:
        if not isinstance(proposal, PatchAuthoringProposal):
            raise AuthoringCompilationError("proposal must be a PatchAuthoringProposal.")

        findings: list[PatchCompilationFinding] = []
        file_changes: list[PatchFileChange] = []

        for mutation in proposal.mutations:
            file_changes.append(
                self._compile_mutation(
                    mutation=mutation,
                    proposal=proposal,
                    findings=findings,
                )
            )

        patch_diff = PatchDiff.create(
            summary=f"Wave 3 authored patch candidate: {proposal.objective_summary}",
            file_changes=tuple(file_changes),
            created_by=self.config.created_by,
            metadata={
                "wave": 3,
                "authoring_stage": "proposal_to_patchdiff_compilation",
                "proposal_id": proposal.proposal_id,
                "proposal_digest": proposal.digest,
                "proposal_raw_digest": proposal.raw_digest,
                "proposal_confidence": proposal.confidence,
                "affected_paths": list(proposal.affected_paths),
                "expected_tests": list(proposal.expected_tests),
                "assumptions": list(proposal.assumptions),
                "risk_notes": list(proposal.risk_notes),
            },
        )

        validation_report = patch_diff.validate()
        if not validation_report.is_valid:
            error_codes = ", ".join(validation_report.codes)
            raise AuthoringCompilationError(
                f"{PatchCompilationFindingCode.PATCH_VALIDATION_ERROR.value}: "
                f"Compiled PatchDiff failed validation: {error_codes}"
            )

        findings.append(
            PatchCompilationFinding(
                code=PatchCompilationFindingCode.COMPILED,
                severity=AuthoringFindingSeverity.INFO,
                summary="Wave 3 proposal compiled into a governed PatchDiff candidate.",
                metadata={
                    "proposal_id": proposal.proposal_id,
                    "patch_id": patch_diff.patch_id,
                    "patch_digest": patch_diff.digest,
                    "file_count": patch_diff.file_count,
                    "changed_paths": list(patch_diff.changed_paths),
                },
            )
        )

        return CompiledPatchCandidate(
            candidate_id=f"compiled-candidate-{uuid4().hex}",
            status=PatchCompilationStatus.COMPILED,
            proposal_id=proposal.proposal_id,
            proposal_digest=proposal.digest,
            patch_diff=patch_diff,
            findings=tuple(findings),
            metadata={
                "compiler": "PatchProposalCompiler",
                "workspace_root": str(self.workspace_root),
                "created_by": self.config.created_by,
                "encoding": self.config.encoding,
            },
        )

    def _compile_mutation(
        self,
        *,
        mutation: PatchAuthoringMutation,
        proposal: PatchAuthoringProposal,
        findings: list[PatchCompilationFinding],
    ) -> PatchFileChange:
        try:
            target_path = self.resolver.resolve(mutation.path)
        except WorkspacePathViolation as exc:
            raise AuthoringCompilationError(
                f"{PatchCompilationFindingCode.PATH_POLICY_VIOLATION.value}: {exc}"
            ) from exc

        normalized_path = self.resolver.relative_path(target_path)

        if mutation.mutation_type is PatchMutationType.CREATE_FILE:
            return self._compile_create_file(
                mutation=mutation,
                target_path=target_path,
                normalized_path=normalized_path,
                proposal=proposal,
                findings=findings,
            )

        if mutation.mutation_type is PatchMutationType.REPLACE_TEXT:
            return self._compile_replace_text(
                mutation=mutation,
                target_path=target_path,
                normalized_path=normalized_path,
                proposal=proposal,
                findings=findings,
            )

        raise AuthoringCompilationError(
            f"Unsupported mutation type: {mutation.mutation_type.value}"
        )

    def _compile_create_file(
        self,
        *,
        mutation: PatchAuthoringMutation,
        target_path: Path,
        normalized_path: str,
        proposal: PatchAuthoringProposal,
        findings: list[PatchCompilationFinding],
    ) -> PatchFileChange:
        if target_path.exists():
            raise AuthoringCompilationError(
                f"{PatchCompilationFindingCode.CREATE_TARGET_EXISTS.value}: "
                f"create_file refuses to overwrite existing file: {normalized_path}"
            )

        after_text = mutation.after_text
        self._validate_compiled_text_size(
            path=normalized_path,
            text=after_text,
        )

        findings.append(
            PatchCompilationFinding(
                code=PatchCompilationFindingCode.COMPILED,
                severity=AuthoringFindingSeverity.INFO,
                summary="create_file mutation compiled into PatchFileChange.add.",
                path=normalized_path,
                metadata={
                    "proposal_id": proposal.proposal_id,
                    "mutation_id": mutation.mutation_id,
                    "mutation_type": mutation.mutation_type.value,
                    "after_sha256": _sha256_text(after_text),
                },
            )
        )

        return PatchFileChange.add(
            path=normalized_path,
            after_text=after_text,
            metadata={
                "wave": 3,
                "authoring_stage": "proposal_to_patchdiff_compilation",
                "proposal_id": proposal.proposal_id,
                "proposal_digest": proposal.digest,
                "mutation_id": mutation.mutation_id,
                "mutation_type": mutation.mutation_type.value,
                "rationale": mutation.rationale,
                "compiled_from": "wave3_authoring_proposal",
            },
        )

    def _compile_replace_text(
        self,
        *,
        mutation: PatchAuthoringMutation,
        target_path: Path,
        normalized_path: str,
        proposal: PatchAuthoringProposal,
        findings: list[PatchCompilationFinding],
    ) -> PatchFileChange:
        if not target_path.exists():
            raise AuthoringCompilationError(
                f"{PatchCompilationFindingCode.TARGET_NOT_FOUND.value}: "
                f"replace_text target does not exist: {normalized_path}"
            )
        if not target_path.is_file():
            raise AuthoringCompilationError(
                f"{PatchCompilationFindingCode.TARGET_NOT_FILE.value}: "
                f"replace_text target is not a file: {normalized_path}"
            )

        try:
            current_text = target_path.read_text(encoding=self.config.encoding)
        except UnicodeDecodeError as exc:
            raise AuthoringCompilationError(
                f"{PatchCompilationFindingCode.DECODE_ERROR.value}: "
                f"Could not decode target file {normalized_path!r} as {self.config.encoding}: {exc}"
            ) from exc

        current_sha256 = _sha256_text(current_text)

        if mutation.before_text == current_text:
            compiled_after_text = mutation.after_text
            match_mode = "whole_file"
        else:
            occurrence_count = current_text.count(mutation.before_text)
            if occurrence_count == 0:
                raise AuthoringCompilationError(
                    f"{PatchCompilationFindingCode.STALE_BEFORE_TEXT.value}: "
                    f"before_text was not found in current workspace file: {normalized_path}"
                )
            if self.config.require_unique_replace_text and occurrence_count != 1:
                raise AuthoringCompilationError(
                    f"{PatchCompilationFindingCode.NON_UNIQUE_BEFORE_TEXT.value}: "
                    f"before_text matched {occurrence_count} locations in {normalized_path}; "
                    "refusing ambiguous replacement."
                )

            compiled_after_text = current_text.replace(
                mutation.before_text,
                mutation.after_text,
                1 if self.config.require_unique_replace_text else occurrence_count,
            )
            match_mode = "snippet"

        if not compiled_after_text:
            raise AuthoringCompilationError(
                f"{PatchCompilationFindingCode.EMPTY_RESULT.value}: "
                f"compiled replacement would make file empty: {normalized_path}"
            )

        if compiled_after_text == current_text:
            raise AuthoringCompilationError(
                f"{PatchCompilationFindingCode.NO_OP_RESULT.value}: "
                f"compiled replacement is a no-op: {normalized_path}"
            )

        self._validate_compiled_text_size(
            path=normalized_path,
            text=compiled_after_text,
        )

        findings.append(
            PatchCompilationFinding(
                code=PatchCompilationFindingCode.COMPILED,
                severity=AuthoringFindingSeverity.INFO,
                summary="replace_text mutation compiled into PatchFileChange.modify.",
                path=normalized_path,
                metadata={
                    "proposal_id": proposal.proposal_id,
                    "mutation_id": mutation.mutation_id,
                    "mutation_type": mutation.mutation_type.value,
                    "match_mode": match_mode,
                    "before_sha256": current_sha256,
                    "after_sha256": _sha256_text(compiled_after_text),
                },
            )
        )

        return PatchFileChange.modify(
            path=normalized_path,
            before_text=current_text,
            after_text=compiled_after_text,
            metadata={
                "wave": 3,
                "authoring_stage": "proposal_to_patchdiff_compilation",
                "proposal_id": proposal.proposal_id,
                "proposal_digest": proposal.digest,
                "mutation_id": mutation.mutation_id,
                "mutation_type": mutation.mutation_type.value,
                "rationale": mutation.rationale,
                "compiled_from": "wave3_authoring_proposal",
                "before_match_mode": match_mode,
                "workspace_before_sha256": current_sha256,
            },
        )

    def _validate_compiled_text_size(self, *, path: str, text: str) -> None:
        byte_count = len(text.encode(self.config.encoding))
        if byte_count > self.config.max_compiled_file_bytes:
            raise AuthoringCompilationError(
                "compiled_file_too_large: "
                f"Compiled text for {path!r} exceeds max_compiled_file_bytes "
                f"({byte_count} > {self.config.max_compiled_file_bytes})."
            )


def _load_findings(value: Any) -> tuple[PatchCompilationFinding, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError("findings must be an iterable of mappings.")

    findings: list[PatchCompilationFinding] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise TypeError("findings must contain only mappings.")
        findings.append(PatchCompilationFinding.from_dict(item))
    return tuple(findings)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_token(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_relative_path(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_relative_path(value)


def _normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("relative path must not be empty.")
    if cleaned.startswith(("/", "~")) or ":" in cleaned.split("/")[0]:
        raise ValueError(f"path must be relative: {value!r}")

    parts: list[str] = []
    for raw_part in cleaned.split("/"):
        part = raw_part.strip()
        if part in {"", "."}:
            continue
        if part == "..":
            raise ValueError(f"path traversal is not allowed: {value!r}")
        parts.append(part)

    if not parts:
        raise ValueError("relative path must not resolve to workspace root.")
    return "/".join(parts)


def _normalize_sha256(value: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) != 64 or any(char not in "0123456789abcdef" for char in cleaned):
        raise ValueError("sha256 must be a 64-character lowercase hexadecimal digest.")
    return cleaned


def _normalize_path_tuple(values: Iterable[str], *, field_name: str) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise TypeError(f"{field_name} must contain only strings.")
        cleaned = value.strip().replace("\\", "/")
        if not cleaned:
            raise ValueError(f"{field_name} must not contain empty paths.")
        normalized.append(cleaned)
    return tuple(normalized)


def _coerce_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")
    return dict(value)


def _require_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string.")
    return value


def _optional_text_from_payload(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string or None.")
    return value
