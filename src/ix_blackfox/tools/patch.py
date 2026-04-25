from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any, Self
from uuid import uuid4


class PatchFileChangeKind(StrEnum):
    """
    File-level mutation declared by a patch diff.
    """

    ADD = auto()
    MODIFY = auto()
    DELETE = auto()


class PatchValidationSeverity(StrEnum):
    """
    Validation finding severity for a patch diff.
    """

    INFO = auto()
    WARNING = auto()
    ERROR = auto()


@dataclass(frozen=True, slots=True)
class PatchValidationFinding:
    """
    One validation finding attached to a patch diff.

    Findings are deliberately simple and serializable so patch validation can be
    surfaced in operator summaries, receipts, and run bundles without depending
    on a specific linter or patch application engine.
    """

    code: str
    severity: PatchValidationSeverity
    summary: str
    path: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _normalize_token(self.code, label="code"))
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "path", _normalize_optional_path(self.path))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "summary": self.summary,
            "path": self.path,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            code=_require_text(payload, "code"),
            severity=PatchValidationSeverity(_require_text(payload, "severity")),
            summary=_require_text(payload, "summary"),
            path=_optional_text_from_payload(payload, "path"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class PatchValidationReport:
    """
    Validation report for a patch diff before application.
    """

    findings: tuple[PatchValidationFinding, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(self.findings))

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def error_count(self) -> int:
        return sum(
            1
            for finding in self.findings
            if finding.severity is PatchValidationSeverity.ERROR
        )

    @property
    def warning_count(self) -> int:
        return sum(
            1
            for finding in self.findings
            if finding.severity is PatchValidationSeverity.WARNING
        )

    @property
    def is_valid(self) -> bool:
        return self.error_count == 0

    @property
    def codes(self) -> tuple[str, ...]:
        return tuple(finding.code for finding in self.findings)

    def has_finding(self, code: str) -> bool:
        normalized_code = _normalize_token(code, label="code")
        return normalized_code in self.codes

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "finding_count": self.finding_count,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_findings = payload.get("findings", ())
        if not isinstance(raw_findings, Iterable) or isinstance(raw_findings, str):
            raise TypeError("findings must be an iterable of mappings.")

        findings: list[PatchValidationFinding] = []
        for raw_finding in raw_findings:
            if not isinstance(raw_finding, Mapping):
                raise TypeError("findings must contain only mappings.")
            findings.append(PatchValidationFinding.from_dict(raw_finding))

        return cls(findings=tuple(findings))


@dataclass(frozen=True, slots=True)
class PatchFileChange:
    """
    One file mutation inside a BlackFox patch diff.

    The model stores complete before/after text. That is intentionally heavier
    than a raw hunk-only representation, but it makes the later patch-apply tool
    deterministic and auditable:
    - modify/delete operations can verify the expected before hash
    - add/modify operations can verify the produced after hash
    - unified diff text can be regenerated reproducibly
    """

    path: str
    change_kind: PatchFileChangeKind
    before_text: str | None = None
    after_text: str | None = None
    before_sha256: str | None = None
    after_sha256: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized_path = _normalize_relative_path(self.path)
        object.__setattr__(self, "path", normalized_path)
        object.__setattr__(self, "metadata", dict(self.metadata))

        computed_before_sha256 = _sha256_text(self.before_text)
        computed_after_sha256 = _sha256_text(self.after_text)

        if self.before_sha256 is not None and self.before_sha256 != computed_before_sha256:
            raise ValueError(
                f"before_sha256 does not match before_text for path {self.path!r}."
            )
        if self.after_sha256 is not None and self.after_sha256 != computed_after_sha256:
            raise ValueError(
                f"after_sha256 does not match after_text for path {self.path!r}."
            )

        object.__setattr__(self, "before_sha256", computed_before_sha256)
        object.__setattr__(self, "after_sha256", computed_after_sha256)

        self._validate_text_contract()

    @classmethod
    def add(
        cls,
        *,
        path: str,
        after_text: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            path=path,
            change_kind=PatchFileChangeKind.ADD,
            before_text=None,
            after_text=after_text,
            metadata=dict(metadata or {}),
        )

    @classmethod
    def modify(
        cls,
        *,
        path: str,
        before_text: str,
        after_text: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            path=path,
            change_kind=PatchFileChangeKind.MODIFY,
            before_text=before_text,
            after_text=after_text,
            metadata=dict(metadata or {}),
        )

    @classmethod
    def delete(
        cls,
        *,
        path: str,
        before_text: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            path=path,
            change_kind=PatchFileChangeKind.DELETE,
            before_text=before_text,
            after_text=None,
            metadata=dict(metadata or {}),
        )

    @property
    def line_delta(self) -> int:
        before_count = len((self.before_text or "").splitlines())
        after_count = len((self.after_text or "").splitlines())
        return after_count - before_count

    @property
    def is_noop(self) -> bool:
        return self.before_text == self.after_text

    def validate(self) -> PatchValidationReport:
        findings: list[PatchValidationFinding] = []

        if self.is_noop:
            findings.append(
                PatchValidationFinding(
                    code="patch.noop_change",
                    severity=PatchValidationSeverity.WARNING,
                    summary="Patch file change does not alter file content.",
                    path=self.path,
                )
            )

        if self.path.startswith((".git/", ".env", ".ssh/")):
            findings.append(
                PatchValidationFinding(
                    code="patch.sensitive_path",
                    severity=PatchValidationSeverity.ERROR,
                    summary="Patch targets a sensitive or repository-control path.",
                    path=self.path,
                )
            )

        if self.change_kind is PatchFileChangeKind.ADD and self.after_text == "":
            findings.append(
                PatchValidationFinding(
                    code="patch.empty_added_file",
                    severity=PatchValidationSeverity.WARNING,
                    summary="Patch adds an empty file.",
                    path=self.path,
                )
            )

        if self.change_kind is PatchFileChangeKind.DELETE:
            findings.append(
                PatchValidationFinding(
                    code="patch.delete_requires_review",
                    severity=PatchValidationSeverity.WARNING,
                    summary="Patch deletes a file and should receive operator review.",
                    path=self.path,
                )
            )

        return PatchValidationReport(findings=tuple(findings))

    def to_unified_diff(self, *, context_lines: int = 3) -> str:
        import difflib

        before_lines = _split_for_diff(self.before_text)
        after_lines = _split_for_diff(self.after_text)

        from_file = "/dev/null" if self.change_kind is PatchFileChangeKind.ADD else f"a/{self.path}"
        to_file = "/dev/null" if self.change_kind is PatchFileChangeKind.DELETE else f"b/{self.path}"

        return "".join(
            difflib.unified_diff(
                before_lines,
                after_lines,
                fromfile=from_file,
                tofile=to_file,
                n=context_lines,
                lineterm="",
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "change_kind": self.change_kind.value,
            "before_text": self.before_text,
            "after_text": self.after_text,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "line_delta": self.line_delta,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            path=_require_text(payload, "path"),
            change_kind=PatchFileChangeKind(_require_text(payload, "change_kind")),
            before_text=_optional_text_from_payload(payload, "before_text"),
            after_text=_optional_text_from_payload(payload, "after_text"),
            before_sha256=_optional_text_from_payload(payload, "before_sha256"),
            after_sha256=_optional_text_from_payload(payload, "after_sha256"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )

    def _validate_text_contract(self) -> None:
        if self.change_kind is PatchFileChangeKind.ADD:
            if self.before_text is not None:
                raise ValueError("ADD changes must not include before_text.")
            if self.after_text is None:
                raise ValueError("ADD changes must include after_text.")

        if self.change_kind is PatchFileChangeKind.MODIFY:
            if self.before_text is None:
                raise ValueError("MODIFY changes must include before_text.")
            if self.after_text is None:
                raise ValueError("MODIFY changes must include after_text.")

        if self.change_kind is PatchFileChangeKind.DELETE:
            if self.before_text is None:
                raise ValueError("DELETE changes must include before_text.")
            if self.after_text is not None:
                raise ValueError("DELETE changes must not include after_text.")


@dataclass(frozen=True, slots=True)
class PatchDiff:
    """
    Auditable patch diff model for governed BlackFox patch application.
    """

    patch_id: str
    summary: str
    file_changes: tuple[PatchFileChange, ...]
    created_by: str = "blackfox"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "patch_id",
            _normalize_identifier(self.patch_id, label="patch_id"),
        )
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "created_by", _normalize_token(self.created_by, label="created_by"))
        object.__setattr__(self, "file_changes", tuple(self.file_changes))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if not self.file_changes:
            raise ValueError("PatchDiff must contain at least one file change.")

        paths = [change.path for change in self.file_changes]
        duplicate_paths = tuple(sorted(path for path in set(paths) if paths.count(path) > 1))
        if duplicate_paths:
            raise ValueError(
                "PatchDiff cannot contain multiple changes for the same path: "
                f"{', '.join(duplicate_paths)}."
            )

    @classmethod
    def create(
        cls,
        *,
        summary: str,
        file_changes: Iterable[PatchFileChange],
        created_by: str = "blackfox",
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            patch_id=f"patch-{uuid4().hex}",
            summary=summary,
            file_changes=tuple(file_changes),
            created_by=created_by,
            metadata=dict(metadata or {}),
        )

    @property
    def changed_paths(self) -> tuple[str, ...]:
        return tuple(change.path for change in self.file_changes)

    @property
    def file_count(self) -> int:
        return len(self.file_changes)

    @property
    def total_line_delta(self) -> int:
        return sum(change.line_delta for change in self.file_changes)

    @property
    def digest(self) -> str:
        payload = {
            "patch_id": self.patch_id,
            "summary": self.summary,
            "created_by": self.created_by,
            "file_changes": [change.to_dict() for change in self.file_changes],
            "metadata": dict(self.metadata),
        }
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def validate(self) -> PatchValidationReport:
        findings: list[PatchValidationFinding] = []

        for change in self.file_changes:
            findings.extend(change.validate().findings)

        destructive_count = sum(
            1
            for change in self.file_changes
            if change.change_kind is PatchFileChangeKind.DELETE
        )
        if destructive_count:
            findings.append(
                PatchValidationFinding(
                    code="patch.contains_deletions",
                    severity=PatchValidationSeverity.WARNING,
                    summary="Patch contains file deletions.",
                    metadata={"delete_count": destructive_count},
                )
            )

        if self.file_count > 25:
            findings.append(
                PatchValidationFinding(
                    code="patch.large_file_count",
                    severity=PatchValidationSeverity.WARNING,
                    summary="Patch changes more than 25 files.",
                    metadata={"file_count": self.file_count},
                )
            )

        return PatchValidationReport(findings=tuple(findings))

    def to_unified_diff(self, *, context_lines: int = 3) -> str:
        return "\n".join(
            change.to_unified_diff(context_lines=context_lines).rstrip("\n")
            for change in self.file_changes
        ).rstrip("\n") + "\n"

    def to_dict(self) -> dict[str, Any]:
        return {
            "patch_id": self.patch_id,
            "summary": self.summary,
            "created_by": self.created_by,
            "file_count": self.file_count,
            "changed_paths": list(self.changed_paths),
            "total_line_delta": self.total_line_delta,
            "digest": self.digest,
            "validation": self.validate().to_dict(),
            "file_changes": [change.to_dict() for change in self.file_changes],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        raw_changes = payload.get("file_changes", ())
        if not isinstance(raw_changes, Iterable) or isinstance(raw_changes, str):
            raise TypeError("file_changes must be an iterable of mappings.")

        changes: list[PatchFileChange] = []
        for raw_change in raw_changes:
            if not isinstance(raw_change, Mapping):
                raise TypeError("file_changes must contain only mappings.")
            changes.append(PatchFileChange.from_dict(raw_change))

        return cls(
            patch_id=_require_text(payload, "patch_id"),
            summary=_require_text(payload, "summary"),
            created_by=str(payload.get("created_by", "blackfox")),
            file_changes=tuple(changes),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


def _split_for_diff(value: str | None) -> list[str]:
    if value is None:
        return []
    return value.splitlines(keepends=True)


def _sha256_text(value: str | None) -> str | None:
    if value is None:
        return None
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


def _normalize_optional_path(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_relative_path(value)


def _normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError("Patch path must not be empty.")
    if cleaned.startswith(("/", "~")):
        raise ValueError(f"Patch path must be relative: {value!r}.")

    parts: list[str] = []
    for raw_part in cleaned.split("/"):
        part = raw_part.strip()
        if part in {"", "."}:
            continue
        if part == "..":
            raise ValueError(f"Patch path must not contain traversal: {value!r}.")
        parts.append(part)

    if not parts:
        raise ValueError("Patch path must not resolve to the workspace root.")

    return "/".join(parts)


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
