from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from pathlib import PurePosixPath
from typing import Any

from ix_blackfox.authoring.errors import AuthoringValidationError
from ix_blackfox.authoring.models import (
    AuthoringFinding,
    AuthoringFindingSeverity,
)


class PatchMutationType(StrEnum):
    """
    Allowed mutation types in a Wave 3 model-authored patch proposal.
    """

    REPLACE_TEXT = "replace_text"
    CREATE_FILE = "create_file"


class PatchProposalValidationCode(StrEnum):
    """
    Machine-readable validation codes emitted by the response parser.
    """

    VALID = auto()
    EMPTY_RESPONSE = auto()
    MARKDOWN_WRAPPED_RESPONSE = auto()
    MALFORMED_JSON = auto()
    TOP_LEVEL_NOT_OBJECT = auto()
    UNKNOWN_TOP_LEVEL_FIELD = auto()
    MISSING_REQUIRED_FIELD = auto()
    INVALID_SCHEMA_VERSION = auto()
    INVALID_FIELD_TYPE = auto()
    INVALID_CONFIDENCE = auto()
    EMPTY_MUTATIONS = auto()
    MUTATION_NOT_OBJECT = auto()
    UNKNOWN_MUTATION_FIELD = auto()
    INVALID_MUTATION_TYPE = auto()
    UNSAFE_PATH = auto()
    EMPTY_BEFORE_TEXT = auto()
    EMPTY_AFTER_TEXT = auto()
    INVALID_CREATE_FILE_BEFORE_TEXT = auto()
    NO_OP_MUTATION = auto()
    SHELL_COMMAND_DETECTED = auto()
    NETWORK_INSTRUCTION_DETECTED = auto()
    SUCCESS_CLAIM_WITHOUT_EVIDENCE = auto()
    DUPLICATE_MUTATION_ID = auto()
    DUPLICATE_CREATE_PATH = auto()


@dataclass(frozen=True, slots=True)
class PatchAuthoringMutation:
    """
    One parsed and validated mutation from a Wave 3 authored patch proposal.
    """

    mutation_id: str
    mutation_type: PatchMutationType
    path: str
    before_text: str
    after_text: str
    rationale: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "mutation_id",
            _normalize_identifier(self.mutation_id, label="mutation_id"),
        )
        object.__setattr__(self, "path", _normalize_relative_path(self.path))
        object.__setattr__(
            self,
            "rationale",
            _normalize_text(self.rationale, label="rationale"),
        )

        if self.mutation_type is PatchMutationType.REPLACE_TEXT:
            if not self.before_text:
                raise AuthoringValidationError(
                    "replace_text mutation before_text must not be empty."
                )
            if not self.after_text:
                raise AuthoringValidationError(
                    "replace_text mutation after_text must not be empty."
                )
            if self.before_text == self.after_text:
                raise AuthoringValidationError(
                    "replace_text mutation must not be a no-op."
                )

        if self.mutation_type is PatchMutationType.CREATE_FILE:
            if self.before_text != "":
                raise AuthoringValidationError(
                    "create_file mutation before_text must be empty."
                )
            if not self.after_text:
                raise AuthoringValidationError(
                    "create_file mutation after_text must not be empty."
                )

    @property
    def size_delta(self) -> int:
        return len(self.after_text) - len(self.before_text)

    @property
    def digest(self) -> str:
        return _sha256_json(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload = {
            "mutation_id": self.mutation_id,
            "mutation_type": self.mutation_type.value,
            "path": self.path,
            "before_text": self.before_text,
            "after_text": self.after_text,
            "rationale": self.rationale,
            "size_delta": self.size_delta,
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class PatchAuthoringProposal:
    """
    Parsed Wave 3 patch-authoring proposal.

    This object represents validated model output only. It has not been compiled
    into a Wave 2 patch candidate and it has not been executed.
    """

    schema_version: str
    proposal_id: str
    objective_summary: str
    reasoning_summary: str
    confidence: float
    assumptions: tuple[str, ...]
    risk_notes: tuple[str, ...]
    expected_tests: tuple[str, ...]
    mutations: tuple[PatchAuthoringMutation, ...]
    raw_digest: str
    findings: tuple[AuthoringFinding, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "schema_version",
            _normalize_text(self.schema_version, label="schema_version"),
        )
        object.__setattr__(
            self,
            "proposal_id",
            _normalize_identifier(self.proposal_id, label="proposal_id"),
        )
        object.__setattr__(
            self,
            "objective_summary",
            _normalize_text(self.objective_summary, label="objective_summary"),
        )
        object.__setattr__(
            self,
            "reasoning_summary",
            _normalize_text(self.reasoning_summary, label="reasoning_summary"),
        )
        if self.confidence < 0.0 or self.confidence > 1.0:
            raise AuthoringValidationError(
                "Proposal confidence must be between 0.0 and 1.0."
            )
        object.__setattr__(
            self,
            "assumptions",
            tuple(
                _normalize_text(value, label="assumption") for value in self.assumptions
            ),
        )
        object.__setattr__(
            self,
            "risk_notes",
            tuple(
                _normalize_text(value, label="risk_note") for value in self.risk_notes
            ),
        )
        object.__setattr__(
            self,
            "expected_tests",
            tuple(
                _normalize_text(value, label="expected_test")
                for value in self.expected_tests
            ),
        )
        mutations = tuple(self.mutations)
        if not mutations:
            raise AuthoringValidationError(
                "Patch authoring proposal requires at least one mutation."
            )
        object.__setattr__(self, "mutations", mutations)
        object.__setattr__(self, "raw_digest", _normalize_sha256(self.raw_digest))
        object.__setattr__(self, "findings", tuple(self.findings))

    @property
    def affected_paths(self) -> tuple[str, ...]:
        paths: list[str] = []
        seen: set[str] = set()
        for mutation in self.mutations:
            if mutation.path in seen:
                continue
            seen.add(mutation.path)
            paths.append(mutation.path)
        return tuple(paths)

    @property
    def total_size_delta(self) -> int:
        return sum(mutation.size_delta for mutation in self.mutations)

    @property
    def digest(self) -> str:
        payload = self.to_dict(include_digest=False)
        return _sha256_json(payload)

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload = {
            "schema_version": self.schema_version,
            "proposal_id": self.proposal_id,
            "objective_summary": self.objective_summary,
            "reasoning_summary": self.reasoning_summary,
            "confidence": self.confidence,
            "assumptions": list(self.assumptions),
            "risk_notes": list(self.risk_notes),
            "expected_tests": list(self.expected_tests),
            "mutations": [mutation.to_dict() for mutation in self.mutations],
            "affected_paths": list(self.affected_paths),
            "total_size_delta": self.total_size_delta,
            "raw_digest": self.raw_digest,
            "findings": [finding.to_dict() for finding in self.findings],
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class PatchAuthoringResponseParserConfig:
    """
    Strict parsing limits for Wave 3 model-authored patch proposals.
    """

    expected_schema_version: str = "wave3.patch_authoring_response.v1"
    max_response_chars: int = 128_000
    max_string_chars: int = 32_000
    max_mutations: int = 12
    reject_markdown_wrapped_json: bool = True
    reject_shell_commands: bool = True
    reject_network_instructions: bool = True
    reject_success_claims_without_evidence: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "expected_schema_version",
            _normalize_text(
                self.expected_schema_version, label="expected_schema_version"
            ),
        )
        if self.max_response_chars <= 0:
            raise ValueError("max_response_chars must be positive.")
        if self.max_string_chars <= 0:
            raise ValueError("max_string_chars must be positive.")
        if self.max_mutations <= 0:
            raise ValueError("max_mutations must be positive.")


@dataclass(frozen=True, slots=True)
class PatchAuthoringResponseParser:
    """
    Strict parser for Wave 3 model-side patch-authoring responses.

    The parser treats model output as hostile input. It accepts JSON only,
    rejects markdown wrappers, rejects unknown fields, rejects unsafe paths, and
    rejects command-like instructions before any proposal can reach compilation.
    """

    config: PatchAuthoringResponseParserConfig = field(
        default_factory=PatchAuthoringResponseParserConfig
    )

    def parse(self, raw_response: str) -> PatchAuthoringProposal:
        response = self._normalize_raw_response(raw_response)
        raw_digest = hashlib.sha256(response.encode("utf-8")).hexdigest()
        payload = self._parse_json_object(response)
        self._validate_top_level_fields(payload)
        self._validate_schema_version(payload)
        self._scan_for_forbidden_content(payload)

        mutations = self._parse_mutations(payload["mutations"])

        findings = (
            AuthoringFinding(
                code="authoring.response_parser.valid",
                severity=AuthoringFindingSeverity.INFO,
                summary="Model patch proposal passed strict Wave 3 response parsing.",
                metadata={
                    "proposal_id": payload["proposal_id"],
                    "mutation_count": len(mutations),
                    "raw_digest": raw_digest,
                },
            ),
        )

        return PatchAuthoringProposal(
            schema_version=payload["schema_version"],
            proposal_id=payload["proposal_id"],
            objective_summary=payload["objective_summary"],
            reasoning_summary=payload["reasoning_summary"],
            confidence=float(payload["confidence"]),
            assumptions=tuple(payload["assumptions"]),
            risk_notes=tuple(payload["risk_notes"]),
            expected_tests=tuple(payload["expected_tests"]),
            mutations=mutations,
            raw_digest=raw_digest,
            findings=findings,
        )

    def _normalize_raw_response(self, raw_response: str) -> str:
        if not isinstance(raw_response, str):
            raise AuthoringValidationError("Model response must be a string.")

        response = raw_response.strip()
        if not response:
            raise _validation_error(
                PatchProposalValidationCode.EMPTY_RESPONSE,
                "Model response was empty.",
            )

        if len(response) > self.config.max_response_chars:
            raise _validation_error(
                PatchProposalValidationCode.INVALID_FIELD_TYPE,
                (
                    "Model response exceeds max_response_chars "
                    f"({len(response)} > {self.config.max_response_chars})."
                ),
            )

        if self.config.reject_markdown_wrapped_json and _looks_markdown_wrapped(
            response
        ):
            raise _validation_error(
                PatchProposalValidationCode.MARKDOWN_WRAPPED_RESPONSE,
                "Model response must be raw JSON only, not markdown-wrapped JSON.",
            )

        return response

    def _parse_json_object(self, response: str) -> dict[str, Any]:
        try:
            payload = json.loads(response)
        except json.JSONDecodeError as exc:
            raise _validation_error(
                PatchProposalValidationCode.MALFORMED_JSON,
                f"Model response was not valid JSON: {exc}",
            ) from exc

        if not isinstance(payload, dict):
            raise _validation_error(
                PatchProposalValidationCode.TOP_LEVEL_NOT_OBJECT,
                "Model response top level must be a JSON object.",
            )

        return payload

    def _validate_top_level_fields(self, payload: Mapping[str, Any]) -> None:
        required_fields = {
            "schema_version",
            "proposal_id",
            "objective_summary",
            "reasoning_summary",
            "confidence",
            "assumptions",
            "risk_notes",
            "expected_tests",
            "mutations",
        }
        allowed_fields = set(required_fields)

        missing = sorted(required_fields - set(payload))
        if missing:
            raise _validation_error(
                PatchProposalValidationCode.MISSING_REQUIRED_FIELD,
                f"Model response missing required field(s): {', '.join(missing)}.",
            )

        unknown = sorted(set(payload) - allowed_fields)
        if unknown:
            raise _validation_error(
                PatchProposalValidationCode.UNKNOWN_TOP_LEVEL_FIELD,
                f"Model response contains unknown top-level field(s): {', '.join(unknown)}.",
            )

        _require_string(
            payload, "schema_version", max_chars=self.config.max_string_chars
        )
        _require_string(payload, "proposal_id", max_chars=self.config.max_string_chars)
        _require_string(
            payload, "objective_summary", max_chars=self.config.max_string_chars
        )
        _require_string(
            payload, "reasoning_summary", max_chars=self.config.max_string_chars
        )
        _require_float(payload, "confidence")
        _require_string_array(
            payload, "assumptions", max_chars=self.config.max_string_chars
        )
        _require_string_array(
            payload, "risk_notes", max_chars=self.config.max_string_chars
        )
        _require_string_array(
            payload, "expected_tests", max_chars=self.config.max_string_chars
        )

        mutations = payload.get("mutations")
        if not isinstance(mutations, list):
            raise _validation_error(
                PatchProposalValidationCode.INVALID_FIELD_TYPE,
                "Field 'mutations' must be an array.",
            )
        if not mutations:
            raise _validation_error(
                PatchProposalValidationCode.EMPTY_MUTATIONS,
                "Field 'mutations' must contain at least one mutation.",
            )
        if len(mutations) > self.config.max_mutations:
            raise _validation_error(
                PatchProposalValidationCode.INVALID_FIELD_TYPE,
                (
                    "Field 'mutations' exceeds max_mutations "
                    f"({len(mutations)} > {self.config.max_mutations})."
                ),
            )

    def _validate_schema_version(self, payload: Mapping[str, Any]) -> None:
        schema_version = payload["schema_version"]
        if schema_version != self.config.expected_schema_version:
            raise _validation_error(
                PatchProposalValidationCode.INVALID_SCHEMA_VERSION,
                (
                    "Model response schema_version mismatch: "
                    f"{schema_version!r} != {self.config.expected_schema_version!r}."
                ),
            )

        confidence = float(payload["confidence"])
        if confidence < 0.0 or confidence > 1.0:
            raise _validation_error(
                PatchProposalValidationCode.INVALID_CONFIDENCE,
                "Field 'confidence' must be between 0.0 and 1.0.",
            )

    def _scan_for_forbidden_content(self, payload: Mapping[str, Any]) -> None:
        strings = tuple(_iter_strings(payload))

        if self.config.reject_shell_commands:
            for value in strings:
                if _contains_shell_command(value):
                    raise _validation_error(
                        PatchProposalValidationCode.SHELL_COMMAND_DETECTED,
                        "Model response contains command-like shell instructions.",
                    )

        if self.config.reject_network_instructions:
            for value in strings:
                if _contains_network_instruction(value):
                    raise _validation_error(
                        PatchProposalValidationCode.NETWORK_INSTRUCTION_DETECTED,
                        "Model response contains network or download instructions.",
                    )

        if self.config.reject_success_claims_without_evidence:
            for value in strings:
                if _contains_success_claim(value):
                    raise _validation_error(
                        PatchProposalValidationCode.SUCCESS_CLAIM_WITHOUT_EVIDENCE,
                        "Model response claims tests or execution succeeded without evidence.",
                    )

    def _parse_mutations(
        self, raw_mutations: list[Any]
    ) -> tuple[PatchAuthoringMutation, ...]:
        mutations: list[PatchAuthoringMutation] = []
        seen_ids: set[str] = set()
        create_paths: set[str] = set()

        for index, raw_mutation in enumerate(raw_mutations):
            if not isinstance(raw_mutation, dict):
                raise _validation_error(
                    PatchProposalValidationCode.MUTATION_NOT_OBJECT,
                    f"Mutation at index {index} must be an object.",
                )

            self._validate_mutation_fields(raw_mutation, index=index)

            mutation_id = _normalize_identifier(
                raw_mutation["mutation_id"],
                label="mutation_id",
            )
            if mutation_id in seen_ids:
                raise _validation_error(
                    PatchProposalValidationCode.DUPLICATE_MUTATION_ID,
                    f"Duplicate mutation_id detected: {mutation_id}.",
                )
            seen_ids.add(mutation_id)

            mutation_type = PatchMutationType(raw_mutation["mutation_type"])
            path = _normalize_relative_path(raw_mutation["path"])

            if mutation_type is PatchMutationType.CREATE_FILE:
                if path in create_paths:
                    raise _validation_error(
                        PatchProposalValidationCode.DUPLICATE_CREATE_PATH,
                        f"Duplicate create_file path detected: {path}.",
                    )
                create_paths.add(path)

            before_text = raw_mutation["before_text"]
            after_text = raw_mutation["after_text"]

            if mutation_type is PatchMutationType.REPLACE_TEXT:
                if before_text == "":
                    raise _validation_error(
                        PatchProposalValidationCode.EMPTY_BEFORE_TEXT,
                        f"replace_text mutation {mutation_id} before_text must not be empty.",
                    )
                if after_text == "":
                    raise _validation_error(
                        PatchProposalValidationCode.EMPTY_AFTER_TEXT,
                        f"replace_text mutation {mutation_id} after_text must not be empty.",
                    )
                if before_text == after_text:
                    raise _validation_error(
                        PatchProposalValidationCode.NO_OP_MUTATION,
                        f"replace_text mutation {mutation_id} is a no-op.",
                    )

            if mutation_type is PatchMutationType.CREATE_FILE:
                if before_text != "":
                    raise _validation_error(
                        PatchProposalValidationCode.INVALID_CREATE_FILE_BEFORE_TEXT,
                        f"create_file mutation {mutation_id} before_text must be empty.",
                    )
                if after_text == "":
                    raise _validation_error(
                        PatchProposalValidationCode.EMPTY_AFTER_TEXT,
                        f"create_file mutation {mutation_id} after_text must not be empty.",
                    )

            mutations.append(
                PatchAuthoringMutation(
                    mutation_id=mutation_id,
                    mutation_type=mutation_type,
                    path=path,
                    before_text=before_text,
                    after_text=after_text,
                    rationale=raw_mutation["rationale"],
                )
            )

        return tuple(mutations)

    def _validate_mutation_fields(
        self, mutation: Mapping[str, Any], *, index: int
    ) -> None:
        required_fields = {
            "mutation_id",
            "mutation_type",
            "path",
            "before_text",
            "after_text",
            "rationale",
        }
        allowed_fields = set(required_fields)

        missing = sorted(required_fields - set(mutation))
        if missing:
            raise _validation_error(
                PatchProposalValidationCode.MISSING_REQUIRED_FIELD,
                f"Mutation at index {index} missing required field(s): {', '.join(missing)}.",
            )

        unknown = sorted(set(mutation) - allowed_fields)
        if unknown:
            raise _validation_error(
                PatchProposalValidationCode.UNKNOWN_MUTATION_FIELD,
                f"Mutation at index {index} contains unknown field(s): {', '.join(unknown)}.",
            )

        _require_string(mutation, "mutation_id", max_chars=self.config.max_string_chars)
        _require_string(
            mutation, "mutation_type", max_chars=self.config.max_string_chars
        )
        _require_string(mutation, "path", max_chars=self.config.max_string_chars)
        _require_string(mutation, "before_text", max_chars=self.config.max_string_chars)
        _require_string(mutation, "after_text", max_chars=self.config.max_string_chars)
        _require_string(mutation, "rationale", max_chars=self.config.max_string_chars)

        try:
            PatchMutationType(mutation["mutation_type"])
        except ValueError as exc:
            raise _validation_error(
                PatchProposalValidationCode.INVALID_MUTATION_TYPE,
                f"Unknown mutation_type: {mutation['mutation_type']!r}.",
            ) from exc

        try:
            _normalize_relative_path(mutation["path"])
        except AuthoringValidationError as exc:
            raise _validation_error(
                PatchProposalValidationCode.UNSAFE_PATH,
                str(exc),
            ) from exc


def _validation_error(
    code: PatchProposalValidationCode,
    message: str,
) -> AuthoringValidationError:
    return AuthoringValidationError(f"{code.value}: {message}")


def _looks_markdown_wrapped(response: str) -> bool:
    stripped = response.strip()
    return stripped.startswith("```") or stripped.endswith("```")


def _iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
        return

    if isinstance(value, Mapping):
        for nested in value.values():
            yield from _iter_strings(nested)
        return

    if isinstance(value, Iterable):
        for nested in value:
            yield from _iter_strings(nested)


def _contains_shell_command(value: str) -> bool:
    lowered = value.lower()
    command_patterns = (
        r"\brm\s+-rf\b",
        r"\bcurl\s+",
        r"\bwget\s+",
        r"\bpowershell\b",
        r"\bcmd\.exe\b",
        r"\bbash\s+-c\b",
        r"\bsh\s+-c\b",
        r"\bpython\s+-c\b",
        r"\bpython3\s+-c\b",
        r"\bchmod\s+",
        r"\bsudo\s+",
        r"\bdel\s+/[fq]\b",
        r"\binvoke-webrequest\b",
        r"\bstart-process\b",
    )
    return any(re.search(pattern, lowered) for pattern in command_patterns)


def _contains_network_instruction(value: str) -> bool:
    lowered = value.lower()
    network_patterns = (
        "http://",
        "https://",
        "ftp://",
        "download ",
        "upload ",
        "send request",
        "post to ",
        "open socket",
        "network access",
    )
    return any(pattern in lowered for pattern in network_patterns)


def _contains_success_claim(value: str) -> bool:
    lowered = value.lower()
    success_claim_patterns = (
        "tests passed",
        "test passed",
        "all tests pass",
        "all tests passed",
        "pytest passed",
        "i ran the tests",
        "i executed the tests",
        "verified by running",
        "confirmed by running",
    )
    return any(pattern in lowered for pattern in success_claim_patterns)


def _require_string(
    payload: Mapping[str, Any],
    key: str,
    *,
    max_chars: int,
) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise _validation_error(
            PatchProposalValidationCode.INVALID_FIELD_TYPE,
            f"Field {key!r} must be a string.",
        )
    if len(value) > max_chars:
        raise _validation_error(
            PatchProposalValidationCode.INVALID_FIELD_TYPE,
            f"Field {key!r} exceeds max string length.",
        )
    return value


def _require_float(payload: Mapping[str, Any], key: str) -> float:
    value = payload.get(key)
    if not isinstance(value, int | float):
        raise _validation_error(
            PatchProposalValidationCode.INVALID_FIELD_TYPE,
            f"Field {key!r} must be a number.",
        )
    return float(value)


def _require_string_array(
    payload: Mapping[str, Any],
    key: str,
    *,
    max_chars: int,
) -> tuple[str, ...]:
    value = payload.get(key)
    if not isinstance(value, list):
        raise _validation_error(
            PatchProposalValidationCode.INVALID_FIELD_TYPE,
            f"Field {key!r} must be an array of strings.",
        )

    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise _validation_error(
                PatchProposalValidationCode.INVALID_FIELD_TYPE,
                f"Field {key!r} item {index} must be a string.",
            )
        if len(item) > max_chars:
            raise _validation_error(
                PatchProposalValidationCode.INVALID_FIELD_TYPE,
                f"Field {key!r} item {index} exceeds max string length.",
            )
        result.append(item)

    return tuple(result)


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise AuthoringValidationError(f"{label} must not be empty.")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.:-]*", cleaned):
        raise AuthoringValidationError(
            f"{label} contains unsupported characters: {value!r}."
        )
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise AuthoringValidationError(f"{label} must not be empty.")
    return cleaned


def _normalize_relative_path(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    if not cleaned:
        raise AuthoringValidationError("path must not be empty.")
    if cleaned.startswith(("/", "~")):
        raise AuthoringValidationError(f"path must be workspace-relative: {value!r}.")
    if ":" in cleaned.split("/")[0]:
        raise AuthoringValidationError(
            f"path must not include a drive or URI prefix: {value!r}."
        )

    path = PurePosixPath(cleaned)
    parts: list[str] = []
    for part in path.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            raise AuthoringValidationError(f"path traversal is forbidden: {value!r}.")
        parts.append(part)

    if not parts:
        raise AuthoringValidationError("path must not resolve to the workspace root.")

    normalized = "/".join(parts)

    if normalized.startswith(".") and not normalized.startswith(".github/"):
        raise AuthoringValidationError(
            f"hidden root paths are not allowed in proposals: {value!r}."
        )

    return normalized


def _normalize_sha256(value: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) != 64 or any(char not in "0123456789abcdef" for char in cleaned):
        raise AuthoringValidationError(
            "sha256 must be a 64-character lowercase hexadecimal value."
        )
    return cleaned


def _sha256_json(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
