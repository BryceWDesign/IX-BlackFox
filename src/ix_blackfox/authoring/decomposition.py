from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum, auto
from typing import Any, Self
from uuid import uuid4

from ix_blackfox.authoring.errors import AuthoringDecompositionError
from ix_blackfox.authoring.models import (
    AuthoringContext,
    AuthoringEvidence,
    AuthoringEvidenceStrength,
    AuthoringFinding,
    AuthoringFindingSeverity,
    AuthoringRequest,
    AuthoringRiskLevel,
    AuthoringStatus,
    AuthoringSubtask,
    AuthoringSubtaskKind,
)


class DecompositionSignalKind(StrEnum):
    """
    Evidence or objective signal used by the Wave 3 task decomposer.
    """

    OBJECTIVE_KEYWORD = auto()
    FAILURE_TARGET = auto()
    RELATED_PATH = auto()
    CONTEXT_PATH = auto()
    EVIDENCE_GAP = auto()
    RISK_HINT = auto()
    TEST_SCOPE = auto()


@dataclass(frozen=True, slots=True)
class DecompositionSignal:
    """
    One normalized signal that influenced Wave 3 task decomposition.
    """

    signal_id: str
    kind: DecompositionSignalKind
    summary: str
    path: str | None = None
    weight: int = 1
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "signal_id",
            _normalize_identifier(self.signal_id, label="signal_id"),
        )
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        object.__setattr__(self, "path", _normalize_optional_relative_path(self.path))
        if self.weight <= 0:
            raise ValueError("DecompositionSignal weight must be positive.")
        object.__setattr__(self, "metadata", dict(self.metadata))

    @classmethod
    def create(
        cls,
        *,
        kind: DecompositionSignalKind,
        summary: str,
        path: str | None = None,
        weight: int = 1,
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            signal_id=f"decomposition-signal-{uuid4().hex}",
            kind=kind,
            summary=summary,
            path=path,
            weight=weight,
            metadata=dict(metadata or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "kind": self.kind.value,
            "summary": self.summary,
            "path": self.path,
            "weight": self.weight,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            signal_id=_require_text(payload, "signal_id"),
            kind=DecompositionSignalKind(_require_text(payload, "kind")),
            summary=_require_text(payload, "summary"),
            path=_optional_text_from_payload(payload, "path"),
            weight=_require_int(payload, "weight"),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class RepairDecompositionPlan:
    """
    Reviewable Wave 3 decomposition plan for one authoring request.
    """

    plan_id: str
    request_id: str
    objective_id: str
    objective_summary: str
    subtasks: tuple[AuthoringSubtask, ...] = field(default_factory=tuple)
    signals: tuple[DecompositionSignal, ...] = field(default_factory=tuple)
    findings: tuple[AuthoringFinding, ...] = field(default_factory=tuple)
    risk_level: AuthoringRiskLevel = AuthoringRiskLevel.MODERATE
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "plan_id",
            _normalize_identifier(self.plan_id, label="plan_id"),
        )
        object.__setattr__(
            self,
            "request_id",
            _normalize_identifier(self.request_id, label="request_id"),
        )
        object.__setattr__(
            self,
            "objective_id",
            _normalize_identifier(self.objective_id, label="objective_id"),
        )
        object.__setattr__(
            self,
            "objective_summary",
            _normalize_text(self.objective_summary, label="objective_summary"),
        )
        object.__setattr__(self, "subtasks", tuple(self.subtasks))
        object.__setattr__(self, "signals", tuple(self.signals))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if not self.subtasks:
            raise ValueError("RepairDecompositionPlan requires at least one subtask.")

    @property
    def requires_review(self) -> bool:
        return any(subtask.kind is AuthoringSubtaskKind.REVIEW for subtask in self.subtasks)

    @property
    def target_paths(self) -> tuple[str, ...]:
        paths: list[str] = []
        seen: set[str] = set()
        for subtask in self.subtasks:
            for path in subtask.target_paths:
                if path in seen:
                    continue
                seen.add(path)
                paths.append(path)
        return tuple(paths)

    def apply_to_request(self, request: AuthoringRequest) -> AuthoringRequest:
        """
        Return a copy of an authoring request marked as decomposed.

        The original request remains immutable.
        """

        if request.request_id != self.request_id:
            raise AuthoringDecompositionError(
                "Cannot apply decomposition plan to a different request."
            )

        merged_findings = _dedupe_findings((*request.findings, *self.findings))
        return replace(
            request,
            status=AuthoringStatus.DECOMPOSED,
            subtasks=self.subtasks,
            findings=merged_findings,
            metadata={
                **dict(request.metadata),
                "decomposition_plan_id": self.plan_id,
                "decomposition_risk_level": self.risk_level.value,
                "decomposition_signal_count": len(self.signals),
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "request_id": self.request_id,
            "objective_id": self.objective_id,
            "objective_summary": self.objective_summary,
            "risk_level": self.risk_level.value,
            "requires_review": self.requires_review,
            "target_paths": list(self.target_paths),
            "subtasks": [subtask.to_dict() for subtask in self.subtasks],
            "signals": [signal.to_dict() for signal in self.signals],
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            plan_id=_require_text(payload, "plan_id"),
            request_id=_require_text(payload, "request_id"),
            objective_id=_require_text(payload, "objective_id"),
            objective_summary=_require_text(payload, "objective_summary"),
            risk_level=AuthoringRiskLevel(_require_text(payload, "risk_level")),
            subtasks=_load_subtasks(payload.get("subtasks", ())),
            signals=_load_signals(payload.get("signals", ())),
            findings=_load_findings(payload.get("findings", ())),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class RepairTaskDecomposerConfig:
    """
    Deterministic limits for Wave 3 task decomposition.
    """

    max_target_paths: int = 8
    require_review_when_evidence_missing: bool = True
    require_review_for_test_mutation: bool = True
    require_review_for_governance_paths: bool = True
    high_risk_keywords: tuple[str, ...] = (
        "delete",
        "remove",
        "rewrite",
        "refactor",
        "dependency",
        "lockfile",
        "policy",
        "approval",
        "secret",
        "credential",
        "token",
        "deploy",
        "production",
        "bypass",
        "skip",
    )
    test_path_patterns: tuple[str, ...] = (
        "test_",
        "/tests/",
        "tests/",
    )
    governance_path_patterns: tuple[str, ...] = (
        "policy",
        "approval",
        "acceptance",
        "validator",
        "receipt",
        "manifest",
        "workspace",
        "control_plane",
    )

    def __post_init__(self) -> None:
        if self.max_target_paths <= 0:
            raise ValueError("max_target_paths must be positive.")
        object.__setattr__(
            self,
            "high_risk_keywords",
            _normalize_keyword_tuple(
                self.high_risk_keywords,
                field_name="high_risk_keywords",
            ),
        )
        object.__setattr__(
            self,
            "test_path_patterns",
            _normalize_keyword_tuple(
                self.test_path_patterns,
                field_name="test_path_patterns",
            ),
        )
        object.__setattr__(
            self,
            "governance_path_patterns",
            _normalize_keyword_tuple(
                self.governance_path_patterns,
                field_name="governance_path_patterns",
            ),
        )


@dataclass(frozen=True, slots=True)
class RepairTaskDecomposer:
    """
    Deterministic Wave 3 repair objective decomposer.

    The decomposer turns an authoring request into explicit inspect, modify,
    test, and review subtasks. It does not author patches. It only makes the
    repair plan reviewable before hypotheses or model-side patch authoring.
    """

    config: RepairTaskDecomposerConfig = field(default_factory=RepairTaskDecomposerConfig)

    def decompose_request(self, request: AuthoringRequest) -> RepairDecompositionPlan:
        if not isinstance(request, AuthoringRequest):
            raise AuthoringDecompositionError("request must be an AuthoringRequest.")

        objective_text = request.objective.summary
        context = request.context
        evidence = request.evidence

        signals = self._collect_signals(
            objective_text=objective_text,
            context=context,
            evidence=evidence,
        )
        target_paths = self._select_target_paths(
            context=context,
            evidence=evidence,
            signals=signals,
        )
        risk_level = self._risk_level(
            objective_text=objective_text,
            target_paths=target_paths,
            evidence=evidence,
        )
        findings = self._build_findings(
            objective_text=objective_text,
            target_paths=target_paths,
            evidence=evidence,
            risk_level=risk_level,
        )
        subtasks = self._build_subtasks(
            request=request,
            target_paths=target_paths,
            evidence=evidence,
            risk_level=risk_level,
        )

        return RepairDecompositionPlan(
            plan_id=f"repair-decomposition-{uuid4().hex}",
            request_id=request.request_id,
            objective_id=request.objective.objective_id,
            objective_summary=objective_text,
            subtasks=subtasks,
            signals=signals,
            findings=findings,
            risk_level=risk_level,
            metadata={
                "decomposer": "RepairTaskDecomposer",
                "mode": request.mode.value,
                "target_path_count": len(target_paths),
                "evidence_count": len(evidence),
                "finding_count": len(findings),
            },
        )

    def _collect_signals(
        self,
        *,
        objective_text: str,
        context: AuthoringContext | None,
        evidence: tuple[AuthoringEvidence, ...],
    ) -> tuple[DecompositionSignal, ...]:
        signals: list[DecompositionSignal] = []
        lowered_objective = objective_text.lower()

        for keyword in self.config.high_risk_keywords:
            if keyword in lowered_objective:
                signals.append(
                    DecompositionSignal.create(
                        kind=DecompositionSignalKind.RISK_HINT,
                        summary=f"Objective contains high-risk keyword: {keyword}",
                        weight=3,
                        metadata={"keyword": keyword},
                    )
                )

        for keyword in _objective_keywords(lowered_objective):
            signals.append(
                DecompositionSignal.create(
                    kind=DecompositionSignalKind.OBJECTIVE_KEYWORD,
                    summary=f"Objective keyword detected: {keyword}",
                    weight=1,
                    metadata={"keyword": keyword},
                )
            )

        if context is not None:
            for path in context.paths[: self.config.max_target_paths]:
                signals.append(
                    DecompositionSignal.create(
                        kind=DecompositionSignalKind.CONTEXT_PATH,
                        summary=f"Context file available: {path}",
                        path=path,
                        weight=1,
                    )
                )

        if not evidence:
            signals.append(
                DecompositionSignal.create(
                    kind=DecompositionSignalKind.EVIDENCE_GAP,
                    summary="No authoring evidence was attached to the request.",
                    weight=3,
                )
            )

        for item in evidence:
            if item.strength is AuthoringEvidenceStrength.MISSING:
                signals.append(
                    DecompositionSignal.create(
                        kind=DecompositionSignalKind.EVIDENCE_GAP,
                        summary=f"Evidence item has missing strength: {item.evidence_id}",
                        weight=2,
                        metadata={"evidence_id": item.evidence_id},
                    )
                )
            for path in item.related_paths[: self.config.max_target_paths]:
                signals.append(
                    DecompositionSignal.create(
                        kind=DecompositionSignalKind.RELATED_PATH,
                        summary=f"Evidence references path: {path}",
                        path=path,
                        weight=2,
                        metadata={"evidence_id": item.evidence_id},
                    )
                )

            for finding in item.findings:
                if finding.path:
                    signals.append(
                        DecompositionSignal.create(
                            kind=DecompositionSignalKind.FAILURE_TARGET,
                            summary=f"Evidence finding targets path: {finding.path}",
                            path=finding.path,
                            weight=3,
                            metadata={
                                "evidence_id": item.evidence_id,
                                "finding_code": finding.code,
                            },
                        )
                    )

        return tuple(signals)

    def _select_target_paths(
        self,
        *,
        context: AuthoringContext | None,
        evidence: tuple[AuthoringEvidence, ...],
        signals: tuple[DecompositionSignal, ...],
    ) -> tuple[str, ...]:
        weighted_paths: dict[str, int] = {}

        for signal in signals:
            if signal.path is None:
                continue
            weighted_paths[signal.path] = weighted_paths.get(signal.path, 0) + signal.weight

        for item in evidence:
            for path in item.related_paths:
                weighted_paths[path] = weighted_paths.get(path, 0) + 2

        if context is not None:
            for path in context.paths:
                weighted_paths.setdefault(path, 1)

        sorted_paths = sorted(
            weighted_paths,
            key=lambda path: (-weighted_paths[path], _path_sort_score(path), path),
        )
        return tuple(sorted_paths[: self.config.max_target_paths])

    def _risk_level(
        self,
        *,
        objective_text: str,
        target_paths: tuple[str, ...],
        evidence: tuple[AuthoringEvidence, ...],
    ) -> AuthoringRiskLevel:
        lowered_objective = objective_text.lower()
        high_risk_hits = sum(
            1 for keyword in self.config.high_risk_keywords if keyword in lowered_objective
        )
        has_direct_evidence = any(
            item.strength is AuthoringEvidenceStrength.DIRECT for item in evidence
        )
        has_missing_or_no_evidence = (
            not evidence
            or any(item.strength is AuthoringEvidenceStrength.MISSING for item in evidence)
        )
        touches_governance = any(self._is_governance_path(path) for path in target_paths)
        touches_tests = any(self._is_test_path(path) for path in target_paths)

        if "bypass" in lowered_objective or "secret" in lowered_objective:
            return AuthoringRiskLevel.CRITICAL

        if touches_governance and self.config.require_review_for_governance_paths:
            return AuthoringRiskLevel.HIGH

        if high_risk_hits >= 2:
            return AuthoringRiskLevel.HIGH

        if touches_tests and self.config.require_review_for_test_mutation:
            return AuthoringRiskLevel.MODERATE

        if has_missing_or_no_evidence and self.config.require_review_when_evidence_missing:
            return AuthoringRiskLevel.MODERATE

        if not has_direct_evidence:
            return AuthoringRiskLevel.MODERATE

        return AuthoringRiskLevel.LOW

    def _build_findings(
        self,
        *,
        objective_text: str,
        target_paths: tuple[str, ...],
        evidence: tuple[AuthoringEvidence, ...],
        risk_level: AuthoringRiskLevel,
    ) -> tuple[AuthoringFinding, ...]:
        findings: list[AuthoringFinding] = []

        if not evidence:
            findings.append(
                AuthoringFinding(
                    code="authoring.decomposition.no_evidence",
                    severity=AuthoringFindingSeverity.WARNING,
                    summary=(
                        "No evidence items were attached; repair decomposition "
                        "must proceed from the objective only."
                    ),
                    metadata={"risk_level": risk_level.value},
                )
            )

        if any(item.strength is AuthoringEvidenceStrength.MISSING for item in evidence):
            findings.append(
                AuthoringFinding(
                    code="authoring.decomposition.missing_failure_evidence",
                    severity=AuthoringFindingSeverity.WARNING,
                    summary=(
                        "At least one evidence item is marked missing; repair "
                        "authoring should require stronger review."
                    ),
                    metadata={"risk_level": risk_level.value},
                )
            )

        if not target_paths:
            findings.append(
                AuthoringFinding(
                    code="authoring.decomposition.no_target_paths",
                    severity=AuthoringFindingSeverity.WARNING,
                    summary=(
                        "No likely target paths were identified from context or evidence."
                    ),
                    metadata={"risk_level": risk_level.value},
                )
            )

        for path in target_paths:
            if self._is_test_path(path):
                findings.append(
                    AuthoringFinding(
                        code="authoring.decomposition.test_path_targeted",
                        severity=AuthoringFindingSeverity.WARNING,
                        summary=(
                            "A likely target path is a test path; generated changes "
                            "must not weaken verification."
                        ),
                        path=path,
                        metadata={"risk_level": risk_level.value},
                    )
                )
            if self._is_governance_path(path):
                findings.append(
                    AuthoringFinding(
                        code="authoring.decomposition.governance_path_targeted",
                        severity=AuthoringFindingSeverity.ERROR,
                        summary=(
                            "A likely target path appears governance-sensitive and "
                            "requires explicit review before mutation."
                        ),
                        path=path,
                        metadata={"risk_level": risk_level.value},
                    )
                )

        lowered_objective = objective_text.lower()
        for keyword in self.config.high_risk_keywords:
            if keyword in lowered_objective:
                findings.append(
                    AuthoringFinding(
                        code="authoring.decomposition.high_risk_objective_keyword",
                        severity=AuthoringFindingSeverity.WARNING,
                        summary=f"Objective contains high-risk keyword: {keyword}",
                        metadata={
                            "keyword": keyword,
                            "risk_level": risk_level.value,
                        },
                    )
                )

        return _dedupe_findings(findings)

    def _build_subtasks(
        self,
        *,
        request: AuthoringRequest,
        target_paths: tuple[str, ...],
        evidence: tuple[AuthoringEvidence, ...],
        risk_level: AuthoringRiskLevel,
    ) -> tuple[AuthoringSubtask, ...]:
        evidence_ids = tuple(item.evidence_id for item in evidence)

        inspect_subtask = AuthoringSubtask(
            subtask_id=f"{request.task_id}-inspect",
            summary="Inspect the objective, available evidence, and bounded repository context.",
            kind=AuthoringSubtaskKind.INSPECT,
            risk_level=risk_level,
            target_paths=target_paths,
            required_evidence=evidence_ids,
            metadata={
                "purpose": "establish_repair_scope",
                "has_direct_evidence": any(
                    item.strength is AuthoringEvidenceStrength.DIRECT for item in evidence
                ),
            },
        )

        modify_subtask = AuthoringSubtask(
            subtask_id=f"{request.task_id}-modify",
            summary="Prepare the smallest patch candidate aligned to the evidence and objective.",
            kind=AuthoringSubtaskKind.MODIFY,
            risk_level=risk_level,
            depends_on=(inspect_subtask.subtask_id,),
            target_paths=target_paths,
            required_evidence=evidence_ids,
            metadata={
                "purpose": "author_minimal_patch_candidate",
                "must_compile_to_patchdiff": True,
            },
        )

        test_subtask = AuthoringSubtask(
            subtask_id=f"{request.task_id}-test",
            summary="Run allowlisted tests through the existing Wave 2 control plane.",
            kind=AuthoringSubtaskKind.TEST,
            risk_level=AuthoringRiskLevel.LOW,
            depends_on=(modify_subtask.subtask_id,),
            target_paths=tuple(path for path in target_paths if self._is_test_path(path)),
            required_evidence=evidence_ids,
            metadata={
                "purpose": "validate_candidate_with_wave2_tests",
                "wave2_required": True,
            },
        )

        subtasks: list[AuthoringSubtask] = [
            inspect_subtask,
            modify_subtask,
            test_subtask,
        ]

        if self._requires_review(
            risk_level=risk_level,
            target_paths=target_paths,
            evidence=evidence,
        ):
            subtasks.append(
                AuthoringSubtask(
                    subtask_id=f"{request.task_id}-review",
                    summary=(
                        "Require explicit human review before high-risk or "
                        "weak-evidence authoring proceeds."
                    ),
                    kind=AuthoringSubtaskKind.REVIEW,
                    risk_level=risk_level,
                    depends_on=(modify_subtask.subtask_id,),
                    target_paths=target_paths,
                    required_evidence=evidence_ids,
                    metadata={
                        "purpose": "preserve_human_review_authority",
                        "review_required": True,
                    },
                )
            )

        return tuple(subtasks)

    def _requires_review(
        self,
        *,
        risk_level: AuthoringRiskLevel,
        target_paths: tuple[str, ...],
        evidence: tuple[AuthoringEvidence, ...],
    ) -> bool:
        if risk_level in {AuthoringRiskLevel.HIGH, AuthoringRiskLevel.CRITICAL}:
            return True

        if self.config.require_review_when_evidence_missing:
            if not evidence or any(
                item.strength in {
                    AuthoringEvidenceStrength.MISSING,
                    AuthoringEvidenceStrength.WEAK,
                }
                for item in evidence
            ):
                return True

        if self.config.require_review_for_test_mutation:
            if any(self._is_test_path(path) for path in target_paths):
                return True

        if self.config.require_review_for_governance_paths:
            if any(self._is_governance_path(path) for path in target_paths):
                return True

        return False

    def _is_test_path(self, path: str) -> bool:
        normalized = path.lower().replace("\\", "/")
        return any(pattern in normalized for pattern in self.config.test_path_patterns)

    def _is_governance_path(self, path: str) -> bool:
        normalized = path.lower().replace("\\", "/")
        return any(pattern in normalized for pattern in self.config.governance_path_patterns)


def _objective_keywords(objective_text: str) -> tuple[str, ...]:
    tokens = re.findall(r"[a-zA-Z][a-zA-Z0-9_]{2,}", objective_text.lower())
    ignored = {
        "the",
        "and",
        "for",
        "with",
        "from",
        "that",
        "this",
        "into",
        "through",
        "failing",
        "failure",
        "repair",
        "fix",
        "test",
        "tests",
    }
    keywords: list[str] = []
    seen: set[str] = set()

    for token in tokens:
        if token in ignored or token in seen:
            continue
        seen.add(token)
        keywords.append(token)

    return tuple(keywords[:8])


def _path_sort_score(path: str) -> int:
    normalized = path.lower().replace("\\", "/")
    if normalized.startswith("src/"):
        return 0
    if normalized.startswith("tests/"):
        return 1
    return 2


def _load_subtasks(value: Any) -> tuple[AuthoringSubtask, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError("subtasks must be an iterable of mappings.")

    subtasks: list[AuthoringSubtask] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise TypeError("subtasks must contain only mappings.")
        subtasks.append(AuthoringSubtask.from_dict(item))
    return tuple(subtasks)


def _load_signals(value: Any) -> tuple[DecompositionSignal, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError("signals must be an iterable of mappings.")

    signals: list[DecompositionSignal] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise TypeError("signals must contain only mappings.")
        signals.append(DecompositionSignal.from_dict(item))
    return tuple(signals)


def _load_findings(value: Any) -> tuple[AuthoringFinding, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError("findings must be an iterable of mappings.")

    findings: list[AuthoringFinding] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise TypeError("findings must contain only mappings.")
        findings.append(AuthoringFinding.from_dict(item))
    return tuple(findings)


def _dedupe_findings(findings: Iterable[AuthoringFinding]) -> tuple[AuthoringFinding, ...]:
    deduped: list[AuthoringFinding] = []
    seen: set[tuple[str, str | None, str]] = set()

    for finding in findings:
        key = (finding.code, finding.path, finding.summary)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)

    return tuple(deduped)


def _normalize_identifier(value: str, *, label: str) -> str:
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


def _normalize_keyword_tuple(values: Iterable[str], *, field_name: str) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise TypeError(f"{field_name} must contain only strings.")
        cleaned = value.strip().lower().replace("\\", "/")
        if not cleaned:
            raise ValueError(f"{field_name} must not contain empty values.")
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


def _require_int(payload: Mapping[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int):
        raise TypeError(f"Field {key!r} must be an integer.")
    return value


def _optional_text_from_payload(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string or None.")
    return value
