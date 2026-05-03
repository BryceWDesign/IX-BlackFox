from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any, Self
from uuid import uuid4

from ix_blackfox.authoring.decomposition import RepairDecompositionPlan
from ix_blackfox.authoring.models import (
    AuthoringEvidence,
    AuthoringEvidenceStrength,
    AuthoringFinding,
    AuthoringFindingSeverity,
    AuthoringRequest,
    AuthoringRiskLevel,
)


class RepairFailureClass(StrEnum):
    """
    Deterministic Wave 3 repair hypothesis failure class.
    """

    IMPORT_ERROR = auto()
    MISSING_SYMBOL = auto()
    SYNTAX_ERROR = auto()
    ASSERTION_MISMATCH = auto()
    TYPE_MISMATCH = auto()
    STALE_TEST_EXPECTATION = auto()
    INCOMPLETE_IMPLEMENTATION = auto()
    CONFIGURATION_ERROR = auto()
    TEST_WEAKENING_RISK = auto()
    POLICY_OR_GOVERNANCE_RISK = auto()
    UNSAFE_REQUEST = auto()
    INSUFFICIENT_EVIDENCE = auto()
    UNKNOWN = auto()


class RepairShape(StrEnum):
    """
    Expected shape of a candidate repair.
    """

    ADD_MISSING_IMPORT_OR_MODULE = auto()
    ADD_MISSING_SYMBOL = auto()
    CORRECT_SYNTAX = auto()
    CORRECT_LOGIC_OR_EXPECTATION = auto()
    CORRECT_TYPE_HANDLING = auto()
    COMPLETE_IMPLEMENTATION = auto()
    UPDATE_CONFIGURATION = auto()
    DO_NOT_AUTHOR_PATCH = auto()
    REQUIRE_HUMAN_REVIEW = auto()
    UNKNOWN = auto()


@dataclass(frozen=True, slots=True)
class RepairHypothesis:
    """
    One deterministic repair hypothesis used to guide Wave 3 patch authoring.
    """

    hypothesis_id: str
    failure_class: RepairFailureClass
    summary: str
    expected_repair_shape: RepairShape
    confidence: float
    risk_level: AuthoringRiskLevel
    target_paths: tuple[str, ...] = field(default_factory=tuple)
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    validation_expectations: tuple[str, ...] = field(default_factory=tuple)
    findings: tuple[AuthoringFinding, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "hypothesis_id",
            _normalize_identifier(self.hypothesis_id, label="hypothesis_id"),
        )
        object.__setattr__(self, "summary", _normalize_text(self.summary, label="summary"))
        if self.confidence < 0.0 or self.confidence > 1.0:
            raise ValueError("RepairHypothesis confidence must be between 0.0 and 1.0.")
        object.__setattr__(
            self,
            "target_paths",
            tuple(_normalize_relative_path(path) for path in self.target_paths),
        )
        object.__setattr__(
            self,
            "evidence_ids",
            tuple(_normalize_identifier(value, label="evidence_id") for value in self.evidence_ids),
        )
        object.__setattr__(
            self,
            "validation_expectations",
            tuple(_normalize_text(value, label="validation_expectation") for value in self.validation_expectations),
        )
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @classmethod
    def create(
        cls,
        *,
        failure_class: RepairFailureClass,
        summary: str,
        expected_repair_shape: RepairShape,
        confidence: float,
        risk_level: AuthoringRiskLevel,
        target_paths: Iterable[str] = (),
        evidence_ids: Iterable[str] = (),
        validation_expectations: Iterable[str] = (),
        findings: Iterable[AuthoringFinding] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        return cls(
            hypothesis_id=f"repair-hypothesis-{uuid4().hex}",
            failure_class=failure_class,
            summary=summary,
            expected_repair_shape=expected_repair_shape,
            confidence=confidence,
            risk_level=risk_level,
            target_paths=tuple(target_paths),
            evidence_ids=tuple(evidence_ids),
            validation_expectations=tuple(validation_expectations),
            findings=tuple(findings),
            metadata=dict(metadata or {}),
        )

    @property
    def requires_review(self) -> bool:
        return self.risk_level in {
            AuthoringRiskLevel.HIGH,
            AuthoringRiskLevel.CRITICAL,
        } or self.expected_repair_shape in {
            RepairShape.DO_NOT_AUTHOR_PATCH,
            RepairShape.REQUIRE_HUMAN_REVIEW,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "failure_class": self.failure_class.value,
            "summary": self.summary,
            "expected_repair_shape": self.expected_repair_shape.value,
            "confidence": self.confidence,
            "risk_level": self.risk_level.value,
            "requires_review": self.requires_review,
            "target_paths": list(self.target_paths),
            "evidence_ids": list(self.evidence_ids),
            "validation_expectations": list(self.validation_expectations),
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            hypothesis_id=_require_text(payload, "hypothesis_id"),
            failure_class=RepairFailureClass(_require_text(payload, "failure_class")),
            summary=_require_text(payload, "summary"),
            expected_repair_shape=RepairShape(_require_text(payload, "expected_repair_shape")),
            confidence=_require_float(payload, "confidence"),
            risk_level=AuthoringRiskLevel(_require_text(payload, "risk_level")),
            target_paths=_coerce_text_tuple(payload.get("target_paths", ()), field_name="target_paths"),
            evidence_ids=_coerce_text_tuple(payload.get("evidence_ids", ()), field_name="evidence_ids"),
            validation_expectations=_coerce_text_tuple(
                payload.get("validation_expectations", ()),
                field_name="validation_expectations",
            ),
            findings=_load_findings(payload.get("findings", ())),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class RepairHypothesisReport:
    """
    Complete deterministic hypothesis output for one Wave 3 authoring request.
    """

    report_id: str
    request_id: str
    objective_id: str
    hypotheses: tuple[RepairHypothesis, ...] = field(default_factory=tuple)
    selected_hypothesis_id: str | None = None
    plan_id: str | None = None
    findings: tuple[AuthoringFinding, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "report_id",
            _normalize_identifier(self.report_id, label="report_id"),
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
            "selected_hypothesis_id",
            _normalize_optional_identifier(
                self.selected_hypothesis_id,
                label="selected_hypothesis_id",
            ),
        )
        object.__setattr__(
            self,
            "plan_id",
            _normalize_optional_identifier(self.plan_id, label="plan_id"),
        )
        hypotheses = tuple(self.hypotheses)
        object.__setattr__(self, "hypotheses", hypotheses)
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if not hypotheses:
            raise ValueError("RepairHypothesisReport requires at least one hypothesis.")

        hypothesis_ids = {hypothesis.hypothesis_id for hypothesis in hypotheses}
        if len(hypothesis_ids) != len(hypotheses):
            raise ValueError("RepairHypothesisReport hypothesis ids must be unique.")

        if self.selected_hypothesis_id is not None and self.selected_hypothesis_id not in hypothesis_ids:
            raise ValueError("selected_hypothesis_id must match a report hypothesis.")

    @property
    def selected_hypothesis(self) -> RepairHypothesis:
        if self.selected_hypothesis_id is None:
            return self.hypotheses[0]

        for hypothesis in self.hypotheses:
            if hypothesis.hypothesis_id == self.selected_hypothesis_id:
                return hypothesis

        raise LookupError("Selected hypothesis is missing from the report.")

    @property
    def contains_authorable_hypothesis(self) -> bool:
        return any(
            hypothesis.expected_repair_shape not in {
                RepairShape.DO_NOT_AUTHOR_PATCH,
                RepairShape.REQUIRE_HUMAN_REVIEW,
            }
            for hypothesis in self.hypotheses
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "request_id": self.request_id,
            "objective_id": self.objective_id,
            "plan_id": self.plan_id,
            "selected_hypothesis_id": self.selected_hypothesis_id,
            "selected_failure_class": self.selected_hypothesis.failure_class.value,
            "contains_authorable_hypothesis": self.contains_authorable_hypothesis,
            "hypotheses": [hypothesis.to_dict() for hypothesis in self.hypotheses],
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            report_id=_require_text(payload, "report_id"),
            request_id=_require_text(payload, "request_id"),
            objective_id=_require_text(payload, "objective_id"),
            plan_id=_optional_text_from_payload(payload, "plan_id"),
            selected_hypothesis_id=_optional_text_from_payload(payload, "selected_hypothesis_id"),
            hypotheses=_load_hypotheses(payload.get("hypotheses", ())),
            findings=_load_findings(payload.get("findings", ())),
            metadata=_coerce_mapping(payload.get("metadata", {}), field_name="metadata"),
        )


@dataclass(frozen=True, slots=True)
class RepairHypothesisEngineConfig:
    """
    Deterministic matching rules for Wave 3 repair hypotheses.
    """

    minimum_authoring_confidence: float = 0.35
    import_error_patterns: tuple[str, ...] = (
        "modulenotfounderror",
        "importerror",
        "cannot import name",
        "no module named",
    )
    missing_symbol_patterns: tuple[str, ...] = (
        "nameerror",
        "attributeerror",
        "not defined",
        "has no attribute",
        "missing symbol",
    )
    syntax_error_patterns: tuple[str, ...] = (
        "syntaxerror",
        "indentationerror",
        "taberror",
        "invalid syntax",
    )
    assertion_patterns: tuple[str, ...] = (
        "assertionerror",
        "assert ",
        "assertion failed",
        "expected",
        "actual",
    )
    type_patterns: tuple[str, ...] = (
        "typeerror",
        "valueerror",
        "keyerror",
        "indexerror",
    )
    configuration_patterns: tuple[str, ...] = (
        "configuration",
        "config",
        "toml",
        "yaml",
        "ini",
        "environment",
    )
    incomplete_patterns: tuple[str, ...] = (
        "notimplementederror",
        "todo",
        "pass",
        "stub",
        "incomplete",
    )
    unsafe_objective_patterns: tuple[str, ...] = (
        "bypass",
        "disable policy",
        "ignore policy",
        "skip tests",
        "hide evidence",
        "secret",
        "credential",
        "token",
    )
    governance_path_patterns: tuple[str, ...] = (
        "policy",
        "approval",
        "acceptance",
        "validator",
        "receipt",
        "workspace",
        "control_plane",
        "manifest",
    )
    test_path_patterns: tuple[str, ...] = (
        "tests/",
        "/tests/",
        "test_",
    )

    def __post_init__(self) -> None:
        if self.minimum_authoring_confidence < 0.0 or self.minimum_authoring_confidence > 1.0:
            raise ValueError("minimum_authoring_confidence must be between 0.0 and 1.0.")

        for field_name in (
            "import_error_patterns",
            "missing_symbol_patterns",
            "syntax_error_patterns",
            "assertion_patterns",
            "type_patterns",
            "configuration_patterns",
            "incomplete_patterns",
            "unsafe_objective_patterns",
            "governance_path_patterns",
            "test_path_patterns",
        ):
            object.__setattr__(
                self,
                field_name,
                _normalize_pattern_tuple(
                    getattr(self, field_name),
                    field_name=field_name,
                ),
            )


@dataclass(frozen=True, slots=True)
class RepairHypothesisEngine:
    """
    Deterministic Wave 3 hypothesis engine.

    The engine does not generate patches. It converts objective text,
    decomposition output, context paths, and failure evidence into reviewable
    repair hypotheses that can guide later model-side or deterministic patch
    authoring.
    """

    config: RepairHypothesisEngineConfig = field(default_factory=RepairHypothesisEngineConfig)

    def generate(
        self,
        *,
        request: AuthoringRequest,
        decomposition: RepairDecompositionPlan | None = None,
    ) -> RepairHypothesisReport:
        objective_text = request.objective.summary
        evidence_text = _combined_evidence_text(request.evidence)
        target_paths = _target_paths_from_request_and_plan(request, decomposition)
        evidence_ids = tuple(item.evidence_id for item in request.evidence)
        findings: list[AuthoringFinding] = []

        candidates: list[RepairHypothesis] = []

        unsafe_hypothesis = self._unsafe_request_hypothesis(
            objective_text=objective_text,
            target_paths=target_paths,
            evidence_ids=evidence_ids,
        )
        if unsafe_hypothesis is not None:
            candidates.append(unsafe_hypothesis)

        governance_hypothesis = self._governance_hypothesis(
            objective_text=objective_text,
            target_paths=target_paths,
            evidence_ids=evidence_ids,
        )
        if governance_hypothesis is not None:
            candidates.append(governance_hypothesis)

        test_risk_hypothesis = self._test_weakening_risk_hypothesis(
            objective_text=objective_text,
            target_paths=target_paths,
            evidence_ids=evidence_ids,
        )
        if test_risk_hypothesis is not None:
            candidates.append(test_risk_hypothesis)

        evidence_hypotheses = self._evidence_driven_hypotheses(
            evidence_text=evidence_text,
            target_paths=target_paths,
            evidence_ids=evidence_ids,
        )
        candidates.extend(evidence_hypotheses)

        if not request.evidence or all(
            item.strength is AuthoringEvidenceStrength.MISSING for item in request.evidence
        ):
            findings.append(
                AuthoringFinding(
                    code="authoring.hypothesis.insufficient_evidence",
                    severity=AuthoringFindingSeverity.WARNING,
                    summary=(
                        "Hypothesis generation has no direct failure evidence; "
                        "authoring should require review or stop before patch generation."
                    ),
                    metadata={"objective_id": request.objective.objective_id},
                )
            )
            candidates.append(
                RepairHypothesis.create(
                    failure_class=RepairFailureClass.INSUFFICIENT_EVIDENCE,
                    summary=(
                        "No direct repair evidence is available. The safest hypothesis "
                        "is insufficient evidence rather than a specific code defect."
                    ),
                    expected_repair_shape=RepairShape.REQUIRE_HUMAN_REVIEW,
                    confidence=0.75,
                    risk_level=AuthoringRiskLevel.MODERATE,
                    target_paths=target_paths,
                    evidence_ids=evidence_ids,
                    validation_expectations=(
                        "Collect direct failing test evidence before executing an authored patch.",
                        "Require human review for objective-only repair authoring.",
                    ),
                    findings=(
                        AuthoringFinding(
                            code="authoring.hypothesis.no_direct_evidence",
                            severity=AuthoringFindingSeverity.WARNING,
                            summary="No direct failure evidence supports a concrete patch hypothesis.",
                        ),
                    ),
                )
            )

        if not candidates:
            candidates.append(
                RepairHypothesis.create(
                    failure_class=RepairFailureClass.UNKNOWN,
                    summary=(
                        "The evidence did not match a known deterministic failure class. "
                        "Treat the repair as unknown and require review before patch authoring."
                    ),
                    expected_repair_shape=RepairShape.UNKNOWN,
                    confidence=0.25,
                    risk_level=AuthoringRiskLevel.MODERATE,
                    target_paths=target_paths,
                    evidence_ids=evidence_ids,
                    validation_expectations=(
                        "Inspect evidence manually.",
                        "Run targeted allowlisted tests after any candidate patch.",
                    ),
                    findings=(
                        AuthoringFinding(
                            code="authoring.hypothesis.unknown_failure_class",
                            severity=AuthoringFindingSeverity.WARNING,
                            summary="No deterministic failure class matched the available evidence.",
                        ),
                    ),
                )
            )

        ranked = self._rank_hypotheses(candidates)
        selected = ranked[0]

        if selected.confidence < self.config.minimum_authoring_confidence:
            findings.append(
                AuthoringFinding(
                    code="authoring.hypothesis.low_confidence_selection",
                    severity=AuthoringFindingSeverity.WARNING,
                    summary=(
                        "Selected repair hypothesis confidence is below the "
                        "minimum authoring confidence threshold."
                    ),
                    metadata={
                        "selected_hypothesis_id": selected.hypothesis_id,
                        "confidence": selected.confidence,
                        "minimum_authoring_confidence": self.config.minimum_authoring_confidence,
                    },
                )
            )

        findings.extend(_report_findings_from_hypotheses(ranked))

        return RepairHypothesisReport(
            report_id=f"repair-hypothesis-report-{uuid4().hex}",
            request_id=request.request_id,
            objective_id=request.objective.objective_id,
            plan_id=None if decomposition is None else decomposition.plan_id,
            hypotheses=ranked,
            selected_hypothesis_id=selected.hypothesis_id,
            findings=_dedupe_findings(findings),
            metadata={
                "engine": "RepairHypothesisEngine",
                "hypothesis_count": len(ranked),
                "target_path_count": len(target_paths),
                "evidence_count": len(request.evidence),
                "minimum_authoring_confidence": self.config.minimum_authoring_confidence,
            },
        )

    def _unsafe_request_hypothesis(
        self,
        *,
        objective_text: str,
        target_paths: tuple[str, ...],
        evidence_ids: tuple[str, ...],
    ) -> RepairHypothesis | None:
        lowered = objective_text.lower()
        matches = _matching_patterns(lowered, self.config.unsafe_objective_patterns)
        if not matches:
            return None

        return RepairHypothesis.create(
            failure_class=RepairFailureClass.UNSAFE_REQUEST,
            summary=(
                "The objective contains unsafe governance-bypass or secret-related "
                f"language: {', '.join(matches)}."
            ),
            expected_repair_shape=RepairShape.DO_NOT_AUTHOR_PATCH,
            confidence=0.95,
            risk_level=AuthoringRiskLevel.CRITICAL,
            target_paths=target_paths,
            evidence_ids=evidence_ids,
            validation_expectations=(
                "Do not author a patch for unsafe objective language.",
                "Require operator clarification and human review.",
            ),
            findings=(
                AuthoringFinding(
                    code="authoring.hypothesis.unsafe_objective",
                    severity=AuthoringFindingSeverity.ERROR,
                    summary="Objective contains unsafe authoring language.",
                    metadata={"matches": list(matches)},
                ),
            ),
            metadata={"matches": list(matches)},
        )

    def _governance_hypothesis(
        self,
        *,
        objective_text: str,
        target_paths: tuple[str, ...],
        evidence_ids: tuple[str, ...],
    ) -> RepairHypothesis | None:
        governance_paths = tuple(
            path for path in target_paths if self._is_governance_path(path)
        )
        objective_matches = _matching_patterns(
            objective_text.lower(),
            self.config.governance_path_patterns,
        )

        if not governance_paths and not objective_matches:
            return None

        return RepairHypothesis.create(
            failure_class=RepairFailureClass.POLICY_OR_GOVERNANCE_RISK,
            summary=(
                "The repair appears to touch governance-sensitive code or language. "
                "Mutation should require explicit human review."
            ),
            expected_repair_shape=RepairShape.REQUIRE_HUMAN_REVIEW,
            confidence=0.82,
            risk_level=AuthoringRiskLevel.HIGH,
            target_paths=governance_paths or target_paths,
            evidence_ids=evidence_ids,
            validation_expectations=(
                "Require review before any governance-sensitive mutation.",
                "Verify policy, receipt, workspace, and acceptance behavior did not weaken.",
            ),
            findings=(
                AuthoringFinding(
                    code="authoring.hypothesis.governance_risk",
                    severity=AuthoringFindingSeverity.ERROR,
                    summary="Hypothesis touches governance-sensitive scope.",
                    metadata={
                        "governance_paths": list(governance_paths),
                        "objective_matches": list(objective_matches),
                    },
                ),
            ),
            metadata={
                "governance_paths": list(governance_paths),
                "objective_matches": list(objective_matches),
            },
        )

    def _test_weakening_risk_hypothesis(
        self,
        *,
        objective_text: str,
        target_paths: tuple[str, ...],
        evidence_ids: tuple[str, ...],
    ) -> RepairHypothesis | None:
        test_paths = tuple(path for path in target_paths if self._is_test_path(path))
        lowered = objective_text.lower()
        suspicious_objective = any(
            phrase in lowered
            for phrase in (
                "skip test",
                "skip tests",
                "delete test",
                "remove test",
                "weaken test",
                "make test pass",
            )
        )

        if not test_paths and not suspicious_objective:
            return None

        return RepairHypothesis.create(
            failure_class=RepairFailureClass.TEST_WEAKENING_RISK,
            summary=(
                "The likely target set includes tests or the objective suggests "
                "test mutation. Generated changes must not weaken verification."
            ),
            expected_repair_shape=RepairShape.REQUIRE_HUMAN_REVIEW,
            confidence=0.7,
            risk_level=AuthoringRiskLevel.MODERATE,
            target_paths=test_paths or target_paths,
            evidence_ids=evidence_ids,
            validation_expectations=(
                "Require review for test-file mutation.",
                "Reject assertion deletion, skip insertion, or weaker expected behavior unless explicitly justified.",
            ),
            findings=(
                AuthoringFinding(
                    code="authoring.hypothesis.test_weakening_risk",
                    severity=AuthoringFindingSeverity.WARNING,
                    summary="Repair scope includes test weakening risk.",
                    metadata={
                        "test_paths": list(test_paths),
                        "suspicious_objective": suspicious_objective,
                    },
                ),
            ),
            metadata={
                "test_paths": list(test_paths),
                "suspicious_objective": suspicious_objective,
            },
        )

    def _evidence_driven_hypotheses(
        self,
        *,
        evidence_text: str,
        target_paths: tuple[str, ...],
        evidence_ids: tuple[str, ...],
    ) -> tuple[RepairHypothesis, ...]:
        lowered = evidence_text.lower()
        if not lowered.strip():
            return ()

        hypotheses: list[RepairHypothesis] = []

        if _matches_any(lowered, self.config.import_error_patterns):
            hypotheses.append(
                RepairHypothesis.create(
                    failure_class=RepairFailureClass.IMPORT_ERROR,
                    summary=(
                        "Failure evidence matches import error patterns. The likely "
                        "repair is adding or correcting an import, module path, or package export."
                    ),
                    expected_repair_shape=RepairShape.ADD_MISSING_IMPORT_OR_MODULE,
                    confidence=0.86,
                    risk_level=AuthoringRiskLevel.LOW,
                    target_paths=target_paths,
                    evidence_ids=evidence_ids,
                    validation_expectations=(
                        "Import the affected module successfully.",
                        "Run failing pytest node and existing allowlisted tests.",
                    ),
                    metadata={"matched_patterns": list(_matching_patterns(lowered, self.config.import_error_patterns))},
                )
            )

        if _matches_any(lowered, self.config.missing_symbol_patterns):
            hypotheses.append(
                RepairHypothesis.create(
                    failure_class=RepairFailureClass.MISSING_SYMBOL,
                    summary=(
                        "Failure evidence matches missing-symbol patterns. The likely "
                        "repair is defining, exporting, or correcting a referenced symbol."
                    ),
                    expected_repair_shape=RepairShape.ADD_MISSING_SYMBOL,
                    confidence=0.82,
                    risk_level=AuthoringRiskLevel.LOW,
                    target_paths=target_paths,
                    evidence_ids=evidence_ids,
                    validation_expectations=(
                        "Referenced symbol exists at the expected import path.",
                        "Run targeted failing tests and relevant unit tests.",
                    ),
                    metadata={"matched_patterns": list(_matching_patterns(lowered, self.config.missing_symbol_patterns))},
                )
            )

        if _matches_any(lowered, self.config.syntax_error_patterns):
            hypotheses.append(
                RepairHypothesis.create(
                    failure_class=RepairFailureClass.SYNTAX_ERROR,
                    summary=(
                        "Failure evidence matches syntax error patterns. The likely "
                        "repair is a minimal syntax or indentation correction."
                    ),
                    expected_repair_shape=RepairShape.CORRECT_SYNTAX,
                    confidence=0.9,
                    risk_level=AuthoringRiskLevel.LOW,
                    target_paths=target_paths,
                    evidence_ids=evidence_ids,
                    validation_expectations=(
                        "Python parser accepts the changed file.",
                        "Run targeted failing tests after syntax correction.",
                    ),
                    metadata={"matched_patterns": list(_matching_patterns(lowered, self.config.syntax_error_patterns))},
                )
            )

        if _matches_any(lowered, self.config.assertion_patterns):
            hypotheses.append(
                RepairHypothesis.create(
                    failure_class=RepairFailureClass.ASSERTION_MISMATCH,
                    summary=(
                        "Failure evidence matches assertion mismatch patterns. The likely "
                        "repair is correcting implementation behavior rather than weakening tests."
                    ),
                    expected_repair_shape=RepairShape.CORRECT_LOGIC_OR_EXPECTATION,
                    confidence=0.68,
                    risk_level=AuthoringRiskLevel.MODERATE,
                    target_paths=target_paths,
                    evidence_ids=evidence_ids,
                    validation_expectations=(
                        "Prefer source behavior correction over test weakening.",
                        "Run failing pytest node and adjacent behavior tests.",
                    ),
                    metadata={"matched_patterns": list(_matching_patterns(lowered, self.config.assertion_patterns))},
                )
            )

        if _matches_any(lowered, self.config.type_patterns):
            hypotheses.append(
                RepairHypothesis.create(
                    failure_class=RepairFailureClass.TYPE_MISMATCH,
                    summary=(
                        "Failure evidence matches type/value/index handling patterns. "
                        "The likely repair is safer input, state, or boundary handling."
                    ),
                    expected_repair_shape=RepairShape.CORRECT_TYPE_HANDLING,
                    confidence=0.63,
                    risk_level=AuthoringRiskLevel.MODERATE,
                    target_paths=target_paths,
                    evidence_ids=evidence_ids,
                    validation_expectations=(
                        "Add or correct type/boundary handling in source code.",
                        "Run targeted tests and edge-case tests when available.",
                    ),
                    metadata={"matched_patterns": list(_matching_patterns(lowered, self.config.type_patterns))},
                )
            )

        if _matches_any(lowered, self.config.incomplete_patterns):
            hypotheses.append(
                RepairHypothesis.create(
                    failure_class=RepairFailureClass.INCOMPLETE_IMPLEMENTATION,
                    summary=(
                        "Failure evidence matches incomplete-implementation patterns. "
                        "The likely repair is completing a stub with minimal supported behavior."
                    ),
                    expected_repair_shape=RepairShape.COMPLETE_IMPLEMENTATION,
                    confidence=0.72,
                    risk_level=AuthoringRiskLevel.MODERATE,
                    target_paths=target_paths,
                    evidence_ids=evidence_ids,
                    validation_expectations=(
                        "Replace stub behavior with minimal implementation aligned to tests.",
                        "Run targeted tests and avoid broad refactor.",
                    ),
                    metadata={"matched_patterns": list(_matching_patterns(lowered, self.config.incomplete_patterns))},
                )
            )

        if _matches_any(lowered, self.config.configuration_patterns):
            hypotheses.append(
                RepairHypothesis.create(
                    failure_class=RepairFailureClass.CONFIGURATION_ERROR,
                    summary=(
                        "Failure evidence matches configuration-related patterns. "
                        "Configuration mutation should be reviewed before execution."
                    ),
                    expected_repair_shape=RepairShape.UPDATE_CONFIGURATION,
                    confidence=0.58,
                    risk_level=AuthoringRiskLevel.HIGH,
                    target_paths=target_paths,
                    evidence_ids=evidence_ids,
                    validation_expectations=(
                        "Require review for config or dependency mutation.",
                        "Run allowlisted validation tests after configuration change.",
                    ),
                    metadata={"matched_patterns": list(_matching_patterns(lowered, self.config.configuration_patterns))},
                )
            )

        return tuple(hypotheses)

    def _rank_hypotheses(
        self,
        hypotheses: Iterable[RepairHypothesis],
    ) -> tuple[RepairHypothesis, ...]:
        return tuple(
            sorted(
                hypotheses,
                key=lambda hypothesis: (
                    _risk_sort_score(hypothesis),
                    -hypothesis.confidence,
                    _failure_class_sort_score(hypothesis.failure_class),
                    hypothesis.summary,
                ),
            )
        )

    def _is_governance_path(self, path: str) -> bool:
        lowered = path.lower().replace("\\", "/")
        return any(pattern in lowered for pattern in self.config.governance_path_patterns)

    def _is_test_path(self, path: str) -> bool:
        lowered = path.lower().replace("\\", "/")
        return any(pattern in lowered for pattern in self.config.test_path_patterns)


def _combined_evidence_text(evidence: tuple[AuthoringEvidence, ...]) -> str:
    parts: list[str] = []

    for item in evidence:
        parts.append(item.summary)
        parts.extend(finding.summary for finding in item.findings)
        parts.extend(str(value) for value in item.metadata.values() if isinstance(value, str))

    return "\n".join(parts)


def _target_paths_from_request_and_plan(
    request: AuthoringRequest,
    decomposition: RepairDecompositionPlan | None,
) -> tuple[str, ...]:
    paths: list[str] = []
    seen: set[str] = set()

    if decomposition is not None:
        for path in decomposition.target_paths:
            if path not in seen:
                seen.add(path)
                paths.append(path)

    for evidence in request.evidence:
        for path in evidence.related_paths:
            if path not in seen:
                seen.add(path)
                paths.append(path)

    if request.context is not None:
        for path in request.context.paths:
            if path not in seen:
                seen.add(path)
                paths.append(path)

    return tuple(paths)


def _report_findings_from_hypotheses(
    hypotheses: Iterable[RepairHypothesis],
) -> tuple[AuthoringFinding, ...]:
    findings: list[AuthoringFinding] = []

    for hypothesis in hypotheses:
        if hypothesis.confidence < 0.35:
            findings.append(
                AuthoringFinding(
                    code="authoring.hypothesis.very_low_confidence",
                    severity=AuthoringFindingSeverity.WARNING,
                    summary=(
                        "A generated repair hypothesis has very low confidence "
                        "and should not drive patch authoring without review."
                    ),
                    metadata={
                        "hypothesis_id": hypothesis.hypothesis_id,
                        "confidence": hypothesis.confidence,
                    },
                )
            )

        if hypothesis.requires_review:
            findings.append(
                AuthoringFinding(
                    code="authoring.hypothesis.review_required",
                    severity=AuthoringFindingSeverity.WARNING,
                    summary="A generated repair hypothesis requires human review.",
                    metadata={
                        "hypothesis_id": hypothesis.hypothesis_id,
                        "failure_class": hypothesis.failure_class.value,
                        "risk_level": hypothesis.risk_level.value,
                    },
                )
            )

    return tuple(findings)


def _risk_sort_score(hypothesis: RepairHypothesis) -> int:
    if hypothesis.failure_class is RepairFailureClass.UNSAFE_REQUEST:
        return 0
    if hypothesis.failure_class is RepairFailureClass.POLICY_OR_GOVERNANCE_RISK:
        return 1
    if hypothesis.failure_class is RepairFailureClass.TEST_WEAKENING_RISK:
        return 2
    if hypothesis.failure_class is RepairFailureClass.INSUFFICIENT_EVIDENCE:
        return 50
    if hypothesis.failure_class is RepairFailureClass.UNKNOWN:
        return 60
    return 10


def _failure_class_sort_score(failure_class: RepairFailureClass) -> int:
    order = {
        RepairFailureClass.SYNTAX_ERROR: 0,
        RepairFailureClass.IMPORT_ERROR: 1,
        RepairFailureClass.MISSING_SYMBOL: 2,
        RepairFailureClass.INCOMPLETE_IMPLEMENTATION: 3,
        RepairFailureClass.ASSERTION_MISMATCH: 4,
        RepairFailureClass.TYPE_MISMATCH: 5,
        RepairFailureClass.CONFIGURATION_ERROR: 6,
        RepairFailureClass.TEST_WEAKENING_RISK: 7,
        RepairFailureClass.POLICY_OR_GOVERNANCE_RISK: 8,
        RepairFailureClass.UNSAFE_REQUEST: 9,
        RepairFailureClass.INSUFFICIENT_EVIDENCE: 10,
        RepairFailureClass.UNKNOWN: 11,
    }
    return order[failure_class]


def _matches_any(text: str, patterns: tuple[str, ...]) -> bool:
    return bool(_matching_patterns(text, patterns))


def _matching_patterns(text: str, patterns: tuple[str, ...]) -> tuple[str, ...]:
    lowered = text.lower()
    matches: list[str] = []
    for pattern in patterns:
        if pattern in lowered:
            matches.append(pattern)
    return tuple(matches)


def _load_hypotheses(value: Any) -> tuple[RepairHypothesis, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError("hypotheses must be an iterable of mappings.")

    hypotheses: list[RepairHypothesis] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise TypeError("hypotheses must contain only mappings.")
        hypotheses.append(RepairHypothesis.from_dict(item))
    return tuple(hypotheses)


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


def _normalize_pattern_tuple(values: Iterable[str], *, field_name: str) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise TypeError(f"{field_name} must contain only strings.")
        cleaned = value.strip().lower()
        if not cleaned:
            raise ValueError(f"{field_name} must not contain empty values.")
        normalized.append(cleaned)
    return tuple(normalized)


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


def _normalize_optional_identifier(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    return _normalize_identifier(value, label=label)


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty.")
    return cleaned


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


def _coerce_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")
    return dict(value)


def _coerce_text_tuple(value: Any, *, field_name: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError(f"{field_name} must be an iterable of strings.")

    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"{field_name} must contain only strings.")
        result.append(item)
    return tuple(result)


def _require_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string.")
    return value


def _require_float(payload: Mapping[str, Any], key: str) -> float:
    value = payload.get(key)
    if not isinstance(value, int | float):
        raise TypeError(f"Field {key!r} must be a number.")
    return float(value)


def _optional_text_from_payload(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"Field {key!r} must be a string or None.")
    return value
