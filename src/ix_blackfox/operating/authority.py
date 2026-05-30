from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any

from ix_blackfox.operating.models import (
    OperatingArtifactKind,
    OperatingDomain,
    OperatingEnvelope,
    OperatingFinding,
    OperatingSeverity,
    normalize_identifier,
    normalize_optional_text,
    normalize_text,
    unique_sorted_enum_tuple,
)
from ix_blackfox.operating.registry import normalize_identifier_tuple


class TeamRole(StrEnum):
    """Organization roles that can hold Wave 10 review authority."""

    PLATFORM_OWNER = auto()
    SECURITY_REVIEWER = auto()
    DEVSECOPS_OPERATOR = auto()
    QA_VERIFIER = auto()
    COMPLIANCE_REVIEWER = auto()
    RELEASE_MANAGER = auto()
    INCIDENT_COMMANDER = auto()
    OBSERVER = auto()


class ReviewerKind(StrEnum):
    """Reviewer actor category used to prevent model or system self-approval."""

    HUMAN = auto()
    SYSTEM = auto()
    MODEL = auto()


class ReviewDecision(StrEnum):
    """Team review decision captured by the Wave 10 operating layer."""

    APPROVED = auto()
    CHANGES_REQUESTED = auto()
    REJECTED = auto()
    COMMENTED = auto()


@dataclass(frozen=True, slots=True)
class OperatingTeam:
    """Team that owns repositories, evidence duties, or operating authority."""

    team_id: str
    name: str
    roles: tuple[TeamRole, ...]
    owned_repository_ids: tuple[str, ...] = ()
    description: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "team_id", normalize_identifier(self.team_id, label="team_id"))
        object.__setattr__(self, "name", normalize_text(self.name, label="name"))
        if not self.roles:
            raise ValueError("OperatingTeam roles must not be empty.")
        object.__setattr__(self, "roles", unique_sorted_enum_tuple(self.roles))
        object.__setattr__(
            self,
            "owned_repository_ids",
            normalize_identifier_tuple(self.owned_repository_ids, label="owned_repository_ids"),
        )
        object.__setattr__(
            self,
            "description",
            normalize_optional_text(self.description, label="description"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "team_id": self.team_id,
            "name": self.name,
            "roles": [role.value for role in self.roles],
            "owned_repository_ids": list(self.owned_repository_ids),
            "description": self.description,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ReviewerAuthority:
    """Bounded review authority granted to one actor inside a team."""

    reviewer_id: str
    reviewer_kind: ReviewerKind
    team_id: str
    roles: tuple[TeamRole, ...]
    approved_repository_ids: tuple[str, ...]
    approved_domains: tuple[OperatingDomain, ...]
    active: bool = True
    delegated_by: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "reviewer_id",
            normalize_identifier(self.reviewer_id, label="reviewer_id"),
        )
        object.__setattr__(self, "team_id", normalize_identifier(self.team_id, label="team_id"))
        if not self.roles:
            raise ValueError("ReviewerAuthority roles must not be empty.")
        if not self.approved_repository_ids:
            raise ValueError("ReviewerAuthority approved_repository_ids must not be empty.")
        if not self.approved_domains:
            raise ValueError("ReviewerAuthority approved_domains must not be empty.")
        object.__setattr__(self, "roles", unique_sorted_enum_tuple(self.roles))
        object.__setattr__(
            self,
            "approved_repository_ids",
            normalize_identifier_tuple(
                self.approved_repository_ids,
                label="approved_repository_ids",
            ),
        )
        object.__setattr__(self, "approved_domains", unique_sorted_enum_tuple(self.approved_domains))
        object.__setattr__(
            self,
            "delegated_by",
            normalize_optional_text(self.delegated_by, label="delegated_by"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def can_issue_authoritative_approval(self) -> bool:
        return self.active and self.reviewer_kind is ReviewerKind.HUMAN

    def covers_repository(self, repository_id: str) -> bool:
        normalized = normalize_identifier(repository_id, label="repository_id")
        return normalized in self.approved_repository_ids

    def covers_domain(self, domain: OperatingDomain) -> bool:
        return domain in self.approved_domains

    def can_review(self, repository_id: str, domains: Sequence[OperatingDomain]) -> bool:
        return self.covers_repository(repository_id) and all(
            self.covers_domain(domain) for domain in domains
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "reviewer_id": self.reviewer_id,
            "reviewer_kind": self.reviewer_kind.value,
            "team_id": self.team_id,
            "roles": [role.value for role in self.roles],
            "approved_repository_ids": list(self.approved_repository_ids),
            "approved_domains": [domain.value for domain in self.approved_domains],
            "active": self.active,
            "delegated_by": self.delegated_by,
            "can_issue_authoritative_approval": self.can_issue_authoritative_approval,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ApprovalQuorum:
    """Minimum approval rule for one review scope."""

    quorum_id: str
    repository_ids: tuple[str, ...]
    domains: tuple[OperatingDomain, ...]
    required_roles: tuple[TeamRole, ...]
    minimum_approvals: int = 1
    required_human_approvals: int = 1
    required_distinct_teams: int = 1
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "quorum_id", normalize_identifier(self.quorum_id, label="quorum_id"))
        if not self.repository_ids:
            raise ValueError("ApprovalQuorum repository_ids must not be empty.")
        if not self.domains:
            raise ValueError("ApprovalQuorum domains must not be empty.")
        if not self.required_roles:
            raise ValueError("ApprovalQuorum required_roles must not be empty.")
        if self.minimum_approvals <= 0:
            raise ValueError("minimum_approvals must be greater than zero.")
        if self.required_human_approvals <= 0:
            raise ValueError("required_human_approvals must be greater than zero.")
        if self.required_human_approvals > self.minimum_approvals:
            raise ValueError("required_human_approvals cannot exceed minimum_approvals.")
        if self.required_distinct_teams <= 0:
            raise ValueError("required_distinct_teams must be greater than zero.")
        if self.required_distinct_teams > self.minimum_approvals:
            raise ValueError("required_distinct_teams cannot exceed minimum_approvals.")
        object.__setattr__(
            self,
            "repository_ids",
            normalize_identifier_tuple(self.repository_ids, label="repository_ids"),
        )
        object.__setattr__(self, "domains", unique_sorted_enum_tuple(self.domains))
        object.__setattr__(self, "required_roles", unique_sorted_enum_tuple(self.required_roles))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def applies_to(self, repository_ids: Sequence[str], domains: Sequence[OperatingDomain]) -> bool:
        normalized_repositories = set(
            normalize_identifier_tuple(repository_ids, label="repository_ids")
        )
        decision_domains = set(domains)
        return bool(normalized_repositories & set(self.repository_ids)) and all(
            domain in decision_domains for domain in self.domains
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "quorum_id": self.quorum_id,
            "repository_ids": list(self.repository_ids),
            "domains": [domain.value for domain in self.domains],
            "required_roles": [role.value for role in self.required_roles],
            "minimum_approvals": self.minimum_approvals,
            "required_human_approvals": self.required_human_approvals,
            "required_distinct_teams": self.required_distinct_teams,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class SeparationOfDutiesRule:
    """Fail-closed rule preventing one actor from authoring and approving the same work."""

    rule_id: str
    forbid_author_approval: bool = True
    forbid_model_approval: bool = True
    forbid_system_approval: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "rule_id", normalize_identifier(self.rule_id, label="rule_id"))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "forbid_author_approval": self.forbid_author_approval,
            "forbid_model_approval": self.forbid_model_approval,
            "forbid_system_approval": self.forbid_system_approval,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class TeamReviewDecision:
    """Review decision bound to repositories, domains, subject, and evidence."""

    decision_id: str
    reviewer_id: str
    decision: ReviewDecision
    repository_ids: tuple[str, ...]
    domains: tuple[OperatingDomain, ...]
    subject_id: str
    subject_author_id: str
    evidence_artifact_ids: tuple[str, ...] = ()
    rationale: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "decision_id",
            normalize_identifier(self.decision_id, label="decision_id"),
        )
        object.__setattr__(
            self,
            "reviewer_id",
            normalize_identifier(self.reviewer_id, label="reviewer_id"),
        )
        if not self.repository_ids:
            raise ValueError("TeamReviewDecision repository_ids must not be empty.")
        if not self.domains:
            raise ValueError("TeamReviewDecision domains must not be empty.")
        object.__setattr__(
            self,
            "repository_ids",
            normalize_identifier_tuple(self.repository_ids, label="repository_ids"),
        )
        object.__setattr__(self, "domains", unique_sorted_enum_tuple(self.domains))
        object.__setattr__(self, "subject_id", normalize_identifier(self.subject_id, label="subject_id"))
        object.__setattr__(
            self,
            "subject_author_id",
            normalize_identifier(self.subject_author_id, label="subject_author_id"),
        )
        object.__setattr__(
            self,
            "evidence_artifact_ids",
            normalize_identifier_tuple(
                self.evidence_artifact_ids,
                label="evidence_artifact_ids",
            ),
        )
        object.__setattr__(
            self,
            "rationale",
            normalize_optional_text(self.rationale, label="rationale"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def is_approval(self) -> bool:
        return self.decision is ReviewDecision.APPROVED

    @property
    def self_approval_attempt(self) -> bool:
        return self.is_approval and self.reviewer_id == self.subject_author_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "reviewer_id": self.reviewer_id,
            "decision": self.decision.value,
            "repository_ids": list(self.repository_ids),
            "domains": [domain.value for domain in self.domains],
            "subject_id": self.subject_id,
            "subject_author_id": self.subject_author_id,
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "rationale": self.rationale,
            "self_approval_attempt": self.self_approval_attempt,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ReviewBoard:
    """Deterministic multi-team authority board for Wave 10 operating gates."""

    board_id: str
    teams: tuple[OperatingTeam, ...]
    reviewer_authorities: tuple[ReviewerAuthority, ...]
    quorums: tuple[ApprovalQuorum, ...]
    decisions: tuple[TeamReviewDecision, ...] = ()
    separation_rules: tuple[SeparationOfDutiesRule, ...] = (
        SeparationOfDutiesRule(rule_id="default-separation-of-duties"),
    )
    generated_by: str = "IX-BlackFox Wave 10 review board"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "board_id", normalize_identifier(self.board_id, label="board_id"))
        if not self.teams:
            raise ValueError("ReviewBoard teams must not be empty.")
        if not self.reviewer_authorities:
            raise ValueError("ReviewBoard reviewer_authorities must not be empty.")
        if not self.quorums:
            raise ValueError("ReviewBoard quorums must not be empty.")
        teams = tuple(sorted(self.teams, key=lambda team: team.team_id))
        team_ids = [team.team_id for team in teams]
        if len(team_ids) != len(set(team_ids)):
            raise ValueError("ReviewBoard team_id values must be unique.")
        object.__setattr__(self, "teams", teams)
        authorities = tuple(sorted(self.reviewer_authorities, key=lambda item: item.reviewer_id))
        reviewer_ids = [authority.reviewer_id for authority in authorities]
        if len(reviewer_ids) != len(set(reviewer_ids)):
            raise ValueError("ReviewBoard reviewer_id values must be unique.")
        unknown_authority_teams = {authority.team_id for authority in authorities} - set(team_ids)
        if unknown_authority_teams:
            unknown = ", ".join(sorted(unknown_authority_teams))
            raise ValueError(f"reviewer authority references unknown team: {unknown}")
        object.__setattr__(self, "reviewer_authorities", authorities)
        quorums = tuple(sorted(self.quorums, key=lambda quorum: quorum.quorum_id))
        quorum_ids = [quorum.quorum_id for quorum in quorums]
        if len(quorum_ids) != len(set(quorum_ids)):
            raise ValueError("ReviewBoard quorum_id values must be unique.")
        object.__setattr__(self, "quorums", quorums)
        decisions = tuple(sorted(self.decisions, key=lambda decision: decision.decision_id))
        decision_ids = [decision.decision_id for decision in decisions]
        if len(decision_ids) != len(set(decision_ids)):
            raise ValueError("ReviewBoard decision_id values must be unique.")
        unknown_decision_reviewers = {decision.reviewer_id for decision in decisions} - set(reviewer_ids)
        if unknown_decision_reviewers:
            unknown = ", ".join(sorted(unknown_decision_reviewers))
            raise ValueError(f"review decision references unknown reviewer: {unknown}")
        object.__setattr__(self, "decisions", decisions)
        rules = tuple(sorted(self.separation_rules, key=lambda rule: rule.rule_id))
        rule_ids = [rule.rule_id for rule in rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("ReviewBoard separation rule_id values must be unique.")
        object.__setattr__(self, "separation_rules", rules)
        object.__setattr__(
            self,
            "generated_by",
            normalize_text(self.generated_by, label="generated_by"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def team_ids(self) -> tuple[str, ...]:
        return tuple(team.team_id for team in self.teams)

    @property
    def reviewer_ids(self) -> tuple[str, ...]:
        return tuple(authority.reviewer_id for authority in self.reviewer_authorities)

    @property
    def authoritative_approval_count(self) -> int:
        return len(self.authoritative_approvals())

    @property
    def findings(self) -> tuple[OperatingFinding, ...]:
        findings = [*self._decision_findings(), *self._quorum_findings()]
        return tuple(sorted(findings, key=lambda finding: (finding.code, finding.summary)))

    @property
    def disposition(self) -> str:
        return self.to_envelope().disposition.value

    def authority_for(self, reviewer_id: str) -> ReviewerAuthority:
        normalized = normalize_identifier(reviewer_id, label="reviewer_id")
        for authority in self.reviewer_authorities:
            if authority.reviewer_id == normalized:
                return authority
        raise KeyError(f"unknown reviewer_id: {normalized}")

    def authoritative_approvals(
        self,
        *,
        repository_id: str | None = None,
        domains: Sequence[OperatingDomain] = (),
    ) -> tuple[TeamReviewDecision, ...]:
        approvals: list[TeamReviewDecision] = []
        for decision in self.decisions:
            if not decision.is_approval:
                continue
            authority = self.authority_for(decision.reviewer_id)
            if not self._decision_is_authoritative(decision=decision, authority=authority):
                continue
            if repository_id is not None:
                normalized_repository_id = normalize_identifier(repository_id, label="repository_id")
                if normalized_repository_id not in decision.repository_ids:
                    continue
            if domains and not all(domain in decision.domains for domain in domains):
                continue
            approvals.append(decision)
        return tuple(sorted(approvals, key=lambda decision: decision.decision_id))

    def to_envelope(self) -> OperatingEnvelope:
        return OperatingEnvelope(
            envelope_id=f"{self.board_id}-team-authority-envelope",
            artifact_kind=OperatingArtifactKind.TEAM_AUTHORITY,
            subject=f"Wave 10 team authority board {self.board_id}",
            domains=(OperatingDomain.MULTI_TEAM, OperatingDomain.REVIEWABLE),
            findings=self.findings,
            metadata={
                "board_id": self.board_id,
                "team_ids": list(self.team_ids),
                "reviewer_ids": list(self.reviewer_ids),
                "quorum_ids": [quorum.quorum_id for quorum in self.quorums],
                "authoritative_approval_count": self.authoritative_approval_count,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        envelope = self.to_envelope()
        return {
            "board_id": self.board_id,
            "generated_by": self.generated_by,
            "teams": [team.to_dict() for team in self.teams],
            "reviewer_authorities": [authority.to_dict() for authority in self.reviewer_authorities],
            "quorums": [quorum.to_dict() for quorum in self.quorums],
            "decisions": [decision.to_dict() for decision in self.decisions],
            "separation_rules": [rule.to_dict() for rule in self.separation_rules],
            "team_count": len(self.teams),
            "reviewer_count": len(self.reviewer_authorities),
            "decision_count": len(self.decisions),
            "authoritative_approval_count": self.authoritative_approval_count,
            "findings": [finding.to_dict() for finding in self.findings],
            "disposition": envelope.disposition.value,
            "digest": envelope.digest,
            "metadata": dict(self.metadata),
        }

    def _decision_findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []
        for decision in self.decisions:
            authority = self.authority_for(decision.reviewer_id)
            if decision.self_approval_attempt and self._forbid_author_approval:
                findings.append(
                    self._decision_finding(
                        decision=decision,
                        code="operating.authority.self-approval-attempt",
                        severity=OperatingSeverity.CRITICAL,
                        summary=(
                            f"Reviewer {decision.reviewer_id} attempted to approve "
                            f"their own subject {decision.subject_id}."
                        ),
                    )
                )
            if decision.is_approval and not authority.active:
                findings.append(
                    self._decision_finding(
                        decision=decision,
                        code="operating.authority.inactive-reviewer-approval",
                        severity=OperatingSeverity.CRITICAL,
                        summary=f"Inactive reviewer {decision.reviewer_id} attempted approval.",
                    )
                )
            if (
                decision.is_approval
                and authority.reviewer_kind is ReviewerKind.MODEL
                and self._forbid_model_approval
            ):
                findings.append(
                    self._decision_finding(
                        decision=decision,
                        code="operating.authority.model-approval-attempt",
                        severity=OperatingSeverity.CRITICAL,
                        summary="A model reviewer attempted to issue approval authority.",
                    )
                )
            if (
                decision.is_approval
                and authority.reviewer_kind is ReviewerKind.SYSTEM
                and self._forbid_system_approval
            ):
                findings.append(
                    self._decision_finding(
                        decision=decision,
                        code="operating.authority.system-approval-attempt",
                        severity=OperatingSeverity.CRITICAL,
                        summary="A system reviewer attempted to issue approval authority.",
                    )
                )
            if decision.is_approval and not self._authority_covers_decision(authority, decision):
                findings.append(
                    self._decision_finding(
                        decision=decision,
                        code="operating.authority.out-of-scope-approval",
                        severity=OperatingSeverity.HIGH,
                        summary=(
                            f"Reviewer {decision.reviewer_id} approved outside their "
                            "repository or domain authority."
                        ),
                    )
                )
            if decision.is_approval and not decision.evidence_artifact_ids:
                findings.append(
                    self._decision_finding(
                        decision=decision,
                        code="operating.authority.approval-missing-evidence",
                        severity=OperatingSeverity.HIGH,
                        summary=f"Approval {decision.decision_id} is not bound to evidence artifacts.",
                    )
                )
        return tuple(findings)

    def _quorum_findings(self) -> tuple[OperatingFinding, ...]:
        findings: list[OperatingFinding] = []
        for quorum in self.quorums:
            approvals = self._approvals_for_quorum(quorum)
            if len(approvals) < quorum.minimum_approvals:
                findings.append(
                    self._quorum_finding(
                        quorum=quorum,
                        code="operating.authority.quorum-minimum-not-met",
                        severity=OperatingSeverity.CRITICAL,
                        summary=(
                            f"Quorum {quorum.quorum_id} requires "
                            f"{quorum.minimum_approvals} authoritative approvals but has {len(approvals)}."
                        ),
                    )
                )
            human_approvals = [
                decision
                for decision in approvals
                if self.authority_for(decision.reviewer_id).reviewer_kind is ReviewerKind.HUMAN
            ]
            if len(human_approvals) < quorum.required_human_approvals:
                findings.append(
                    self._quorum_finding(
                        quorum=quorum,
                        code="operating.authority.quorum-human-approval-not-met",
                        severity=OperatingSeverity.CRITICAL,
                        summary=(
                            f"Quorum {quorum.quorum_id} requires "
                            f"{quorum.required_human_approvals} human approvals but has "
                            f"{len(human_approvals)}."
                        ),
                    )
                )
            distinct_teams = {self.authority_for(decision.reviewer_id).team_id for decision in approvals}
            if len(distinct_teams) < quorum.required_distinct_teams:
                findings.append(
                    self._quorum_finding(
                        quorum=quorum,
                        code="operating.authority.quorum-distinct-team-not-met",
                        severity=OperatingSeverity.HIGH,
                        summary=(
                            f"Quorum {quorum.quorum_id} requires approvals from "
                            f"{quorum.required_distinct_teams} distinct teams but has "
                            f"{len(distinct_teams)}."
                        ),
                    )
                )
            covered_roles = {
                role
                for decision in approvals
                for role in self.authority_for(decision.reviewer_id).roles
            }
            missing_roles = tuple(role for role in quorum.required_roles if role not in covered_roles)
            if missing_roles:
                findings.append(
                    self._quorum_finding(
                        quorum=quorum,
                        code="operating.authority.quorum-required-role-not-met",
                        severity=OperatingSeverity.HIGH,
                        summary=(
                            f"Quorum {quorum.quorum_id} is missing required roles: "
                            f"{', '.join(role.value for role in missing_roles)}."
                        ),
                    )
                )
        return tuple(findings)

    @property
    def _forbid_author_approval(self) -> bool:
        return any(rule.forbid_author_approval for rule in self.separation_rules)

    @property
    def _forbid_model_approval(self) -> bool:
        return any(rule.forbid_model_approval for rule in self.separation_rules)

    @property
    def _forbid_system_approval(self) -> bool:
        return any(rule.forbid_system_approval for rule in self.separation_rules)

    def _approvals_for_quorum(self, quorum: ApprovalQuorum) -> tuple[TeamReviewDecision, ...]:
        approvals: list[TeamReviewDecision] = []
        for decision in self.decisions:
            if not decision.is_approval:
                continue
            if not quorum.applies_to(decision.repository_ids, decision.domains):
                continue
            authority = self.authority_for(decision.reviewer_id)
            if self._decision_is_authoritative(decision=decision, authority=authority):
                approvals.append(decision)
        return tuple(sorted(approvals, key=lambda decision: decision.decision_id))

    def _decision_is_authoritative(
        self,
        *,
        decision: TeamReviewDecision,
        authority: ReviewerAuthority,
    ) -> bool:
        return (
            decision.is_approval
            and authority.can_issue_authoritative_approval
            and not (decision.self_approval_attempt and self._forbid_author_approval)
            and self._authority_covers_decision(authority, decision)
            and bool(decision.evidence_artifact_ids)
        )

    def _authority_covers_decision(
        self,
        authority: ReviewerAuthority,
        decision: TeamReviewDecision,
    ) -> bool:
        return all(
            authority.covers_repository(repository_id) for repository_id in decision.repository_ids
        ) and all(authority.covers_domain(domain) for domain in decision.domains)

    def _decision_finding(
        self,
        *,
        decision: TeamReviewDecision,
        code: str,
        severity: OperatingSeverity,
        summary: str,
    ) -> OperatingFinding:
        return OperatingFinding(
            code=code,
            severity=severity,
            summary=summary,
            domains=(OperatingDomain.MULTI_TEAM, OperatingDomain.REVIEWABLE),
            blocking=True,
            metadata={
                "board_id": self.board_id,
                "decision_id": decision.decision_id,
                "reviewer_id": decision.reviewer_id,
                "subject_id": decision.subject_id,
            },
        )

    def _quorum_finding(
        self,
        *,
        quorum: ApprovalQuorum,
        code: str,
        severity: OperatingSeverity,
        summary: str,
    ) -> OperatingFinding:
        return OperatingFinding(
            code=code,
            severity=severity,
            summary=summary,
            domains=(OperatingDomain.MULTI_TEAM, OperatingDomain.REVIEWABLE),
            blocking=True,
            metadata={
                "board_id": self.board_id,
                "quorum_id": quorum.quorum_id,
                "repository_ids": list(quorum.repository_ids),
                "domains": [domain.value for domain in quorum.domains],
            },
        )
