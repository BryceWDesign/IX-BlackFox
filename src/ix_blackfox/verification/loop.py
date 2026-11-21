from __future__ import annotations

import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from ix_blackfox.authority_crypto.encoding import (
    AuthorityProofError,
    canonical_bytes,
    digest,
)
from ix_blackfox.authority_crypto.signing import SigningController
from ix_blackfox.authority_crypto.trust import TrustPolicy
from ix_blackfox.autonomy.contracts import (
    OperationError,
    identifier,
    integer,
    text,
    timestamp,
)
from ix_blackfox.verification.contracts import (
    CONTRACT,
    MAX_CHAIN,
    parse_contract,
    trust_binding,
)
from ix_blackfox.verification.proof import (
    BUNDLE,
    CLOSURE_TYPE,
    authorization,
    evaluate,
    evidence_target,
    scope,
    semantic_result,
    verify_bundle,
    verify_evidence,
)

if TYPE_CHECKING:
    from ix_blackfox.autonomy.coordinator import OperationCoordinator
    from ix_blackfox.live_gateway.service import LiveAuthorityGateway

PROPOSALS = {"propose-verification", "propose-followup"}
READ_ACTIONS = {
    "verification-assess",
    "verification-target",
    "verification-chain",
    "verification-export",
}
ACTIONS = READ_ACTIONS | {
    "verification-evidence",
    "verification-fail",
    "verification-close",
}


class VerificationLoop:
    def __init__(self, coordinator: OperationCoordinator) -> None:
        self.coordinator = coordinator
        self.store = coordinator.store

    def trust(
        self,
        gateway: LiveAuthorityGateway,
    ) -> tuple[SigningController, TrustPolicy, dict[str, TrustPolicy]]:
        signing, config = (
            gateway.receipt_store.signing,
            self.coordinator.config.verification,
        )
        if signing is None or config is None:
            raise OperationError("Closed-loop verification is not configured.", 409)
        authority = signing.current_policy()
        policies = config.policies(authority)
        now = datetime.now(UTC)
        if any(
            policy.expires_at <= now or all(key.revoked for key in policy.keys)
            for policy in policies.values()
        ):
            raise OperationError("A verification role has no usable trust policy.", 503)
        return signing, authority, policies

    def proposal(
        self,
        gateway: LiveAuthorityGateway,
        db: sqlite3.Connection,
        plan: dict[str, Any],
        proposer: str,
        action: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        _, _, policies = self.trust(gateway)
        scopes = {
            step_id: scope(
                gateway.build_subject(
                    agent_id=step["agent_id"],
                    tool_name=step["tool_name"],
                    arguments=step["arguments"],
                    protocol="blackfox-api/v1",
                ).to_dict()
            )
            for step_id, step in plan["steps"].items()
        }
        parent = None
        if action == "propose-verification":
            contract = parse_contract(payload["contract"], plan)
        else:
            parent_id = identifier(payload["parent_operation_id"])
            parent_state = self.store.load(db, parent_id)
            prior = self.state(parent_state)
            mode = payload["mode"]
            if mode not in ("rollback", "remediation"):
                raise OperationError("Follow-up mode must be rollback or remediation.")
            if (
                parent_state["closed"]
                or not prior["failure"]
                or prior["selected_followup"]
            ):
                raise OperationError(
                    "Follow-up requires an open failure without a selected response.",
                    409,
                )
            depth = 1
            ancestor = prior
            while ancestor["binding"]["parent"]:
                depth += 1
                if depth >= MAX_CHAIN:
                    raise OperationError("Maximum follow-up depth reached.", 409)
                ancestor = self.state(
                    self.store.load(db, ancestor["binding"]["parent"]["operation_id"])
                )
            self.check_policy(gateway, parent_state)
            parent_binding = prior["binding"]
            if scopes != parent_binding["scope"]:
                raise OperationError(
                    "Follow-up must retain the approved provider scopes.", 409
                )
            original = parent_binding["contract"]
            contract = parse_contract(
                {
                    "schema_version": CONTRACT,
                    "change": payload["change"],
                    "requirements": original[
                        "rollback_requirements"
                        if mode == "rollback"
                        else "requirements"
                    ],
                    "rollback_requirements": original["rollback_requirements"],
                },
                plan,
            )
            parent = {
                "operation_id": parent_id,
                "mode": mode,
                "failure_sha256": digest(prior["failure"]),
            }
        return {
            "binding": {
                "nonce": secrets.token_hex(32),
                "proposer": proposer,
                "contract": contract,
                "parent": parent,
                "scope": scopes,
                "trust_digest": trust_binding(policies),
                "max_age_seconds": self.coordinator.config.max_evidence_age_seconds,
            },
            "epoch_started": datetime.now(UTC).isoformat(),
            "approval_review": {},
            "failure": {},
            "proofs": {},
            "selected_followup": "",
            "closure": None,
        }

    @staticmethod
    def state(operation: dict[str, Any]) -> dict[str, Any]:
        if "verification" not in operation:
            raise OperationError(
                "This operation has no Wave 19 verification contract.", 409
            )
        result: dict[str, Any] = operation["verification"]
        return result

    def check_policy(
        self, gateway: LiveAuthorityGateway, operation: dict[str, Any]
    ) -> None:
        _, _, policies = self.trust(gateway)
        binding = self.state(operation)["binding"]
        if (
            binding["trust_digest"] != trust_binding(policies)
            or binding["max_age_seconds"]
            != self.coordinator.config.max_evidence_age_seconds
            or any(
                scope(
                    gateway.build_subject(
                        agent_id=step["agent_id"],
                        tool_name=step["tool_name"],
                        arguments=step["arguments"],
                        protocol="blackfox-api/v1",
                    ).to_dict()
                )
                != binding["scope"][name]
                for name, step in operation["plan"]["steps"].items()
            )
        ):
            raise OperationError(
                "The pinned verification trust, freshness, or scope changed.", 409
            )

    def approve(
        self,
        gateway: LiveAuthorityGateway,
        db: sqlite3.Connection,
        operation: dict[str, Any],
        snapshot: str,
        reviewer: str,
    ) -> None:
        self.check_policy(gateway, operation)
        state = self.state(operation)
        if state["failure"]:
            raise OperationError(
                "A failed attempt requires a separately approved follow-up.", 409
            )
        link = state["binding"]["parent"]
        if link:
            parent = self.store.load(db, link["operation_id"])
            prior = self.state(parent)
            self.check_policy(gateway, parent)
            op = operation["plan"]["operation_id"]
            if (
                parent["closed"]
                or digest(prior["failure"]) != link["failure_sha256"]
                or prior["selected_followup"] not in ("", op)
            ):
                raise OperationError(
                    "The failure already has a different response or is closed.", 409
                )
            if not prior["selected_followup"]:
                prior["selected_followup"] = op
                self.store.save(
                    db,
                    parent,
                    "verification_followup_selected",
                    operation_id=op,
                    mode=link["mode"],
                    reviewer=reviewer,
                )
        state["approval_review"] = {
            "snapshot_digest": snapshot,
            "epoch": operation["epoch"],
            "reviewer": reviewer,
            "at": datetime.now(UTC).isoformat(),
        }

    @staticmethod
    def renew(operation: dict[str, Any]) -> None:
        state = VerificationLoop.state(operation)
        if state["failure"]:
            raise OperationError(
                "Failed verification requires a separate follow-up operation.", 409
            )
        state.update(
            epoch_started=datetime.now(UTC).isoformat(), proofs={}, approval_review={}
        )

    def manifest(
        self,
        gateway: LiveAuthorityGateway,
        operation: dict[str, Any],
        *,
        step_id: str | None = None,
    ) -> dict[str, Any]:
        state = self.state(operation)
        attempts = {}
        for name, current in operation["steps"].items():
            attempt = current["attempt"]
            if (
                (step_id is not None and step_id != name)
                or attempt["phase"] == "not_attempted"
                or not attempt.get("authorization_receipt_id")
            ):
                continue
            target, _ = self.coordinator._observation_target(gateway, operation, name)
            auth_id = target.metadata["authorization_receipt_id"]
            if auth_id != attempt["authorization_receipt_id"]:
                raise AuthorityProofError(
                    "Mesh authorization differs from the retained attempt."
                )
            receipt = gateway.receipt_store.get(auth_id)
            if receipt is None:
                raise AuthorityProofError("Authorization receipt is missing.")
            attempts[name] = {
                "request_id": attempt["request_id"],
                "reserved_at": attempt["reserved_at"],
                "authorization_id": auth_id,
                "receipt": receipt,
                "approval": attempt["approval_review"],
            }
        return {
            "plan": operation["plan"],
            "binding": state["binding"],
            "epoch": operation["epoch"],
            "epoch_started": state["epoch_started"],
            "snapshot_digest": self.coordinator._snapshot(gateway, operation),
            "attempts": attempts,
            "proofs": state["proofs"],
            "failure": state["failure"],
        }

    def observation(
        self,
        gateway: LiveAuthorityGateway,
        operation: dict[str, Any],
        step: str,
        now: datetime,
    ) -> dict[str, Any] | None:
        state = self.state(operation)
        if state["failure"]:
            return {
                "disposition": "mismatch",
                "evidence_digest": digest(state["failure"]),
            }
        if not state["proofs"]:
            return None
        _, authority, policies = self.trust(gateway)
        report = evaluate(
            self.manifest(gateway, operation, step_id=step),
            authority,
            policies,
            now,
            step_id=step,
        )
        if report["status"] == "verified":
            return {"disposition": "verified", "evidence_digest": digest(report)}
        return None

    def bundle(
        self, db: sqlite3.Connection, operation: dict[str, Any]
    ) -> dict[str, Any]:
        records: list[dict[str, Any]] = []
        while len(records) < MAX_CHAIN:
            state = self.state(operation)
            record = state["closure"]
            if record is None:
                raise OperationError("Operation has no signed closure.", 409)
            records.append(record)
            if record["content"]["next"] is None:
                return {"schema_version": BUNDLE, "records": records}
            operation = self.store.load(db, state["selected_followup"])
        raise AuthorityProofError("Closure chain exceeds its depth bound.")

    def unresolved(
        self,
        gateway: LiveAuthorityGateway,
        db: sqlite3.Connection,
        after: str,
        limit: int,
    ) -> dict[str, Any]:
        _, authority, policies = self.trust(gateway)
        rows = db.execute(
            """
            SELECT operation_id FROM operations
            WHERE operation_id > ? AND json_type(state, '$.verification') = 'object'
                AND json_extract(state, '$.closed') = 0
            ORDER BY operation_id LIMIT ?
            """,
            (after, limit + 1),
        ).fetchall()
        results = []
        now = datetime.now(UTC)
        for (operation_id,) in rows[:limit]:
            operation = self.store.load(db, operation_id)
            state = self.state(operation)
            if not operation["steps"]:
                continue
            try:
                report = evaluate(
                    self.manifest(gateway, operation), authority, policies, now
                )
            except (AuthorityProofError, OperationError, OSError):
                results.append(
                    {"operation_id": operation_id, "status": "proof_unavailable"}
                )
                continue
            if report["status"] != "verified":
                results.append(
                    {
                        "operation_id": operation_id,
                        "status": report["status"],
                        "followup": state["selected_followup"],
                        "failure": state["failure"],
                        "unresolved_requirements": {
                            name: item["status"]
                            for name, item in report["requirements"].items()
                            if item["status"] != "passed"
                        },
                    }
                )
        return {
            "unresolved": results,
            "next_after": rows[limit - 1][0] if len(rows) > limit else None,
        }

    def request(
        self,
        gateway: LiveAuthorityGateway,
        db: sqlite3.Connection,
        operation: dict[str, Any],
        action: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        state = self.state(operation)
        op = operation["plan"]["operation_id"]
        signing, authority, policies = self.trust(gateway)
        now = datetime.now(UTC)
        if action == "verification-export":
            return self.bundle(db, operation)
        if action == "verification-chain":
            chain: list[dict[str, Any]] = []
            while len(chain) < MAX_CHAIN:
                current = self.state(operation)
                chain.append(
                    {
                        "operation_id": operation["plan"]["operation_id"],
                        "contract": current["binding"]["contract"],
                        "parent": current["binding"]["parent"],
                        "failure": current["failure"],
                        "closed": operation["closed"],
                    }
                )
                child = current["selected_followup"]
                if not child:
                    return {"chain": chain}
                operation = self.store.load(db, child)
            raise AuthorityProofError("Operation chain exceeds its depth bound.")

        # A closed operation is assessed from its immutable signed record.
        if operation["closed"]:
            if action == "verification-assess":
                return verify_bundle(
                    self.bundle(db, operation),
                    authority,
                    policies,
                    operation_id=op,
                    now=now,
                )
            raise OperationError("Operation is closed.", 409)

        manifest = self.manifest(gateway, operation)
        if action in {"verification-target", "verification-evidence"}:
            requirement_id = identifier(data["requirement_id"])
            requirement = next(
                (
                    row
                    for row in state["binding"]["contract"]["requirements"]
                    if row["id"] == requirement_id
                ),
                None,
            )
            if requirement is None:
                raise OperationError("Requirement not found.", 404)
            step = requirement["step_id"]
            if step not in manifest["attempts"]:
                raise OperationError(
                    "Requirement has no authorized attempt to verify.", 409
                )
            target = evidence_target(
                manifest, requirement, authorization(manifest, step, authority)
            )
            if action == "verification-target":
                return target
            self.check_policy(gateway, operation)
            if state["selected_followup"]:
                raise OperationError(
                    "Evidence is frozen after follow-up selection.", 409
                )
            self.record_evidence(
                db, operation, requirement, target, data["envelope"], policies, now
            )
            return evaluate(
                manifest | {"failure": state["failure"]}, authority, policies, now
            )

        report = evaluate(manifest, authority, policies, now)
        child = state["selected_followup"]
        child_state = self.state(self.store.load(db, child)) if child else None
        child_record = child_state["closure"] if child_state else None
        child_digest = digest(child_record) if child_record else None
        assessment_digest = digest(
            {
                "manifest": manifest,
                "followup": child,
                "followup_closure": child_digest,
            }
        )
        if action == "verification-assess":
            parent = state["binding"]["parent"]
            return {
                **report,
                "operation_id": op,
                "epoch": operation["epoch"],
                "assessment_digest": assessment_digest,
                "parent": parent,
                "followup": child,
                "followup_closure_sha256": child_digest,
                "feedback": self.state(self.store.load(db, parent["operation_id"]))[
                    "failure"
                ]
                if parent
                else {},
                "failure": state["failure"],
            }
        if integer(data["epoch"], "epoch", 0, 2**53 - 1) != operation["epoch"]:
            raise OperationError("Operation epoch changed; assess again.", 409)
        if data["assessment_digest"] != assessment_digest:
            raise OperationError(
                "Assessment changed; review the current evidence again.", 409
            )
        reviewer, reason = (
            text(data["reviewer"], "reviewer", 128),
            text(data["reason"], "reason"),
        )
        if action == "verification-fail":
            if (
                state["failure"]
                or report["status"] == "verified"
                or not any(
                    row["attempt"]["phase"] in ("attempted", "reserved")
                    for row in operation["steps"].values()
                )
            ):
                raise OperationError(
                    "Only an unresolved execution may be declared failed.", 409
                )
            state["failure"] = {
                "at": now.isoformat(),
                "reviewer": reviewer,
                "reason": reason,
                "assessment_digest": data["assessment_digest"],
                "requirements": report["requirements"],
            }
            self.store.save(db, operation, "verification_failure", **state["failure"])
            return {"status": "failed", "failure": state["failure"]}

        self.check_policy(gateway, operation)
        next_digest = None
        decision = data["decision"]
        if decision in ("followup", "abandoned") and child and state["failure"]:
            child_bundle = self.bundle(db, self.store.load(db, child))
            verdict = verify_bundle(
                child_bundle, authority, policies, operation_id=child, now=now
            )
            if not (
                (decision == "followup" and verdict["current"])
                or (
                    decision == "abandoned"
                    and verdict["outcome_at_closure"] == "abandoned"
                )
            ):
                raise OperationError(
                    "Follow-up closure does not support that decision.", 409
                )
            next_digest = verdict["closure_sha256"]
        elif not child and (
            (decision == "verified" and report["status"] == "verified")
            or (decision == "abandoned" and report["status"] != "verified")
        ):
            pass
        else:
            raise OperationError(
                "Requested closure is unsupported by the current assessment.", 409
            )
        review = {
            "at": now.isoformat(),
            "reviewer": reviewer,
            "reason": reason,
            "outcome": decision,
        }
        content = {"assessment": manifest, "review": review, "next": next_digest}
        state["closure"] = {
            "content": content,
            "signature": signing.envelope(
                CLOSURE_TYPE,
                {"content_sha256": digest(content)},
            ),
        }
        operation.update(closed=True, approval="")
        verdict = verify_bundle(
            self.bundle(db, operation), authority, policies, operation_id=op
        )
        if decision != "abandoned" and not verdict["current"]:
            raise OperationError(
                "Evidence became stale before closure could be committed.", 409
            )
        self.store.save(
            db,
            operation,
            "verification_closed",
            **review,
            closure_sha256=verdict["closure_sha256"],
        )
        return verdict

    def record_evidence(
        self,
        db: sqlite3.Connection,
        operation: dict[str, Any],
        requirement: dict[str, Any],
        target: dict[str, Any],
        envelope: Any,
        policies: dict[str, TrustPolicy],
        now: datetime,
    ) -> None:
        state = self.state(operation)
        name = requirement["id"]
        policy = policies[requirement["source"]]
        if not isinstance(envelope, dict) or len(canonical_bytes(envelope)) > 24576:
            raise OperationError(
                "Verification evidence exceeds the envelope limit.", 400
            )
        try:
            body = verify_evidence(envelope, target, policy, now)
        except (AuthorityProofError, OperationError) as exc:
            raise OperationError(
                "Evidence signature, role, target or observation interval is invalid.",
                403,
            ) from exc
        age = timedelta(seconds=state["binding"]["max_age_seconds"])
        if now - timestamp(body["observed_at"]) >= age:
            raise OperationError("Verification evidence is stale.", 403)
        entries = state["proofs"].setdefault(name, [])
        if any(
            semantic_result(verify_evidence(item, target, policy, now))
            == semantic_result(body)
            for item in entries
        ):
            return
        if len(entries) >= 2:
            raise OperationError(
                "Contradictory evidence is already retained for this criterion.", 409
            )
        entries.append(envelope)
        self.store.save(
            db,
            operation,
            "verification_evidence",
            requirement_id=name,
            target=target,
            envelope=envelope,
        )
        if not state["failure"] and (
            len(entries) == 2
            or body["status"] != "pass"
            or canonical_bytes(body["value"])
            != canonical_bytes(requirement["expected"])
        ):
            state["failure"] = {
                "at": now.isoformat(),
                "requirement_id": name,
                "reason": "contradictory evidence"
                if len(entries) == 2
                else "acceptance criterion failed",
                "expected": requirement["expected"],
                "observed": body["value"],
                "evidence_sha256": digest(envelope),
            }
            self.store.save(db, operation, "verification_failure", **state["failure"])
