from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import TYPE_CHECKING, Any

from ix_blackfox.authority_crypto.encoding import (
    AuthorityProofError,
    canonical_bytes,
    digest,
    strict_json,
)
from ix_blackfox.authority_crypto.verification import verify_receipt
from ix_blackfox.autonomy.contracts import (
    AutonomyConfig,
    DispatchPermit,
    OperationError,
    identifier,
    integer,
    json_object,
    object_fields,
    parse_plan,
    text,
    timestamp,
)
from ix_blackfox.autonomy.store import OperationStore
from ix_blackfox.integration_mesh.ledger import MeshLedger
from ix_blackfox.live_gateway.evidence import EvidencePolicy, SignedEvidenceArtifact
from ix_blackfox.live_gateway.models import AuthoritySubject

if TYPE_CHECKING:
    from ix_blackfox.live_gateway.enterprise_identity import AuthenticatedPrincipal
    from ix_blackfox.live_gateway.service import (
        GatewayHttpResponse,
        LiveAuthorityGateway,
    )

PROTOCOL = "blackfox-api/v1"
OBSERVATION = "operation_observation"


class OperationCoordinator:
    def __init__(self, config: AutonomyConfig) -> None:
        self.config = config
        self.store = OperationStore(config.database)
        self.observation_policy = EvidencePolicy(
            policy_id="operation-observation",
            required_kinds=(OBSERVATION,),
            target_bound_kinds=(OBSERVATION,),
            accepted_statuses=("verified",),
            allowed_issuers=(config.observer_issuer,),
            max_age_seconds=config.max_evidence_age_seconds,
        )

    def request(
        self,
        gateway: LiveAuthorityGateway,
        action: str,
        payload: Mapping[str, Any],
        headers: Mapping[str, str],
    ) -> GatewayHttpResponse:
        from ix_blackfox.live_gateway.service import _json_response

        try:
            if action in {"propose", "subject", "dispatch"}:
                principal, error = gateway.authenticate_principal(
                    headers=headers,
                    claimed_agent_id=next(
                        (
                            value
                            for key, value in headers.items()
                            if key.lower() == "x-blackfox-agent-id"
                        ),
                        "",
                    ),
                )
                if error or principal is None:
                    raise OperationError("Agent authentication required.", 401)
                if action == "propose":
                    return _json_response(
                        201, self._propose(gateway, principal.agent_id, payload)
                    )
                data = object_fields(
                    payload,
                    {"operation_id", "step_id", "evidence_refs"}
                    if action == "dispatch"
                    else {"operation_id", "step_id"},
                    action,
                )
                operation_id, step_id = (
                    identifier(data["operation_id"]),
                    identifier(data["step_id"]),
                )
                if action == "subject":
                    with self.store.transaction(write=False) as db:
                        state = self.store.load(db, operation_id)
                        _, subject, _ = self._step_subject(
                            gateway, principal, state, step_id
                        )
                        return _json_response(200, subject.to_dict())
                refs = data["evidence_refs"]
                if not isinstance(refs, list) or not 1 <= len(refs) <= 64:
                    raise OperationError("Dispatch requires 1–64 evidence references.")
                return self._dispatch(
                    gateway,
                    principal,
                    headers,
                    operation_id,
                    step_id,
                    [text(ref, "evidence reference", 128) for ref in refs],
                )
            if not gateway.operator_authorized(headers):
                raise OperationError("Operator authentication required.", 401)
            return _json_response(200, self._operator(gateway, action, payload))
        except OperationError as exc:
            return _json_response(exc.status, {"error": str(exc)})
        except (AuthorityProofError, OSError, sqlite3.Error):
            return _json_response(
                503,
                {"error": "Operation state or proof unavailable.", "retry_safe": False},
            )
        except (KeyError, ValueError) as exc:
            return _json_response(400, {"error": str(exc)})

    def _propose(
        self, gateway: LiveAuthorityGateway, agent_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        plan = parse_plan(payload)
        now = datetime.now(UTC)
        if not now < timestamp(plan["expires_at"]) <= now + timedelta(days=30):
            raise OperationError("Operation expiry must be within the next 30 days.")
        for step in plan["steps"].values():
            if step["tool_name"] not in self.config.tools:
                raise OperationError(
                    "Plan contains a tool outside the operation allowlist."
                )
            if gateway.config.agent_registry.lookup(step["agent_id"]) is None:
                raise OperationError("Plan contains an unregistered agent.")
            gateway.build_subject(
                agent_id=step["agent_id"],
                tool_name=step["tool_name"],
                arguments=step["arguments"],
                protocol=PROTOCOL,
            )
        state = {
            "plan": plan,
            "plan_digest": digest(plan),
            "proposer": agent_id,
            "epoch": 0,
            "facts": {},
            "facts_until": "",
            "approval": "",
            "attempts": 0,
            "cost_spent": 0,
            "closed": False,
            "steps": {},
        }
        with self.store.transaction() as db:
            if db.execute(
                "SELECT 1 FROM operations WHERE operation_id=?", (plan["operation_id"],)
            ).fetchone():
                raise OperationError("Operation identifier is already reserved.", 409)
            self.store.save(
                db,
                state,
                "proposed",
                proposer=agent_id,
                plan_digest=state["plan_digest"],
            )
        return {
            "operation_id": plan["operation_id"],
            "plan_digest": state["plan_digest"],
        }

    def _snapshot(self, gateway: LiveAuthorityGateway, state: dict[str, Any]) -> str:
        subjects: dict[str, str | None] = {}
        for step_id, step in state["plan"]["steps"].items():
            if (
                gateway.config.route_for(step["tool_name"]) is None
                or gateway.config.agent_registry.lookup(step["agent_id"]) is None
            ):
                subjects[step_id] = None
                continue
            subjects[step_id] = gateway.build_subject(
                agent_id=step["agent_id"],
                tool_name=step["tool_name"],
                arguments=step["arguments"],
                protocol=PROTOCOL,
            ).digest
        return digest(
            {
                "plan": state["plan_digest"],
                "epoch": state["epoch"],
                "facts": state["facts"],
                "facts_until": state["facts_until"],
                "policy": self.config.policy_digest,
                "routes": subjects,
            }
        )

    def _operator(
        self, gateway: LiveAuthorityGateway, action: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        fields = {
            "inspect": set(),
            "events": {"after"},
            "approve": {"snapshot_digest", "reviewer"},
            "conditions": {"epoch", "facts", "valid_until", "reason"},
            "suspend": {"epoch", "reason"},
            "close": {"epoch", "reason"},
            "observation-target": {"step_id"},
            "observe": {"step_id", "evidence_ref"},
        }
        if action not in fields:
            raise OperationError("Operation endpoint not found.", 404)
        data = object_fields(payload, {"operation_id", *fields[action]}, action)
        op = identifier(data["operation_id"])
        with self.store.transaction(
            write=action not in {"inspect", "events", "observation-target"}
        ) as db:
            state = self.store.load(db, op)
            if action == "inspect":
                return self._inspect(gateway, state)
            if action == "events":
                return {
                    "events": self.store.events(
                        db, op, integer(data["after"], "after", 0, 2**63 - 1)
                    )
                }
            if action in {"observation-target", "observe"}:
                step_id = identifier(data["step_id"])
                target, current = self._observation_target(gateway, state, step_id)
                if action == "observation-target":
                    return target.to_dict()
                self._observe(
                    gateway,
                    db,
                    state,
                    current,
                    step_id,
                    target,
                    text(data["evidence_ref"], "evidence reference", 128),
                )
                return self._inspect(gateway, state)
            if state["closed"]:
                raise OperationError("Operation is closed.", 409)
            if action == "approve":
                self._check_window(state)
                snapshot = self._snapshot(gateway, state)
                if data["snapshot_digest"] != snapshot:
                    raise OperationError(
                        "Operation conditions or policy changed; inspect again.", 409
                    )
                reviewer = text(data["reviewer"], "reviewer", 128)
                if state["approval"] != snapshot:
                    state["approval"] = snapshot
                    self.store.save(
                        db,
                        state,
                        "approved",
                        snapshot_digest=snapshot,
                        reviewer=reviewer,
                    )
                return self._inspect(gateway, state)
            if integer(data["epoch"], "epoch", 0, 2**63 - 2) != state["epoch"]:
                raise OperationError("Operation epoch changed; inspect again.", 409)
            reason = text(data["reason"], "reason")
            if action == "conditions":
                facts = json_object(data["facts"], "facts", 8192)
                for key in facts:
                    identifier(key)
                until = timestamp(data["valid_until"])
                now = datetime.now(UTC)
                if (
                    not now
                    < until
                    <= now + timedelta(seconds=self.config.max_evidence_age_seconds)
                ):
                    raise OperationError(
                        "Condition expiry exceeds the configured freshness window."
                    )
                state.update(facts=facts, facts_until=until.isoformat())
            elif action == "close":
                state["closed"] = True
            else:
                state["facts_until"] = ""
            state.update(epoch=state["epoch"] + 1, approval="")
            self.store.save(
                db,
                state,
                action,
                epoch=state["epoch"],
                reason=reason,
                facts=state["facts"],
                facts_until=state["facts_until"],
            )
            return self._inspect(gateway, state)

    def _inspect(
        self, gateway: LiveAuthorityGateway, state: dict[str, Any]
    ) -> dict[str, Any]:
        snapshot = self._snapshot(gateway, state)
        now = datetime.now(UTC)
        statuses = {}
        for name in state["plan"]["steps"]:
            current = state["steps"].get(name, {})
            attempt = current.get("attempt", {})
            observation = current.get("observation", {})
            phase = attempt.get("phase", "pending")
            if observation and self._current_observation(gateway, state, name, now):
                phase = observation["disposition"]
            elif observation:
                phase = "observation_stale"
            elif phase == "reserved":
                phase = "outcome_unknown"
            statuses[name] = phase
        return {
            **state,
            "snapshot_digest": snapshot,
            "step_status": statuses,
            "approved": bool(
                state["approval"] == snapshot
                and state["facts_until"]
                and timestamp(state["facts_until"]) > now
                and timestamp(state["plan"]["expires_at"]) > now
                and not state["closed"]
            ),
            "complete": bool(
                statuses and all(status == "verified" for status in statuses.values())
            ),
        }

    @staticmethod
    def _check_window(state: dict[str, Any]) -> None:
        now = datetime.now(UTC)
        if state["closed"] or timestamp(state["plan"]["expires_at"]) <= now:
            raise OperationError("Operation is closed or expired.", 409)
        if not state["facts_until"] or timestamp(state["facts_until"]) <= now:
            raise OperationError("Operation conditions are suspended or stale.", 409)

    def _check_ready(
        self, gateway: LiveAuthorityGateway, state: dict[str, Any], step_id: str
    ) -> tuple[dict[str, Any], dict[str, str]]:
        self._check_window(state)
        if state["approval"] != self._snapshot(gateway, state):
            raise OperationError(
                "Current operation snapshot requires operator approval.", 403
            )
        step = state["plan"]["steps"].get(step_id)
        if step is None:
            raise OperationError("Step not found.", 404)
        if any(
            key not in state["facts"]
            or canonical_bytes(state["facts"][key]) != canonical_bytes(value)
            for key, value in step["preconditions"].items()
        ):
            raise OperationError("Step preconditions are not satisfied.", 409)
        now = datetime.now(UTC)
        # Any discrepancy or uncertain transport requires reconciliation before new effects.
        for name, current in state["steps"].items():
            attempt = current["attempt"]
            observation = self._current_observation(gateway, state, name, now)
            if attempt["phase"] in {"attempted", "reserved"} and (
                observation is None or observation["disposition"] == "mismatch"
            ):
                raise OperationError(
                    "An outstanding attempt requires independent reconciliation.", 409
                )
        dependencies = self._dependency_digests(gateway, state, step_id, now)
        return step, dependencies

    def _dependency_digests(
        self,
        gateway: LiveAuthorityGateway,
        state: dict[str, Any],
        step_id: str,
        now: datetime,
    ) -> dict[str, str]:
        pending = list(state["plan"]["steps"][step_id]["depends_on"])
        found: dict[str, str] = {}
        while pending:
            name = pending.pop()
            if name in found:
                continue
            observation = self._current_observation(gateway, state, name, now)
            if not observation or observation["disposition"] != "verified":
                raise OperationError(
                    "A dependency has no current verified outcome.", 409
                )
            found[name] = observation["evidence_digest"]
            pending.extend(state["plan"]["steps"][name]["depends_on"])
        return found

    def _step_subject(
        self,
        gateway: LiveAuthorityGateway,
        principal: AuthenticatedPrincipal,
        state: dict[str, Any],
        step_id: str,
    ) -> tuple[dict[str, Any], AuthoritySubject, dict[str, Any]]:
        step = state["plan"]["steps"].get(step_id)
        if (
            step is None
            or step["agent_id"] != principal.agent_id
            or step["tool_name"] not in self.config.tools
        ):
            raise OperationError("Step not found for this agent.", 404)
        current = state["steps"].get(step_id, {}).get("attempt", {})
        if current.get("phase") not in {None, "not_attempted"}:
            raise OperationError(
                "Step already has an attempt requiring retention or reconciliation.",
                409,
            )
        if state["attempts"] >= state["plan"]["max_attempts"] or (
            state["cost_spent"] + step["cost"] > state["plan"]["max_cost"]
        ):
            raise OperationError("Operation budget is exhausted.", 409)
        _, dependencies = self._check_ready(gateway, state, step_id)
        binding = {
            "operation_id": state["plan"]["operation_id"],
            "plan_digest": state["plan_digest"],
            "epoch": state["epoch"],
            "snapshot_digest": state["approval"],
            "step_id": step_id,
            "attempt": state["attempts"] + 1,
            "dependency_observations": dependencies,
        }
        subject = gateway.build_subject(
            agent_id=principal.agent_id,
            tool_name=step["tool_name"],
            arguments=step["arguments"],
            protocol=PROTOCOL,
            principal=principal,
            operation=binding,
        )
        if principal.authorize_action(
            tool_name=subject.tool_name,
            repository_id=subject.repository_id,
            path=subject.path,
        ):
            raise OperationError("Principal is not delegated to this step.", 403)
        return step, subject, binding

    def _dispatch(
        self,
        gateway: LiveAuthorityGateway,
        principal: AuthenticatedPrincipal,
        headers: Mapping[str, str],
        operation_id: str,
        step_id: str,
        evidence: list[str],
    ) -> GatewayHttpResponse:
        from ix_blackfox.live_gateway.service import _json_response

        with self.store.transaction() as db:
            state = self.store.load(db, operation_id)
            step, subject, binding = self._step_subject(
                gateway, principal, state, step_id
            )
            prepared = gateway.prepare_authority(
                agent_id=principal.agent_id,
                tool_name=step["tool_name"],
                arguments=step["arguments"],
                evidence_ids=evidence,
                protocol=PROTOCOL,
                principal=principal,
                operation=binding,
            )
            if not prepared.decision.allowed:
                return _json_response(
                    403,
                    {
                        "error": "Step authority requirements were not met.",
                        "authority": prepared.decision.to_dict(),
                        "execution_state": "not_attempted",
                    },
                )
            key = "op:" + digest(binding)
            request_id = digest(
                {
                    "agent_id": principal.agent_id,
                    "connector_id": prepared.route.connector_id,
                    "tool_name": step["tool_name"],
                    "key": key,
                }
            )
            attempt = {
                "phase": "reserved",
                "subject_digest": subject.digest,
                "request_id": request_id,
                "reserved_at": datetime.now(UTC).isoformat(),
                "binding": binding,
            }
            state["steps"][step_id] = {"attempt": attempt}
            state["attempts"] += 1
            state["cost_spent"] += step["cost"]
            self.store.save(db, state, "reserved", step_id=step_id, attempt=attempt)

        permit = DispatchPermit(
            binding,
            partial(self._record_authorization, operation_id, step_id, request_id),
            partial(self._guard, gateway, binding, request_id),
        )
        forwarded = {
            k: v
            for k, v in headers.items()
            if k.lower()
            in {
                "authorization",
                "x-blackfox-agent-id",
                "x-blackfox-agent-token",
            }
        }
        forwarded["X-BlackFox-Idempotency-Key"] = key
        try:
            response = gateway._handle_api(
                payload={
                    "agent_id": principal.agent_id,
                    "tool_name": step["tool_name"],
                    "arguments": step["arguments"],
                    "context": {"evidence_refs": evidence},
                },
                headers=forwarded,
                permit=permit,
            )
        except OperationError as exc:
            response = _json_response(
                exc.status, {"error": str(exc), "execution_state": "not_attempted"}
            )
        except (AuthorityProofError, sqlite3.Error, OSError) as exc:
            response = gateway._proof_unavailable(exc)
        return self._finish_dispatch(operation_id, step_id, request_id, response)

    def _record_authorization(
        self,
        operation_id: str,
        step_id: str,
        request_id: str,
        authorization_id: str,
    ) -> None:
        with self.store.transaction() as db:
            state = self.store.load(db, operation_id)
            attempt = state["steps"][step_id]["attempt"]
            if attempt["request_id"] != request_id or attempt["phase"] != "reserved":
                raise OperationError(
                    "Attempt changed before authorization was recorded.", 409
                )
            attempt["authorization_receipt_id"] = authorization_id
            self.store.save(
                db,
                state,
                "authorized",
                step_id=step_id,
                request_id=request_id,
                authorization_receipt_id=authorization_id,
            )

    @contextmanager
    def _guard(
        self,
        gateway: LiveAuthorityGateway,
        binding: Mapping[str, Any],
        request_id: str,
        authorization_id: str,
        revalidate: Callable[[], None],
    ) -> Iterator[None]:
        failure: Exception | None = None
        with self.store.transaction() as db:
            state = self.store.load(db, binding["operation_id"])
            step_id = binding["step_id"]
            current = state["steps"][step_id]
            attempt = current["attempt"]
            if (
                state["approval"] != binding["snapshot_digest"]
                or attempt["request_id"] != request_id
                or attempt["phase"] != "reserved"
                or attempt.get("authorization_receipt_id") != authorization_id
                or current.get("observation")
            ):
                raise OperationError("Operation changed before dispatch.", 409)
            # The reserved step is expected here. No other reserved attempt can
            # exist because reservation itself checks for outstanding work.
            del state["steps"][step_id]
            revalidate()
            _, dependencies = self._check_ready(gateway, state, step_id)
            if dependencies != binding["dependency_observations"]:
                raise OperationError(
                    "Dependency evidence changed before dispatch.", 409
                )
            self._check_window(state)
            state["steps"][step_id] = current
            try:
                yield
            except Exception as exc:
                failure = exc
            attempt["phase"] = "attempted"
            self.store.save(db, state, "attempted", step_id=step_id, attempt=attempt)
        if failure is not None:
            raise failure

    def _finish_dispatch(
        self,
        operation_id: str,
        step_id: str,
        request_id: str,
        response: GatewayHttpResponse,
    ) -> GatewayHttpResponse:
        from ix_blackfox.live_gateway.service import _json_response

        body = strict_json(response.body)
        with self.store.transaction() as db:
            state = self.store.load(db, operation_id)
            attempt = state["steps"][step_id]["attempt"]
            # A storage fault after entering the guard can roll its transaction back.
            # Preserve reservations unless the response proves a pre-dispatch denial.
            if attempt["request_id"] == request_id:
                execution = body.get("execution_state", "")
                if (
                    attempt["phase"] == "reserved"
                    and execution == "not_attempted"
                    and response.status < 500
                    and not state["steps"][step_id].get("observation")
                ):
                    attempt["phase"] = "not_attempted"
                attempt["transport_state"] = (
                    "outcome_unknown"
                    if attempt["phase"] == "reserved"
                    else execution or "not_attempted"
                )
                self.store.save(
                    db,
                    state,
                    "transport_reported",
                    step_id=step_id,
                    request_id=request_id,
                    transport_state=attempt["transport_state"],
                    receipt_id=body.get("receipt_id", ""),
                )
        if attempt["phase"] == "reserved":
            body.update(execution_state="outcome_unknown", retry_safe=False)
        return _json_response(
            response.status,
            {
                **body,
                "operation_id": operation_id,
                "step_id": step_id,
                "request_id": request_id,
            },
        )

    def _observation_target(
        self,
        gateway: LiveAuthorityGateway,
        state: dict[str, Any],
        step_id: str,
    ) -> tuple[AuthoritySubject, dict[str, Any]]:
        step = state["plan"]["steps"].get(step_id)
        current = state["steps"].get(step_id)
        if (
            step is None
            or current is None
            or current["attempt"]["phase"] == "not_attempted"
        ):
            raise OperationError("Step has no retained attempt to observe.", 409)
        attempt = current["attempt"]
        mesh, signing = gateway.config.mesh, gateway.receipt_store.signing
        assert mesh is not None and signing is not None
        request = MeshLedger(mesh.database).inspect_request(attempt["request_id"])
        if (
            not request
            or request["subject_digest"] != attempt["subject_digest"]
            or not request["authorization_id"]
        ):
            raise OperationError(
                "Step has no retained authorization to reconcile.", 409
            )
        envelope = gateway.receipt_store.get(request["authorization_id"])
        if envelope is None:
            raise AuthorityProofError("Retained authorization is unavailable.")
        receipt = verify_receipt(envelope, signing.current_policy())
        if (
            receipt["record_type"] != "authorization"
            or receipt["subject"]["digest"] != attempt["subject_digest"]
        ):
            raise AuthorityProofError(
                "Retained authorization does not match the attempt."
            )
        source = receipt["subject"]
        return AuthoritySubject(
            agent_id=step["agent_id"],
            tool_name=step["tool_name"],
            capability=OBSERVATION,
            repository_id=source["repository_id"],
            revision=source["revision"],
            path="",
            arguments_digest=digest(
                {
                    "request_id": attempt["request_id"],
                    "authorization_receipt_id": receipt["receipt_id"],
                    "subject_digest": attempt["subject_digest"],
                }
            ),
            authority_context_digest=self._snapshot(gateway, state),
            protocol="blackfox-operation-observation/v1",
            metadata={
                "operation_id": state["plan"]["operation_id"],
                "step_id": step_id,
                "epoch": state["epoch"],
                "request_id": attempt["request_id"],
                "authorization_receipt_id": receipt["receipt_id"],
            },
        ), current

    def _verify_observation(
        self,
        gateway: LiveAuthorityGateway,
        target: AuthoritySubject,
        evidence_ref: str,
        now: datetime,
    ) -> SignedEvidenceArtifact | None:
        verification, artifact = gateway.evidence_store.verify_one(
            evidence_ref,
            subject=target,
            policy=self.observation_policy,
            now=now,
        )
        if (
            not verification.passed
            or artifact is None
            or artifact.kind != OBSERVATION
            or artifact.key_id != self.config.observer_key_id
            or timestamp(artifact.produced_at) > now
        ):
            return None
        return artifact

    def _current_observation(
        self,
        gateway: LiveAuthorityGateway,
        state: dict[str, Any],
        step_id: str,
        now: datetime,
    ) -> dict[str, Any] | None:
        observation = state["steps"].get(step_id, {}).get("observation")
        if not observation or observation["epoch"] != state["epoch"]:
            return None
        target, _ = self._observation_target(gateway, state, step_id)
        artifact = self._verify_observation(
            gateway, target, observation["evidence_ref"], now
        )
        return (
            observation
            if artifact and artifact.digest == observation["evidence_digest"]
            else None
        )

    def _observe(
        self,
        gateway: LiveAuthorityGateway,
        db: sqlite3.Connection,
        state: dict[str, Any],
        current: dict[str, Any],
        step_id: str,
        target: AuthoritySubject,
        evidence_ref: str,
    ) -> None:
        now = datetime.now(UTC)
        artifact = self._verify_observation(gateway, target, evidence_ref, now)
        if artifact is None or timestamp(artifact.produced_at) < timestamp(
            current["attempt"]["reserved_at"]
        ):
            raise OperationError(
                "Fresh independent evidence bound to this attempt is required.", 403
            )
        payload = object_fields(
            dict(artifact.payload), {"kind", "value"}, "observation"
        )
        value = json_object(payload["value"], "observed value", 8192)
        step = state["plan"]["steps"][step_id]
        if payload["kind"] == "outcome":
            self._dependency_digests(gateway, state, step_id, now)
            disposition = (
                "verified"
                if canonical_bytes(value) == canonical_bytes(step["expected_outcome"])
                else "mismatch"
            )
        elif payload["kind"] == "recovery":
            if canonical_bytes(value) != canonical_bytes(
                step["recovery"]["expected_outcome"]
            ):
                raise OperationError(
                    "Recovery evidence does not satisfy the approved obligation.", 409
                )
            disposition = "recovered"
        else:
            raise OperationError("Observation kind must be outcome or recovery.")
        previous = current.get("observation")
        if previous and previous["epoch"] == state["epoch"]:
            if previous["evidence_digest"] == artifact.digest:
                return
            if previous["disposition"] != "mismatch" or disposition != "recovered":
                raise OperationError(
                    "Existing observation requires a new epoch before replacement.", 409
                )
        observation = {
            "epoch": state["epoch"],
            "disposition": disposition,
            "value": value,
            "evidence_ref": evidence_ref,
            "evidence_digest": artifact.digest,
            "issuer": artifact.issuer,
            "produced_at": artifact.produced_at,
        }
        current["observation"] = observation
        self.store.save(db, state, "observed", step_id=step_id, **observation)
