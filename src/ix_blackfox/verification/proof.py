from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from ix_blackfox.authority_crypto.encoding import (
    AuthorityProofError,
    canonical_bytes,
    decode64,
    digest,
    fields,
    strict_json,
)
from ix_blackfox.authority_crypto.trust import TrustPolicy
from ix_blackfox.authority_crypto.verification import verify_receipt
from ix_blackfox.autonomy.contracts import (
    OperationError,
    identifier,
    integer,
    json_object,
    parse_plan,
    text,
    timestamp,
)
from ix_blackfox.operating.models import digest_payload
from ix_blackfox.verification.contracts import (
    MAX_CHAIN,
    parse_contract,
    sha256,
    trust_binding,
    validate_roles,
)

EVIDENCE_TYPE = "application/vnd.ix-blackfox.verification-evidence.v19+json"
CLOSURE_TYPE = "application/vnd.ix-blackfox.verification-closure.v19+json"
BUNDLE = "wave19.verification-bundle.v1"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AuthorityProofError(message)


def scope(subject: dict[str, Any]) -> dict[str, str]:
    return {
        "repository_id": subject["repository_id"],
        "connector_digest": digest(subject["metadata"]["integration_connector"]),
    }


def authorization(
    manifest: dict[str, Any], step_id: str, authority: TrustPolicy
) -> dict[str, Any]:
    step = manifest["plan"]["steps"][step_id]
    attempt = manifest["attempts"][step_id]
    receipt = verify_receipt(attempt["receipt"], authority)
    subject = receipt["subject"]
    binding = subject["metadata"]["operation"]
    approval = attempt["approval"]
    require(
        receipt["record_type"] == "authorization"
        and binding["operation_id"] == manifest["plan"]["operation_id"]
        and binding["plan_digest"] == digest(manifest["plan"])
        and binding["verification_digest"] == digest(manifest["binding"])
        and binding["step_id"] == step_id
        and binding["epoch"] == approval["epoch"] <= manifest["epoch"]
        and binding["snapshot_digest"] == approval["snapshot_digest"]
        and binding["approval_review_digest"] == digest(approval)
        and receipt["receipt_id"] == attempt["authorization_id"]
        and subject["agent_id"] == step["agent_id"]
        and subject["tool_name"] == step["tool_name"]
        and subject["arguments_digest"] == digest_payload(step["arguments"])
        and scope(subject) == manifest["binding"]["scope"][step_id]
        and timestamp(approval["at"])
        <= timestamp(attempt["reserved_at"])
        <= timestamp(receipt["recorded_at"]),
        "Authorization receipt does not match the approved change and attempt.",
    )
    require(
        attempt["request_id"]
        == digest(
            {
                "agent_id": subject["agent_id"],
                "connector_id": subject["metadata"]["integration_connector"][
                    "connector_id"
                ],
                "tool_name": step["tool_name"],
                "key": "op:" + digest(binding),
            }
        ),
        "Attempt request ID does not match the signed authority binding.",
    )
    return receipt


def evidence_target(
    manifest: dict[str, Any],
    requirement: dict[str, Any],
    receipt: dict[str, Any],
) -> dict[str, Any]:
    step_id = requirement["step_id"]
    attempt = manifest["attempts"][step_id]
    target = {
        "schema_version": "wave19.evidence-target.v1",
        "operation_id": manifest["plan"]["operation_id"],
        "plan_digest": digest(manifest["plan"]),
        "verification_digest": digest(manifest["binding"]),
        "change": manifest["binding"]["contract"]["change"],
        "parent": manifest["binding"]["parent"],
        "criterion": requirement,
        "epoch": manifest["epoch"],
        "epoch_started": manifest["epoch_started"],
        "snapshot_digest": manifest["snapshot_digest"],
        "request_id": attempt["request_id"],
        "authorization_id": receipt["receipt_id"],
        "subject": receipt["subject"],
        "not_before": max(
            timestamp(attempt["reserved_at"]),
            timestamp(receipt["recorded_at"]),
            timestamp(manifest["epoch_started"]),
        ).isoformat(),
    }
    return {**target, "digest": digest(target)}


def signed_body(
    policy: TrustPolicy, envelope: dict[str, Any], payload_type: str, now: datetime
) -> tuple[dict[str, Any], datetime]:
    try:
        body = policy.verify(envelope, payload_type, now=now)
    except OverflowError as exc:
        raise AuthorityProofError(
            "Verification signature contains an invalid time."
        ) from exc
    statement = strict_json(decode64(envelope["payload"]))
    signed = timestamp(statement["signed_at"])
    require(signed <= now, "Verification signature is dated in the future.")
    return body, signed


def verify_evidence(
    envelope: dict[str, Any], target: dict[str, Any], policy: TrustPolicy, now: datetime
) -> dict[str, Any]:
    body, signed = signed_body(policy, envelope, EVIDENCE_TYPE, now)
    fields(body, {"target_digest", "observed_at", "artifact_sha256", "status", "value"})
    sha256(body["artifact_sha256"])
    json_object(body["value"], "observed result", 8192)
    require(
        body["target_digest"] == target["digest"]
        and body["status"] in ("pass", "fail")
        and timestamp(target["not_before"]) <= timestamp(body["observed_at"]) <= signed,
        "Evidence does not match the target or observation interval.",
    )
    return body


def semantic_result(body: dict[str, Any]) -> str:
    return digest({"status": body["status"], "value": body["value"]})


def evaluate(
    manifest: dict[str, Any],
    authority: TrustPolicy,
    policies: dict[str, TrustPolicy],
    now: datetime,
    *,
    step_id: str | None = None,
) -> dict[str, Any]:
    binding = manifest["binding"]
    require(
        trust_binding(policies) == binding["trust_digest"],
        "Verification trust pins changed.",
    )
    age = timedelta(seconds=integer(binding["max_age_seconds"], "freshness", 1, 86400))
    results: dict[str, Any] = {}
    receipts = {}
    requirements = binding["contract"]["requirements"]
    require(
        set(manifest["proofs"]) <= {row["id"] for row in requirements},
        "Evidence exists for an unknown criterion.",
    )
    for row in requirements:
        name, step = row["id"], row["step_id"]
        if step_id is not None and step != step_id:
            continue
        entries = manifest["proofs"].get(name, [])
        require(
            isinstance(entries, list) and len(entries) <= 2, "Invalid evidence history."
        )
        result: dict[str, Any] = {"status": "missing", "evidence": []}
        if step in manifest["attempts"] and step not in receipts:
            receipts[step] = authorization(manifest, step, authority)
        if entries:
            require(step in receipts, "Evidence lacks a retained authorization.")
            target = evidence_target(manifest, row, receipts[step])
            bodies = [
                verify_evidence(envelope, target, policies[row["source"]], now)
                for envelope in entries
            ]
            values = {semantic_result(body) for body in bodies}
            require(
                len(values) == len(entries),
                "Duplicate evidence results in the same epoch.",
            )
            body = bodies[0]
            if len(values) > 1:
                status = "contradictory"
            elif body["status"] != "pass" or canonical_bytes(
                body["value"]
            ) != canonical_bytes(row["expected"]):
                status = "failed"
            elif now - timestamp(body["observed_at"]) >= age:
                status = "stale"
            else:
                status = "passed"
            result = {
                "status": status,
                "evidence": [
                    {**item, "envelope_sha256": digest(envelope)}
                    for item, envelope in zip(bodies, entries, strict=True)
                ],
            }
        results[name] = result
    statuses = {item["status"] for item in results.values()}
    if statuses & {"failed", "contradictory"} or manifest["failure"]:
        status = "failed"
    elif statuses == {"passed"}:
        status = "verified"
    else:
        status = "pending"
    return {"status": status, "requirements": results}


def inherited_contract(
    parent: dict[str, Any], child: dict[str, Any], mode: str
) -> bool:
    return (
        mode in {"remediation", "rollback"}
        and canonical_bytes(child["requirements"])
        == canonical_bytes(
            parent["requirements" if mode == "remediation" else "rollback_requirements"]
        )
        and canonical_bytes(child["rollback_requirements"])
        == canonical_bytes(parent["rollback_requirements"])
    )


def _verified_records(
    bundle: dict[str, Any],
    authority: TrustPolicy,
    policies: dict[str, TrustPolicy],
    now: datetime,
) -> list[dict[str, Any]]:
    fields(bundle, {"schema_version", "records"})
    records = bundle["records"]
    require(
        bundle["schema_version"] == BUNDLE
        and isinstance(records, list)
        and 1 <= len(records) <= MAX_CHAIN,
        "Invalid closure chain.",
    )
    contents: list[dict[str, Any]] = []
    for record in records:
        fields(record, {"content", "signature"})
        content = fields(record["content"], {"assessment", "review", "next"})
        manifest = content["assessment"]
        review = fields(content["review"], {"at", "reviewer", "reason", "outcome"})
        body, signed = signed_body(authority, record["signature"], CLOSURE_TYPE, now)
        at = timestamp(review["at"])
        require(
            body == {"content_sha256": digest(content)} and at <= signed,
            "Closure signature or review time does not match the retained content.",
        )
        fields(
            manifest,
            {
                "plan",
                "binding",
                "epoch",
                "epoch_started",
                "snapshot_digest",
                "attempts",
                "proofs",
                "failure",
            },
        )
        text(review["reviewer"], "reviewer", 128)
        text(review["reason"], "review reason")
        plan = manifest["plan"]
        normalized = parse_plan(
            {
                **plan,
                "steps": [
                    {"step_id": name, **step} for name, step in plan["steps"].items()
                ],
            }
        )
        require(
            canonical_bytes(plan) == canonical_bytes(normalized),
            "Invalid retained plan.",
        )
        binding = fields(
            manifest["binding"],
            {
                "nonce",
                "proposer",
                "contract",
                "parent",
                "scope",
                "trust_digest",
                "max_age_seconds",
            },
        )
        sha256(binding["nonce"])
        identifier(binding["proposer"])
        require(
            set(binding["scope"]) == set(plan["steps"])
            and canonical_bytes(parse_contract(binding["contract"], plan))
            == canonical_bytes(binding["contract"])
            and set(manifest["attempts"]) <= set(plan["steps"])
            and timestamp(manifest["epoch_started"]) <= at,
            "Invalid closure contract, attempts, scope or epoch.",
        )
        contents.append(content)
    return contents


def verify_bundle(
    bundle: dict[str, Any],
    authority: TrustPolicy,
    policies: dict[str, TrustPolicy],
    *,
    operation_id: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate the signed closure chain and independently recompute its verdict."""
    try:
        return _verify_bundle(
            bundle,
            authority,
            policies,
            identifier(operation_id),
            now or datetime.now(UTC),
        )
    except (KeyError, TypeError, AttributeError, OverflowError, OperationError) as exc:
        raise AuthorityProofError(
            "Malformed verification closure or trust binding."
        ) from exc


def _verify_bundle(
    bundle: dict[str, Any],
    authority: TrustPolicy,
    policies: dict[str, TrustPolicy],
    operation_id: str,
    now: datetime,
) -> dict[str, Any]:
    validate_roles(policies, authority)
    contents = _verified_records(bundle, authority, policies, now)
    root, leaf = contents[0], contents[-1]
    require(
        root["assessment"]["plan"]["operation_id"] == operation_id,
        "Closure belongs to another operation.",
    )
    seen = set()
    for index, content in enumerate(contents):
        manifest, review = content["assessment"], content["review"]
        op = manifest["plan"]["operation_id"]
        require(op not in seen, "Repeated operation in closure chain.")
        seen.add(op)
        at = timestamp(review["at"])
        report = evaluate(manifest, authority, policies, at)
        if index == len(contents) - 1:
            require(content["next"] is None, "Closure chain is truncated.")
            require(
                review["outcome"]
                == ("verified" if report["status"] == "verified" else "abandoned"),
                "Terminal review does not match recomputed criteria.",
            )
            continue
        child = contents[index + 1]["assessment"]
        link = child["binding"]["parent"]
        mode = link["mode"]
        require(
            manifest["failure"]
            and link
            == {
                "operation_id": op,
                "mode": mode,
                "failure_sha256": digest(manifest["failure"]),
            }
            and inherited_contract(
                manifest["binding"]["contract"], child["binding"]["contract"], mode
            )
            and manifest["binding"]["scope"] == child["binding"]["scope"]
            and content["next"] == digest(bundle["records"][index + 1])
            and timestamp(contents[index + 1]["review"]["at"]) <= at
            and review["outcome"]
            == (
                "abandoned" if leaf["review"]["outcome"] == "abandoned" else "followup"
            ),
            "Closure does not link to the authorized follow-up and inherited requirements.",
        )
        require(
            leaf["review"]["outcome"] == "abandoned"
            or evaluate(leaf["assessment"], authority, policies, at)["status"]
            == "verified",
            "Follow-up was not verified when the parent was closed.",
        )

    outcome = leaf["review"]["outcome"]
    if outcome == "verified" and any(
        item["assessment"]["binding"]["parent"]
        and item["assessment"]["binding"]["parent"]["mode"] == "rollback"
        for item in contents
    ):
        outcome = "rolled_back"
    report = evaluate(leaf["assessment"], authority, policies, now)
    return {
        "operation_id": operation_id,
        "closure_sha256": digest(bundle["records"][0]),
        "outcome_at_closure": outcome,
        "current": outcome != "abandoned" and report["status"] == "verified",
        "terminal_operation_id": leaf["assessment"]["plan"]["operation_id"],
        **report,
    }
