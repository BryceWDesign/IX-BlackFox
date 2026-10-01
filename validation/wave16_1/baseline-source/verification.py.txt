from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ix_blackfox.authority_crypto.encoding import (
    CHECKPOINT_TYPE,
    RECEIPT_TYPE,
    AuthorityProofError,
    canonical_bytes,
    digest,
    fields,
)
from ix_blackfox.authority_crypto.trust import TrustPolicy, timestamp
from ix_blackfox.operating.models import digest_payload

RECEIPT_SCHEMA = "wave16.authority_receipt.v1"
BUNDLE_SCHEMA = "wave16.receipt_bundle.v1"
CHECKPOINT_SCHEMA = "wave16.checkpoint.v1"


def verify_receipt(receipt: dict[str, Any], policy: TrustPolicy) -> dict[str, Any]:
    body = {key: value for key, value in receipt.items() if key != "attestation"}
    signed = policy.verify(receipt.get("attestation"), RECEIPT_TYPE)
    if canonical_bytes(signed) != canonical_bytes(body):
        raise AuthorityProofError("Receipt fields differ from signed body.")
    if body.get("schema_version") != RECEIPT_SCHEMA or (
        body.get("deployment_id"),
        body.get("stream_id"),
    ) != (policy.deployment_id, policy.stream_id):
        raise AuthorityProofError("Receipt schema or trust domain mismatch.")
    without_digest = {
        key: value for key, value in body.items() if key != "receipt_digest"
    }
    if body.get("receipt_digest") != digest(without_digest):
        raise AuthorityProofError("Receipt digest mismatch.")
    without_id = {
        key: value for key, value in without_digest.items() if key != "receipt_id"
    }
    if body.get("receipt_id") != "wave16-receipt-" + digest(without_id):
        raise AuthorityProofError("Receipt ID mismatch.")
    if (
        type(body.get("sequence")) is not int
        or body["sequence"] < 1
        or not isinstance(body.get("previous_receipt_digest"), str)
    ):
        raise AuthorityProofError("Invalid receipt sequence.")
    kind = body.get("record_type")
    if kind not in {"authorization", "outcome", "denial"}:
        raise AuthorityProofError("Invalid signed record type.")
    expected = {
        "schema_version",
        "deployment_id",
        "stream_id",
        "sequence",
        "previous_receipt_digest",
        "receipt_id",
        "receipt_digest",
        "recorded_at",
        "protocol",
        "record_type",
        "subject",
        "authority_decision",
        "authenticated_principal",
        "evidence_refs",
        "evaluated_evidence_digests",
        "single_use_evidence_claims",
        "upstream_attempted",
        "upstream_status",
        "upstream_response_sha256",
        "upstream_error",
        "execution_state",
        "executed",
    }
    if kind == "outcome":
        expected |= {"authorization_receipt_id", "authorization_receipt_digest"}
    fields(body, expected)
    timestamp(body["recorded_at"])
    if (
        not isinstance(body["protocol"], str)
        or not body["protocol"]
        or not isinstance(body["subject"], dict)
        or not isinstance(body["authority_decision"], dict)
        or not isinstance(body["authenticated_principal"], dict)
    ):
        raise AuthorityProofError("Malformed signed authority context.")
    refs = body["evidence_refs"]
    if (
        not isinstance(refs, list)
        or any(not isinstance(item, str) or not item for item in refs)
        or len(refs) != len(set(refs))
    ):
        raise AuthorityProofError("Malformed evidence references.")
    if not isinstance(body["evaluated_evidence_digests"], dict) or any(
        not isinstance(key, str)
        or not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
        for key, value in body["evaluated_evidence_digests"].items()
    ):
        raise AuthorityProofError("Malformed evidence digest map.")
    if (
        type(body["upstream_status"]) is not int
        or not 0 <= body["upstream_status"] <= 599
        or not isinstance(body["upstream_error"], str)
        or not isinstance(body["upstream_response_sha256"], str)
    ):
        raise AuthorityProofError("Malformed upstream observation.")
    if (
        type(body.get("upstream_attempted")) is not bool
        or type(body.get("executed")) is not bool
    ):
        raise AuthorityProofError("Execution flags must be booleans.")
    if kind in {"authorization", "outcome"}:
        subject, decision, principal = (
            body.get("subject"),
            body.get("authority_decision"),
            body.get("authenticated_principal"),
        )
        if (
            not isinstance(subject, dict)
            or subject.get("schema_version") != "wave14.authority_subject.v1"
            or subject.get("digest")
            != digest_payload(
                {key: value for key, value in subject.items() if key != "digest"}
            )
        ):
            raise AuthorityProofError("Authority subject digest mismatch.")
        if (
            not isinstance(decision, dict)
            or decision.get("digest")
            != digest_payload(
                {key: value for key, value in decision.items() if key != "digest"}
            )
            or decision.get("allowed") is not True
            or decision.get("status") != "allow"
            or canonical_bytes(decision.get("subject")) != canonical_bytes(subject)
        ):
            raise AuthorityProofError("Signed authority decision is inconsistent.")
        if not isinstance(principal, dict) or principal.get("agent_id") != subject.get(
            "agent_id"
        ):
            raise AuthorityProofError("Authenticated principal binding mismatch.")
        if not isinstance(subject.get("metadata"), dict):
            raise AuthorityProofError("Malformed subject metadata.")
        if principal.get("authentication_type") == "oidc_jwt" and subject.get(
            "metadata", {}
        ).get("identity_context_digest") != digest_payload(principal):
            raise AuthorityProofError("Federated principal context mismatch.")
        evidence = decision.get("evidence")
        if (
            not isinstance(evidence, dict)
            or not isinstance(evidence.get("verifications"), list)
            or any(not isinstance(item, dict) for item in evidence["verifications"])
        ):
            raise AuthorityProofError("Malformed evaluated evidence.")
        expected_evidence = {
            item["evidence_id"]: item["digest"]
            for item in decision.get("evidence", {}).get("verifications", [])
            if item.get("passed") is True
        }
        if canonical_bytes(body.get("evaluated_evidence_digests")) != canonical_bytes(
            expected_evidence
        ):
            raise AuthorityProofError("Evidence digest binding mismatch.")
    if kind == "authorization" and (
        body["upstream_attempted"]
        or body["executed"]
        or body.get("execution_state") != "authorized_not_dispatched"
    ):
        raise AuthorityProofError("Authorization cannot claim execution.")
    if kind == "denial" and (
        body["upstream_attempted"]
        or body["executed"]
        or body.get("execution_state") != "not_attempted"
    ):
        raise AuthorityProofError("Denial cannot claim execution.")
    if kind == "outcome" and (
        body["upstream_attempted"] is not True
        or body.get("execution_state") not in {"response_received", "outcome_unknown"}
    ):
        raise AuthorityProofError("Invalid outcome execution state.")
    claims = body.get("single_use_evidence_claims")
    if (
        not isinstance(claims, list)
        or any(not isinstance(item, str) or not item for item in claims)
        or len(claims) != len(set(claims))
    ):
        raise AuthorityProofError("Malformed evidence claims.")
    if kind in {"authorization", "outcome"} and not set(claims).issubset(refs):
        raise AuthorityProofError(
            "Evidence claims are absent from the authority references."
        )
    if kind == "outcome" and body["executed"] is not (
        body["execution_state"] == "response_received"
    ):
        raise AuthorityProofError(
            "Outcome execution flag contradicts its observed state."
        )
    return body


def verify_records(
    receipts: list[dict[str, Any]], policy: TrustPolicy
) -> tuple[str, tuple[str, ...]]:
    head = ""
    authorizations: dict[str, dict[str, Any]] = {}
    completed: set[str] = set()
    ids: set[str] = set()
    claims: set[str] = set()
    for sequence, receipt in enumerate(receipts, 1):
        body = verify_receipt(receipt, policy)
        if (
            body["sequence"] != sequence
            or body["previous_receipt_digest"] != head
            or body["receipt_id"] in ids
        ):
            raise AuthorityProofError(
                "Receipt chain has a gap, duplicate or reordering."
            )
        ids.add(body["receipt_id"])
        kind = body["record_type"]
        if kind == "authorization":
            if claims.intersection(body["single_use_evidence_claims"]):
                raise AuthorityProofError(
                    "Single-use evidence authorized more than once."
                )
            claims.update(body["single_use_evidence_claims"])
            authorizations[body["receipt_id"]] = body
        elif kind == "outcome":
            parent_id = body.get("authorization_receipt_id")
            parent = (
                authorizations.get(parent_id) if isinstance(parent_id, str) else None
            )
            if (
                parent is None
                or parent_id in completed
                or body.get("authorization_receipt_digest") != parent["receipt_digest"]
            ):
                raise AuthorityProofError(
                    "Outcome lacks a unique earlier authorization."
                )
            for field in (
                "subject",
                "authority_decision",
                "authenticated_principal",
                "evidence_refs",
                "evaluated_evidence_digests",
                "single_use_evidence_claims",
            ):
                if canonical_bytes(body.get(field)) != canonical_bytes(
                    parent.get(field)
                ):
                    raise AuthorityProofError(
                        "Outcome does not match its authorization."
                    )
            completed.add(str(parent_id))
        elif body["single_use_evidence_claims"]:
            raise AuthorityProofError(
                "Denial cannot claim consumption under authorization."
            )
        head = body["receipt_digest"]
    return head, tuple(item for item in authorizations if item not in completed)


def checkpoint_body(
    receipts: list[dict[str, Any]], policy: TrustPolicy
) -> dict[str, Any]:
    return {
        "schema_version": CHECKPOINT_SCHEMA,
        "deployment_id": policy.deployment_id,
        "stream_id": policy.stream_id,
        "receipt_count": len(receipts),
        "head_digest": receipts[-1]["receipt_digest"] if receipts else "",
        "receipts_sha256": digest(receipts),
    }


@dataclass(frozen=True)
class BundleVerification:
    passed: bool
    receipt_count: int = 0
    head_digest: str = ""
    checkpoint_matched: bool = False
    unresolved_authorizations: tuple[str, ...] = ()
    issues: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "wave16.verification.v1",
            "passed": self.passed,
            "receipt_count": self.receipt_count,
            "head_digest": self.head_digest,
            "checkpoint_matched": self.checkpoint_matched,
            "unresolved_authorizations": list(self.unresolved_authorizations),
            "issues": list(self.issues),
            "scope": "Pinned gateway signatures and receipt/checkpoint consistency; execution is the gateway observation, not proof of arbitrary side effects.",
            "completeness": "Matches supplied expected checkpoint; rollback protection depends on independent retention."
            if self.checkpoint_matched
            else "Latestness is not established without a separately retained expected checkpoint.",
        }


def verify_bundle(
    bundle: dict[str, Any],
    policy: TrustPolicy,
    *,
    expected_checkpoint: dict[str, Any] | None = None,
) -> BundleVerification:
    try:
        fields(
            bundle,
            {"schema_version", "deployment_id", "stream_id", "receipts", "checkpoint"},
        )
        if bundle["schema_version"] != BUNDLE_SCHEMA or (
            bundle["deployment_id"],
            bundle["stream_id"],
        ) != (policy.deployment_id, policy.stream_id):
            raise AuthorityProofError("Bundle domain mismatch.")
        receipts = bundle["receipts"]
        if not isinstance(receipts, list) or any(
            not isinstance(item, dict) for item in receipts
        ):
            raise AuthorityProofError("Bundle receipts must be objects.")
        head, pending = verify_records(receipts, policy)
        signed_head = policy.verify(bundle["checkpoint"], CHECKPOINT_TYPE)
        if canonical_bytes(signed_head) != canonical_bytes(
            checkpoint_body(receipts, policy)
        ):
            raise AuthorityProofError("Checkpoint does not match the receipt snapshot.")
        if expected_checkpoint is not None and canonical_bytes(
            policy.verify(expected_checkpoint, CHECKPOINT_TYPE)
        ) != canonical_bytes(signed_head):
            raise AuthorityProofError(
                "Bundle does not match the independently retained checkpoint."
            )
        return BundleVerification(
            True, len(receipts), head, expected_checkpoint is not None, pending
        )
    except (AuthorityProofError, KeyError, TypeError, ValueError) as exc:
        return BundleVerification(False, issues=(str(exc),))
