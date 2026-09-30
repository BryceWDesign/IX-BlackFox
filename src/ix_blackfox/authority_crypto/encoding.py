from __future__ import annotations

import base64
import hashlib
import json
import math
from pathlib import Path
from typing import Any

RECEIPT_TYPE = "application/vnd.ix-blackfox.authority-receipt.v16+json"
CHECKPOINT_TYPE = "application/vnd.ix-blackfox.authority-checkpoint.v16+json"
MAX_DOCUMENT_BYTES = 64 * 1024 * 1024


class AuthorityProofError(ValueError):
    """An authority proof cannot be established, with no unsigned fallback."""


def _validate(value: Any) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise AuthorityProofError("Unpaired Unicode surrogate.")
    elif isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise AuthorityProofError("Integer exceeds interoperable exact range.")
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise AuthorityProofError("Non-finite JSON number.")
    elif isinstance(value, list):
        for item in value:
            _validate(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AuthorityProofError("JSON object keys must be strings.")
            _validate(key)
            _validate(item)
    else:
        raise AuthorityProofError("Unsupported JSON value.")


def canonical_bytes(value: Any) -> bytes:
    """BlackFox JSON profile v1 (Python 3.11+), explicitly not RFC 8785."""
    try:
        _validate(value)
        result = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (RecursionError, UnicodeError, ValueError) as exc:
        raise AuthorityProofError("Invalid canonical JSON.") from exc
    if len(result) > MAX_DOCUMENT_BYTES:
        raise AuthorityProofError("Proof exceeds document size limit.")
    return result


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def strict_json(raw: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise AuthorityProofError("Duplicate JSON key.")
            result[key] = value
        return result

    def invalid(value: str) -> None:
        raise AuthorityProofError("Non-finite JSON number.")

    if len(raw) > MAX_DOCUMENT_BYTES:
        raise AuthorityProofError("Proof exceeds document size limit.")
    try:
        result = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise AuthorityProofError("Invalid or ambiguous JSON.") from exc
    if not isinstance(result, dict):
        raise AuthorityProofError("Document must be a JSON object.")
    canonical_bytes(result)
    return result


def read_document(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        return strict_json(stream.read(MAX_DOCUMENT_BYTES + 1))


def fields(value: Any, expected: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise AuthorityProofError("Unexpected or missing proof fields.")
    return value


def text_field(value: dict[str, Any], name: str) -> str:
    result = value.get(name)
    if not isinstance(result, str) or not result.strip():
        raise AuthorityProofError(f"{name} must be a non-empty string.")
    return result


def encode64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def decode64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise AuthorityProofError("Invalid base64 value.")
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise AuthorityProofError("Invalid base64 value.") from exc
    if encode64(result) != value:
        raise AuthorityProofError("Non-canonical base64 value.")
    return result


def pae(payload_type: str, payload: bytes) -> bytes:
    kind = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(kind)).encode("ascii")
        + b" "
        + kind
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )
