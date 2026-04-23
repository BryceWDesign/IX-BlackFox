from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any

from ix_blackfox.vault.seal import SealedPayload, seal_payload, verify_seal


class VaultStateIntegrityError(RuntimeError):
    """
    Raised when stored vault state fails integrity validation.
    """


@dataclass(frozen=True, slots=True)
class VaultStateEntry:
    """
    One persisted vault state entry.

    Attributes
    ----------
    key:
        Stable logical key for the stored state.
    purpose:
        Logical purpose namespace bound into the seal.
    sealed:
        Integrity-sealed payload envelope.
    path:
        Filesystem path where the entry is stored.
    """

    key: str
    purpose: str
    sealed: SealedPayload
    path: Path

    def payload_dict(self) -> dict[str, Any]:
        """
        Return the decoded stored payload.
        """
        return self.sealed.payload_dict()


class VaultStateStore:
    """
    Disk-backed integrity-protected state store.

    This store persists JSON-serializable payloads to disk and verifies
    tamper-evident seals on read. It does not provide confidentiality.
    """

    def __init__(
        self,
        *,
        root_dir: Path | None = None,
        secret: str | bytes,
        purpose_namespace: str = "vault-state",
    ) -> None:
        resolved_root = (
            Path.cwd() / ".blackfox" / "state" / "vault"
            if root_dir is None
            else root_dir
        )
        self._root_dir = resolved_root.resolve()
        self._secret = secret
        self._purpose_namespace = _normalize_text(
            purpose_namespace,
            label="purpose namespace",
        )
        self._lock = RLock()
        self._root_dir.mkdir(parents=True, exist_ok=True)

    def put(self, key: str, payload: dict[str, Any]) -> VaultStateEntry:
        """
        Persist a payload under a logical key.
        """
        normalized_key = _normalize_key(key)
        purpose = self._entry_purpose(normalized_key)
        sealed = seal_payload(payload, secret=self._secret, purpose=purpose)
        entry_path = self._entry_path(normalized_key)

        serialized = {
            "key": normalized_key,
            "purpose": purpose,
            "sealed": {
                "purpose": sealed.purpose,
                "payload_b64": sealed.payload_b64,
                "digest": sealed.digest,
                "created_at": sealed.created_at.isoformat(),
                "algorithm": sealed.algorithm,
            },
        }

        with self._lock:
            entry_path.write_text(
                json.dumps(
                    serialized,
                    sort_keys=True,
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

        return VaultStateEntry(
            key=normalized_key,
            purpose=purpose,
            sealed=sealed,
            path=entry_path,
        )

    def get(self, key: str) -> VaultStateEntry | None:
        """
        Read and verify a persisted entry by key.
        """
        normalized_key = _normalize_key(key)
        entry_path = self._entry_path(normalized_key)

        with self._lock:
            if not entry_path.exists():
                return None
            raw = json.loads(entry_path.read_text(encoding="utf-8"))

        entry = _decode_entry(raw=raw, path=entry_path)

        expected_purpose = self._entry_purpose(normalized_key)
        if entry.key != normalized_key:
            raise VaultStateIntegrityError(
                f"Stored key mismatch for '{normalized_key}'."
            )
        if entry.purpose != expected_purpose:
            raise VaultStateIntegrityError(
                f"Stored purpose mismatch for '{normalized_key}'."
            )
        if not verify_seal(entry.sealed, secret=self._secret):
            raise VaultStateIntegrityError(
                f"Integrity verification failed for '{normalized_key}'."
            )

        return entry

    def delete(self, key: str) -> bool:
        """
        Delete a stored entry by key.
        """
        normalized_key = _normalize_key(key)
        entry_path = self._entry_path(normalized_key)

        with self._lock:
            if not entry_path.exists():
                return False
            entry_path.unlink()
            return True

    def keys(self) -> tuple[str, ...]:
        """
        Return all stored keys in sorted order.
        """
        with self._lock:
            return tuple(
                sorted(path.stem for path in self._root_dir.glob("*.json"))
            )

    def clear(self) -> None:
        """
        Remove all stored entries.
        """
        with self._lock:
            for path in self._root_dir.glob("*.json"):
                path.unlink()

    def _entry_path(self, key: str) -> Path:
        return self._root_dir / f"{key}.json"

    def _entry_purpose(self, key: str) -> str:
        return f"{self._purpose_namespace}:{key}"


def _decode_entry(*, raw: dict[str, Any], path: Path) -> VaultStateEntry:
    try:
        sealed_raw = raw["sealed"]
        sealed = SealedPayload(
            purpose=str(sealed_raw["purpose"]),
            payload_b64=str(sealed_raw["payload_b64"]),
            digest=str(sealed_raw["digest"]),
            created_at=_parse_datetime(str(sealed_raw["created_at"])),
            algorithm=str(sealed_raw.get("algorithm", "hmac-sha256")),
        )
        return VaultStateEntry(
            key=_normalize_key(str(raw["key"])),
            purpose=_normalize_text(str(raw["purpose"]), label="purpose"),
            sealed=sealed,
            path=path.resolve(),
        )
    except KeyError as exc:
        raise VaultStateIntegrityError(
            f"Stored state entry is malformed: missing field {exc!s}."
        ) from exc
    except ValueError as exc:
        raise VaultStateIntegrityError(
            f"Stored state entry is invalid: {exc}"
        ) from exc


def _parse_datetime(value: str):
    from datetime import datetime

    return datetime.fromisoformat(value)


def _normalize_key(value: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError("Vault state key must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"Vault state {label} must not be empty.")
    return cleaned
