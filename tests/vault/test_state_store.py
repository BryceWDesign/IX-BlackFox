from __future__ import annotations

import json
from pathlib import Path

import pytest

from ix_blackfox.vault import (
    VaultStateIntegrityError,
    VaultStateStore,
)


def test_vault_state_store_put_get_and_keys(tmp_path: Path) -> None:
    store = VaultStateStore(
        root_dir=tmp_path / "vault-state",
        secret="blackfox-secret",
    )

    stored = store.put(
        "Kernel Status",
        {"status": "ready", "debug": False},
    )
    fetched = store.get("kernel status")

    assert stored.key == "kernel status"
    assert stored.path.name == "kernel status.json"
    assert fetched is not None
    assert fetched.key == "kernel status"
    assert fetched.payload_dict() == {"debug": False, "status": "ready"}
    assert store.keys() == ("kernel status",)


def test_vault_state_store_detects_tampering(tmp_path: Path) -> None:
    store = VaultStateStore(
        root_dir=tmp_path / "vault-state",
        secret="blackfox-secret",
    )
    stored = store.put(
        "task-state",
        {"status": "running"},
    )

    raw = json.loads(stored.path.read_text(encoding="utf-8"))
    raw["sealed"]["payload_b64"] = "eyJzdGF0dXMiOiJjb21wcm9taXNlZCJ9"
    stored.path.write_text(
        json.dumps(raw, sort_keys=True, indent=2),
        encoding="utf-8",
    )

    with pytest.raises(VaultStateIntegrityError, match="Integrity verification failed"):
        store.get("task-state")


def test_vault_state_store_detects_key_or_purpose_mismatch(tmp_path: Path) -> None:
    store = VaultStateStore(
        root_dir=tmp_path / "vault-state",
        secret="blackfox-secret",
    )
    stored = store.put(
        "session-state",
        {"active": True},
    )

    raw = json.loads(stored.path.read_text(encoding="utf-8"))
    raw["key"] = "other-key"
    stored.path.write_text(
        json.dumps(raw, sort_keys=True, indent=2),
        encoding="utf-8",
    )

    with pytest.raises(VaultStateIntegrityError, match="Stored key mismatch"):
        store.get("session-state")


def test_vault_state_store_delete_and_clear(tmp_path: Path) -> None:
    store = VaultStateStore(
        root_dir=tmp_path / "vault-state",
        secret="blackfox-secret",
    )
    store.put("a", {"value": 1})
    store.put("b", {"value": 2})

    assert store.delete("a") is True
    assert store.delete("a") is False
    assert store.keys() == ("b",)

    store.clear()

    assert store.keys() == ()
    assert store.get("b") is None


@pytest.mark.parametrize(
    ("key", "message"),
    [
        ("", "Vault state key must not be empty"),
        ("   ", "Vault state key must not be empty"),
    ],
)
def test_vault_state_store_rejects_empty_keys(
    tmp_path: Path,
    key: str,
    message: str,
) -> None:
    store = VaultStateStore(
        root_dir=tmp_path / "vault-state",
        secret="blackfox-secret",
    )

    with pytest.raises(ValueError, match=message):
        store.put(key, {"value": 1})


def test_vault_state_store_rejects_empty_namespace(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Vault state purpose namespace must not be empty"):
        VaultStateStore(
            root_dir=tmp_path / "vault-state",
            secret="blackfox-secret",
            purpose_namespace="   ",
        )
