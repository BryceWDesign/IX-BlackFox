"""
Vault subsystem.

Vault manages protected state, artifact provenance, hashing, and
confidential-material handling. The first layers provide tamper-evident
sealing, stable fingerprinting, provenance chaining, and integrity-
checked disk state, plus redaction-oriented zeroization helpers without
overstating confidentiality guarantees.
"""

from ix_blackfox.vault.provenance import (
    ProvenanceLedger,
    ProvenanceLedgerSnapshot,
    ProvenanceRecord,
)
from ix_blackfox.vault.seal import (
    SealedPayload,
    fingerprint_bytes,
    seal_payload,
    verify_seal,
    zeroize_text,
)
from ix_blackfox.vault.state_store import (
    VaultStateEntry,
    VaultStateIntegrityError,
    VaultStateStore,
)

__all__ = [
    "ProvenanceLedger",
    "ProvenanceLedgerSnapshot",
    "ProvenanceRecord",
    "SealedPayload",
    "VaultStateEntry",
    "VaultStateIntegrityError",
    "VaultStateStore",
    "fingerprint_bytes",
    "seal_payload",
    "verify_seal",
    "zeroize_text",
]
