"""
Vault subsystem.

Vault manages protected state, artifact provenance, hashing, and
confidential-material handling. The first layers provide tamper-evident
sealing, stable fingerprinting, provenance chaining, and redaction-
oriented zeroization helpers without overstating confidentiality
guarantees.
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

__all__ = [
    "ProvenanceLedger",
    "ProvenanceLedgerSnapshot",
    "ProvenanceRecord",
    "SealedPayload",
    "fingerprint_bytes",
    "seal_payload",
    "verify_seal",
    "zeroize_text",
]
