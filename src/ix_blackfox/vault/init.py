"""
Vault subsystem.

Vault manages protected state, artifact provenance, hashing, and
confidential-material handling. The first layer provides tamper-evident
sealing, stable fingerprinting, and redaction-oriented zeroization
helpers without overstating confidentiality guarantees.
"""

from ix_blackfox.vault.seal import (
    SealedPayload,
    fingerprint_bytes,
    seal_payload,
    verify_seal,
    zeroize_text,
)

__all__ = [
    "SealedPayload",
    "fingerprint_bytes",
    "seal_payload",
    "verify_seal",
    "zeroize_text",
]
