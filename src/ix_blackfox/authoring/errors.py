from __future__ import annotations


class AuthoringError(RuntimeError):
    """
    Base exception for Wave 3 patch-authoring failures.
    """


class AuthoringContextError(AuthoringError):
    """
    Raised when bounded repository context collection fails.
    """


class AuthoringEvidenceError(AuthoringError):
    """
    Raised when failure evidence cannot be extracted or normalized.
    """


class AuthoringDecompositionError(AuthoringError):
    """
    Raised when a repair objective cannot be decomposed safely.
    """


class AuthoringHypothesisError(AuthoringError):
    """
    Raised when repair hypothesis generation fails.
    """


class AuthoringParseError(AuthoringError):
    """
    Raised when untrusted model proposal text cannot be parsed.
    """


class AuthoringValidationError(AuthoringError):
    """
    Raised when untrusted model proposal text violates the Wave 3 schema,
    path, or safety contract.
    """


class AuthoringCompilationError(AuthoringError):
    """
    Raised when a parsed proposal cannot be compiled into a governed PatchDiff.
    """


class AuthoringPolicyError(AuthoringError):
    """
    Raised when authoring policy evaluation fails.
    """


class AuthoringCandidateError(AuthoringError):
    """
    Raised when authored candidate ranking or selection fails.
    """


class AuthoringReceiptError(AuthoringError):
    """
    Raised when authoring receipt-chain construction or validation fails.
    """
