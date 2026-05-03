from __future__ import annotations


class AuthoringError(Exception):
    """
    Base exception for IX-BlackFox Wave 3 authoring failures.

    Authoring failures are distinct from Wave 2 patch execution failures. A
    proposal can fail during context collection, evidence normalization,
    decomposition, parsing, policy, or patch compilation before it ever reaches
    the governed Wave 2 repair loop.
    """


class AuthoringValidationError(AuthoringError):
    """
    Raised when an authoring model, request, proposal, or receipt is malformed.
    """


class AuthoringContextError(AuthoringError):
    """
    Raised when repository context cannot be collected or bounded safely.
    """


class AuthoringEvidenceError(AuthoringError):
    """
    Raised when failure or objective evidence cannot be normalized safely.
    """


class AuthoringDecompositionError(AuthoringError):
    """
    Raised when a repair objective cannot be decomposed into reviewable tasks.
    """


class AuthoringPolicyError(AuthoringError):
    """
    Raised when an authored candidate violates Wave 3 authoring policy.
    """


class AuthoringCompilationError(AuthoringError):
    """
    Raised when a validated proposal cannot compile into a governed patch.
    """


class AuthoringProviderError(AuthoringError):
    """
    Raised when a deterministic or model-assisted authoring provider fails.
    """
