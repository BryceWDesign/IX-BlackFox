from __future__ import annotations

from ix_blackfox.exceptions import BlackFoxError


class BrainProviderError(BlackFoxError):
    """
    Base error for model-provider interactions in the brain plane.
    """


class BrainProviderConfigurationError(BrainProviderError):
    """
    Raised when provider configuration or manifest mapping is invalid.
    """


class BrainProviderUnavailableError(BrainProviderError):
    """
    Raised when a provider cannot be reached or is not healthy enough to serve.
    """


class BrainProviderTimeoutError(BrainProviderError):
    """
    Raised when a provider operation exceeds its allowed time budget.
    """


class BrainProviderInvocationError(BrainProviderError):
    """
    Raised when a provider invocation fails during request execution.
    """


class BrainProviderProtocolError(BrainProviderError):
    """
    Raised when a provider response violates the expected abstraction contract.
    """
