"""Credential-safe errors shared by optional provider adapters."""


class ProviderError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        provider: str,
        retryable: bool,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.provider = provider
        self.retryable = retryable
        self.status_code = status_code
