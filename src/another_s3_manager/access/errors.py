"""Transport-independent access denials."""


class AccessDenied(PermissionError):
    """Keep legacy PermissionError handling and message text intact."""

    def __init__(self, code: str, message: str, details: dict | None = None) -> None:
        self.code = code
        self.message = message
        self.details = details if details is not None else {}
        super().__init__(message)


class AuthenticationError(AccessDenied):
    """A credential refusal, translated by the calling transport adapter."""
