"""Typed exceptions for S3 operations.

Every layer that talks to boto3 raises one of these (instead of bare
`ValueError("...")` or `RuntimeError("...")`). HTTP and MCP boundary
handlers catch the base `S3OperationError` and map `.code` + `.http_status`
to the appropriate response.

The `code` field carries the raw boto error code (e.g. "AccessDenied",
"NoSuchBucket", "InvalidRegion") so frontends and AI agents can render
specific guidance instead of a generic "something failed".
"""

from __future__ import annotations

from typing import ClassVar


class S3OperationError(Exception):
    """Base class for typed S3 errors.

    Subclasses set their default `http_status` via a class-level attribute;
    callers can still override per-call by passing `http_status=...`.
    """

    # Subclasses override this. The base default is 500 (server error).
    default_http_status: ClassVar[int] = 500

    def __init__(self, code: str, message: str, http_status: int | None = None) -> None:
        self.code = code
        self.http_status = http_status if http_status is not None else self.default_http_status
        super().__init__(message)


class S3ConfigError(S3OperationError):
    """Bad role config — invalid region, malformed endpoint, missing creds."""

    default_http_status: ClassVar[int] = 400


class S3AccessDeniedError(S3OperationError):
    """S3 returned AccessDenied / Forbidden."""

    default_http_status: ClassVar[int] = 403


class S3NotFoundError(S3OperationError):
    """S3 returned NoSuchBucket / NoSuchKey / 404."""

    default_http_status: ClassVar[int] = 404


class S3NetworkError(S3OperationError):
    """Connect timeout, DNS failure, EndpointConnectionError."""

    default_http_status: ClassVar[int] = 502


class CredentialsExpiredError(S3OperationError):
    """STS / assume_role / refresh failure — re-auth required."""

    default_http_status: ClassVar[int] = 401
