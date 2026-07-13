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


class S3ThrottledError(S3OperationError):
    """S3 is rate-limiting us — SlowDown / RequestLimitExceeded / 503."""

    default_http_status: ClassVar[int] = 503


class RoleNotFoundError(ValueError):
    """The requested role does not exist in the configuration.

    Why this is not just a ValueError: validate_role_access() short-circuits for
    admins ("admins have access to all roles"), so for an admin an unknown role
    is NOT caught there — it surfaces later, when get_s3_client() fails to find
    it. That used to be a bare ValueError, which the MCP tools' exception ladder
    swallowed into a useless "INTERNAL_ERROR: Internal server error": the agent
    was told nothing, and the tool call was miscounted as a server fault. A
    non-admin asking for the same role got a proper ROLE_NOT_ALLOWED naming the
    roles it may use — so the answer depended on who was asking.

    Subclasses ValueError ON PURPOSE and nothing else: get_s3_client raises
    ValueError for a dozen unrelated config faults (missing endpoint_url, empty
    keys, unknown role type), and the web routes catch ValueError -> HTTP 400
    for all of them. Keeping ValueError in the bases means every existing web
    handler behaves exactly as before. The MCP tools name this class explicitly
    alongside PermissionError so an unknown role becomes ROLE_NOT_ALLOWED there
    — actionable for an agent — without a blanket `except ValueError` that would
    disguise real config errors as permission problems.
    """


# ----- Classifier ------------------------------------------------------------

# Boto error codes that map to S3ConfigError (admin needs to fix the role).
_CONFIG_ERROR_CODES = {
    "InvalidRegion",
    "InvalidLocationConstraint",
    "InvalidAccessKeyId",
    "InvalidArgument",
    "SignatureDoesNotMatch",
    "InvalidBucketName",
    "InvalidEndpoint",
    "AuthorizationHeaderMalformed",
}

# Codes that mean "not found".
_NOT_FOUND_CODES = {"NoSuchBucket", "NoSuchKey", "404"}

# Codes that mean "denied".
_ACCESS_DENIED_CODES = {"AccessDenied", "Forbidden", "AllAccessDisabled"}

# Codes that mean "auth/STS expiry — re-auth required".
_EXPIRED_CODES = {
    "ExpiredToken",
    "ExpiredTokenException",
    "TokenRefreshRequired",
    "RequestExpired",
}

# Codes that mean "slow down, you're being rate-limited".
_THROTTLED_CODES = {
    "SlowDown",
    "RequestLimitExceeded",
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
    "ServiceUnavailable",
    "503",
}


def classify_boto_error(error: BaseException) -> S3OperationError:
    """Convert a boto / arbitrary exception into the right typed S3 error.

    Inspects ClientError's `Error.Code` and `ResponseMetadata.HTTPStatusCode`
    when available. Falls back to checking exception class name for the
    botocore-side errors (EndpointConnectionError etc) which don't carry
    response dicts.

    Classifies by bucket in order: expired tokens, access denied, not found,
    config errors, then throttling (code in _THROTTLED_CODES or HTTP 503).
    The specific-code buckets are checked before the generic 503 catch-all,
    ensuring that e.g. an AccessDenied response with HTTP 503 still classifies
    as S3AccessDeniedError, not S3ThrottledError.

    For an unknown error code or a non-boto exception, returns a base
    `S3OperationError` with `code="Unknown"` and `http_status=500`.
    """
    # Already typed — pass through (idempotent).
    if isinstance(error, S3OperationError):
        return error

    # Network-layer errors don't have response dicts; classify by class name.
    network_class_names = {
        "EndpointConnectionError",
        "ConnectTimeoutError",
        "ReadTimeoutError",
        "ConnectionClosedError",
        "DnsResolveError",
    }
    if type(error).__name__ in network_class_names:
        return S3NetworkError(
            code=type(error).__name__,
            message=str(error) or "Network error talking to S3 endpoint",
        )

    # ClientError with response dict.
    response = getattr(error, "response", None)
    if isinstance(response, dict):
        err_dict = response.get("Error", {}) if isinstance(response.get("Error"), dict) else {}
        code = str(err_dict.get("Code") or "Unknown")
        message = str(err_dict.get("Message") or str(error) or "S3 error")
        http_status = 500
        meta = response.get("ResponseMetadata", {})
        if isinstance(meta, dict):
            try:
                http_status = int(meta.get("HTTPStatusCode") or 500)
            except (ValueError, TypeError):
                http_status = 500

        if code in _EXPIRED_CODES:
            return CredentialsExpiredError(code, message)
        if code in _ACCESS_DENIED_CODES:
            return S3AccessDeniedError(code, message)
        if code in _NOT_FOUND_CODES:
            return S3NotFoundError(code, message)
        if code in _CONFIG_ERROR_CODES:
            return S3ConfigError(code, message)
        # A 503 is throttling even when the code is unfamiliar (S3-compatible
        # providers invent their own). Check the code set first so a 400
        # `Throttling` is still caught.
        if code in _THROTTLED_CODES or http_status == 503:
            return S3ThrottledError(code, message)

        # Unknown code: keep the boto status if it's a real HTTP code, else 500.
        return S3OperationError(code, message, http_status=http_status if http_status >= 400 else 500)

    # Arbitrary Exception — last resort.
    return S3OperationError("Unknown", str(error) or repr(error))


# ----- Metric label taxonomy -------------------------------------------------

# Exact-type lookup, not isinstance: every entry is a direct subclass of
# S3OperationError, so an unmapped subclass correctly falls through to "other"
# rather than silently inheriting a parent's label.
_METRIC_LABEL_BY_TYPE: dict[type, str] = {
    S3AccessDeniedError: "access_denied",
    S3NotFoundError: "not_found",
    CredentialsExpiredError: "credentials_expired",
    S3NetworkError: "network_error",
    S3ConfigError: "config_error",
    S3ThrottledError: "throttled",
}


def error_code_label(error: BaseException) -> str:
    """Map any exception to a bounded `error_code` metric label.

    The returned value is one of a fixed set — never a raw boto code, whose
    cardinality is unbounded. `"none"` is NOT produced here; it is the success
    path's label.
    """
    typed = classify_boto_error(error)
    return _METRIC_LABEL_BY_TYPE.get(type(typed), "other")
