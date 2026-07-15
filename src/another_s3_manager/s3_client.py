"""
S3 client management module
"""

import heapq
import logging
import os
import threading
import time
from datetime import datetime
from typing import Any, BinaryIO, Callable, Dict, Iterator, Optional, Tuple, TypeVar
from typing import Any as AnyType

import boto3
from botocore.config import Config
from botocore.credentials import RefreshableCredentials
from botocore.exceptions import ClientError, CredentialRetrievalError, MetadataRetrievalError
from botocore.session import Session as BotocoreSession

from another_s3_manager.config import load_config
from another_s3_manager.constants import S3_USE_SSL, S3_VERIFY_SSL

# Cache for S3 clients per role
_s3_clients_cache: Dict[str, AnyType] = {}
# Guards the check-build-store sequence in get_s3_client (double-checked
# locking, same shape as database.py's get_engine). R001 moved every boto3
# call onto a worker-thread pool, so concurrent cache misses for the same
# role are now real — without this lock two threads could both miss, both
# assume the same role / build a client, and race the dict write.
_s3_clients_lock = threading.Lock()
T = TypeVar("T")

# Set up logging
logger = logging.getLogger(__name__)


def _iter_error_chain(error: BaseException):
    """Yield the provided error and every available cause/context."""
    visited_ids = set()
    current = error
    while current and id(current) not in visited_ids:
        visited_ids.add(id(current))
        yield current
        current = getattr(current, "__cause__", None) or getattr(current, "__context__", None)


def _clear_boto3_cached_credentials() -> None:
    """Force boto3/botocore to drop cached credentials so providers refetch new tokens."""
    try:
        # Clear boto3 default session credentials (used by DEFAULT_SESSION and module-level _session)
        default_session = getattr(boto3, "DEFAULT_SESSION", None)
        if default_session is not None:
            try:
                if hasattr(default_session, "_credentials"):
                    default_session._credentials = None
            except Exception as exc:  # noqa: BLE001 - best effort cleanup
                logger.debug("_clear_boto3_cached_credentials: default_session._credentials clear failed: %s", exc)
            try:
                inner_session = getattr(default_session, "_session", None)
                if inner_session is not None and hasattr(inner_session, "_credentials"):
                    inner_session._credentials = None
            except Exception as exc:  # noqa: BLE001 - best effort cleanup
                logger.debug(
                    "_clear_boto3_cached_credentials: default_session._session._credentials clear failed: %s", exc
                )

        module_session = getattr(boto3, "_session", None)
        if module_session is not None and hasattr(module_session, "_credentials"):
            try:
                module_session._credentials = None
            except Exception as exc:  # noqa: BLE001 - best effort cleanup
                logger.debug("_clear_boto3_cached_credentials: module_session._credentials clear failed: %s", exc)

        # Clear credential resolver caches on a fresh botocore session
        import botocore.session

        botocore_session = botocore.session.get_session()
        if hasattr(botocore_session, "_credentials"):
            botocore_session._credentials = None

        credential_resolver = botocore_session.get_component("credential_provider")
        if credential_resolver is not None:
            providers = getattr(credential_resolver, "_providers", [])
            for provider in providers:
                if hasattr(provider, "_creds"):
                    provider._creds = None
                if hasattr(provider, "_loaded_config"):
                    provider._loaded_config = False
                cache_attr = getattr(provider, "cache", None)
                if isinstance(cache_attr, dict):
                    cache_attr.clear()

        # Drop default session entirely so boto3 recreates it with fresh state
        boto3.DEFAULT_SESSION = None
    except Exception as cache_error:  # noqa: BLE001 - we only log best-effort cleanup failures
        logger.debug("Failed to clear boto3 credential cache: %s", cache_error)


def invalidate_s3_client(role_name: Optional[str] = None) -> None:
    """Remove cached S3 client for the specified role."""
    cache_key = role_name or "default"
    _s3_clients_cache.pop(cache_key, None)


def _is_expired_credentials_error(error: BaseException) -> bool:
    """Detect whether an error is caused by expired or invalid credentials."""
    expired_phrases = {
        "token is expired",
        "token expired",
        "expiredtoken",
        "expired token",
        "credentials have expired",
        "basic claim validations",
        "session expired",
        "web identity token has expired",
        "assume role with web identity failed",
        "sts returned error code expiredtokenexception",
        "service account token failed",
    }

    eks_identity_hints = {
        "eks-pod-identity",
        "pod identity agent",
        "iam-tokens.amazonaws.com",
        "aws-iam-token",
        "iam-credentials-service",
        "container metadata",
        "container-role",
    }

    for chained_error in _iter_error_chain(error):
        # Check for MetadataRetrievalError (used by container-role provider)
        if isinstance(chained_error, MetadataRetrievalError):
            message = str(chained_error).lower()
            if any(phrase in message for phrase in expired_phrases):
                logger.debug("MetadataRetrievalError with expired token detected, treating as expired credentials")
                return True

        if isinstance(chained_error, CredentialRetrievalError):
            provider_name = getattr(chained_error, "provider", "unknown")
            # Check if it's from container-role provider (eks-pod-identity)
            if provider_name and "container" in provider_name.lower():
                message = str(chained_error).lower()
                if any(phrase in message for phrase in expired_phrases):
                    logger.debug("CredentialRetrievalError from container-role provider with expired token")
                    return True
            logger.debug(
                "CredentialRetrievalError from provider '%s' treated as expired credentials",
                provider_name,
            )
            return True

        message = str(chained_error).lower()
        if any(phrase in message for phrase in expired_phrases):
            if any(hint in message for hint in eks_identity_hints):
                logger.warning("Detected expired pod identity token, requesting fresh credentials")
            return True

        error_response = getattr(chained_error, "response", None) or {}
        error_code = (error_response.get("Error") or {}).get("Code", "")
        if error_code and error_code.lower() in {
            "expiredtoken",
            "expiredtokenexception",
            "invalididentitytoken",
            "tokenexpired",
            "requestexpired",
        }:
            return True

    return False


def _parse_bool(value: AnyType, default: bool) -> bool:
    """Parse common truthy/falsey values from config."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _get_boto3_config(addressing_style: Optional[str] = None) -> Config:
    """Get boto3 configuration with optional addressing style overrides."""
    config_kwargs = {
        "signature_version": "s3v4",
        "retries": {"max_attempts": 3},
        "connect_timeout": 10,  # 10 seconds connection timeout
        "read_timeout": 30,  # 30 seconds read timeout (for large uploads)
    }
    if addressing_style:
        config_kwargs["s3"] = {"addressing_style": addressing_style}
    return Config(**config_kwargs)


def _new_boto3_session() -> boto3.Session:
    """Build a fresh, explicit boto3 Session for a single client build.

    boto3's module-level helpers (`boto3.client(...)`, `boto3.resource(...)`)
    are documented as NOT thread-safe: they lazily create and share
    `boto3.DEFAULT_SESSION` across every caller in the process. R001 moved
    every S3/STS call onto a worker-thread pool, so concurrent client builds
    (e.g. two roles cold-starting, or two threads racing a cache miss for the
    same role before the lock in get_s3_client is acquired) now genuinely
    race on that shared default session. Building each client from its own
    unshared Session sidesteps that entirely, at the cost of a cheap
    in-memory object per build — cache misses are rare (first request per
    role, or after explicit invalidation), so this is not a hot path.
    """
    return boto3.Session()


def _create_s3_client_from_role(role: Dict[str, Any]) -> AnyType:
    """Create S3 client from role configuration."""
    role_type = role.get("type")
    addressing_style = role.get("addressing_style")
    if not addressing_style:
        # Backwards compatibility for boolean flags
        if _parse_bool(role.get("path_style") or role.get("use_path_style"), False):
            addressing_style = "path"
    boto_config = _get_boto3_config(addressing_style=addressing_style)

    endpoint_url = role.get("endpoint_url")
    use_ssl = _parse_bool(role.get("use_ssl"), S3_USE_SSL)
    verify_ssl = _parse_bool(role.get("verify_ssl"), S3_VERIFY_SSL)

    if role_type == "default":
        client_kwargs = {
            "use_ssl": use_ssl,
            "verify": verify_ssl,
            "config": boto_config,
        }
        if endpoint_url:
            client_kwargs["endpoint_url"] = endpoint_url
        return _new_boto3_session().client("s3", **client_kwargs)

    elif role_type == "profile":
        profile_name = role.get("profile_name")
        if not profile_name:
            raise ValueError("profile_name is required for profile type")
        session = boto3.Session(profile_name=profile_name)
        client_kwargs = {
            "use_ssl": use_ssl,
            "verify": verify_ssl,
            "config": boto_config,
        }
        if endpoint_url:
            client_kwargs["endpoint_url"] = endpoint_url
        return session.client("s3", **client_kwargs)

    elif role_type == "assume_role":
        role_arn = role.get("role_arn")
        if not role_arn:
            raise ValueError("role_arn is required for assume_role type")

        # Region for the STS + assumed-role S3 clients: the role's own region
        # wins, then the AWS_REGION env this app documents. botocore itself only
        # falls back to AWS_DEFAULT_REGION / shared config — in a bare container
        # with just AWS_REGION set, creating the STS client raises NoRegionError
        # ("You must specify a region") even though S3 clients with an explicit
        # endpoint_url get away without one. None keeps botocore's own chain.
        region = (role.get("region") or "").strip() or os.environ.get("AWS_REGION") or None

        def refresh_assumed_role_credentials():
            """Refresh credentials by assuming the role again using current pod identity credentials."""
            try:
                logger.debug(f"Refreshing credentials for assumed role: {role_arn}")
                # Create a fresh STS client that will use current pod identity credentials.
                # Explicit session (not the module-level default) — see _new_boto3_session.
                sts_client = _new_boto3_session().client(
                    "sts", region_name=region, use_ssl=use_ssl, verify=verify_ssl, config=boto_config
                )

                from another_s3_manager.metrics import credentials_refreshed_total, safe_role_label

                _role_lbl = safe_role_label(role.get("name") or "unknown")
                try:
                    assumed_role = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="s3-file-manager-session")
                except Exception:
                    credentials_refreshed_total.labels(role=_role_lbl, result="error").inc()
                    raise
                credentials_refreshed_total.labels(role=_role_lbl, result="ok").inc()
                creds = assumed_role["Credentials"]

                # Get expiration time - keep as string for RefreshableCredentials
                expiration = creds.get("Expiration")
                # RefreshableCredentials expects expiry_time as string, not datetime
                if expiration is not None and isinstance(expiration, datetime):
                    # Convert datetime to ISO format string
                    expiration = expiration.isoformat()
                elif expiration is not None and not isinstance(expiration, str):
                    expiration = None

                logger.debug(f"Successfully refreshed credentials for role {role_arn}, expires at: {expiration}")

                return {
                    "access_key": creds["AccessKeyId"],
                    "secret_key": creds["SecretAccessKey"],
                    "token": creds["SessionToken"],
                    "expiry_time": expiration,  # String or None
                }
            except Exception as e:
                logger.error(f"Failed to refresh credentials for assumed role {role_arn}: {e}", exc_info=True)
                raise

        # Try to create STS client and assume role with retry for expired tokens
        sts_attempts = 0
        initial_credentials = None
        expiration = None

        while sts_attempts < 2:
            try:
                logger.info(f"Creating STS client for assume_role: {role_arn} (attempt {sts_attempts + 1})")
                # Get initial credentials. Explicit session (not the module-level
                # default) — see _new_boto3_session.
                sts_client = _new_boto3_session().client(
                    "sts", region_name=region, use_ssl=use_ssl, verify=verify_ssl, config=boto_config
                )

                logger.info(f"Attempting to assume role: {role_arn}")

                from another_s3_manager.metrics import safe_role_label, sts_assume_role_total

                _role_lbl = safe_role_label(role.get("name") or "unknown")
                try:
                    assumed_role = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="s3-file-manager-session")
                except Exception:
                    sts_assume_role_total.labels(role=_role_lbl, result="error").inc()
                    raise
                sts_assume_role_total.labels(role=_role_lbl, result="ok").inc()
                initial_credentials = assumed_role["Credentials"]

                # Get expiration time - keep as string for RefreshableCredentials
                expiration = initial_credentials.get("Expiration")
                # RefreshableCredentials.create_from_metadata expects expiry_time as string, not datetime
                if expiration is not None and isinstance(expiration, datetime):
                    # Convert datetime to ISO format string
                    expiration = expiration.isoformat()
                elif expiration is not None and not isinstance(expiration, str):
                    expiration = None

                logger.info(f"Successfully assumed role: {role_arn}, session expires at: {expiration}")
                break  # Success, exit retry loop

            except CredentialRetrievalError as e:
                is_expired = _is_expired_credentials_error(e)
                if is_expired and sts_attempts == 0:
                    # First attempt failed with expired token, clear cache and retry
                    logger.warning(
                        f"Failed to retrieve credentials for STS client (expired token detected), "
                        f"clearing cache and retrying for role {role_arn}",
                        extra={
                            "role_arn": role_arn,
                            "error_type": "CredentialRetrievalError",
                            "attempt": sts_attempts + 1,
                        },
                    )
                    _clear_boto3_cached_credentials()
                    sts_attempts += 1
                    continue  # Retry once
                else:
                    # Second attempt failed or not an expired token error.
                    # Convert to typed CredentialsExpiredError so the HTTP boundary
                    # can return 401 (re-auth required) instead of bare 400.
                    from another_s3_manager.errors import CredentialsExpiredError

                    logger.error(
                        f"Failed to retrieve credentials for STS client (needed to assume role {role_arn})",
                        extra={
                            "role_arn": role_arn,
                            "error_type": "CredentialRetrievalError",
                            "attempt": sts_attempts + 1,
                        },
                        exc_info=True,
                    )
                    raise CredentialsExpiredError(
                        code="CredentialRetrievalError",
                        message=(
                            f"Unable to retrieve AWS credentials needed to assume role {role_arn}. "
                            f"In Kubernetes, ensure IRSA (IAM Roles for Service Accounts) or eks-pod-identity is configured, "
                            f"or that the pod has access to instance profile credentials. "
                            f"Error: {str(e)}"
                        ),
                    ) from e
            except ClientError as e:
                from another_s3_manager.errors import S3AccessDeniedError, classify_boto_error

                error_code = (
                    e.response.get("Error", {}).get("Code", "") if hasattr(e, "response") and e.response else ""
                )
                error_msg = (
                    e.response.get("Error", {}).get("Message", "") if hasattr(e, "response") and e.response else ""
                )
                logger.error(
                    f"Failed to assume role {role_arn}",
                    extra={
                        "role_arn": role_arn,
                        "error_code": error_code,
                        "error_message": error_msg,
                    },
                    exc_info=True,
                )
                # Convert to typed exception via classifier (preserves boto code +
                # http_status). Preserve the role ARN context in the message —
                # admins need to know which role's config is broken.
                typed = classify_boto_error(e)
                original = typed.args[0] if typed.args else str(e)
                # Preserve role-arn context. For AccessDenied specifically,
                # add the IRSA / pod-identity hint that helps admins debug
                # trust-policy bugs (the boto message names the principal but
                # not the resolution path).
                if isinstance(typed, S3AccessDeniedError):
                    typed.args = (
                        f"assume_role for {role_arn}: {original}. "
                        f"Check that the pod/service account has permission to assume this role "
                        f"(IAM trust policy must allow the calling principal).",
                    )
                else:
                    typed.args = (f"assume_role for {role_arn}: {original}",)
                raise typed from e
            except Exception as e:
                error_type = type(e).__name__
                error_msg = str(e)
                # Check for NoCredentialsError — re-auth required, not bad config.
                if "NoCredentialsError" in error_type or "Unable to locate credentials" in error_msg:
                    from another_s3_manager.errors import CredentialsExpiredError

                    logger.error(
                        f"No AWS credentials found (needed to assume role {role_arn})",
                        extra={
                            "role_arn": role_arn,
                            "error_type": error_type,
                        },
                        exc_info=True,
                    )
                    raise CredentialsExpiredError(
                        code="NoCredentialsError",
                        message=(
                            f"Unable to locate AWS credentials needed to assume role {role_arn}. "
                            f"In Kubernetes, ensure IRSA (IAM Roles for Service Accounts) or eks-pod-identity is configured, "
                            f"or that the pod has access to instance profile credentials. "
                            f"Error: {error_msg}"
                        ),
                    ) from e

                from another_s3_manager.errors import S3OperationError

                logger.error(
                    f"Unexpected error while assuming role {role_arn}",
                    extra={"role_arn": role_arn, "error_type": error_type},
                    exc_info=True,
                )
                raise S3OperationError(
                    code="Unknown",
                    message=f"Unexpected error while assuming role {role_arn}: {error_msg}",
                    http_status=500,
                ) from e

        # Verify that we successfully obtained credentials
        if initial_credentials is None:
            raise ValueError(
                f"Failed to obtain credentials for role {role_arn} after retries. "
                f"This should not happen - credentials should have been obtained or an exception raised."
            )

        # Create refreshable credentials that will automatically refresh when expired
        # expiry_time is required by RefreshableCredentials, even if None
        refreshable_creds = RefreshableCredentials.create_from_metadata(
            metadata={
                "access_key": initial_credentials["AccessKeyId"],
                "secret_key": initial_credentials["SecretAccessKey"],
                "token": initial_credentials["SessionToken"],
                "expiry_time": expiration,  # Can be None if not provided
            },
            refresh_using=refresh_assumed_role_credentials,
            method="assume-role",
        )

        # Create a botocore session with refreshable credentials
        botocore_session = BotocoreSession()
        botocore_session._credentials = refreshable_creds

        client_kwargs = {
            "use_ssl": use_ssl,
            "verify": verify_ssl,
            "config": boto_config,
        }
        if region:
            client_kwargs["region_name"] = region
        if endpoint_url:
            client_kwargs["endpoint_url"] = endpoint_url

        logger.info(f"Creating S3 client with auto-refreshable assumed role credentials for {role_arn}")
        return botocore_session.create_client("s3", **client_kwargs)

    elif role_type == "credentials":
        access_key_id = role.get("access_key_id")
        secret_access_key = role.get("secret_access_key")
        region = role.get("region")

        if not access_key_id or not secret_access_key:
            raise ValueError("access_key_id and secret_access_key are required for credentials type")

        # Trim whitespace from credentials (common issue when copying from AWS console)
        access_key_id = access_key_id.strip()
        secret_access_key = secret_access_key.strip()

        if not access_key_id or not secret_access_key:
            raise ValueError("access_key_id and secret_access_key cannot be empty after trimming")

        client_kwargs = {
            "aws_access_key_id": access_key_id,
            "aws_secret_access_key": secret_access_key,
            "use_ssl": use_ssl,
            "verify": verify_ssl,
            "config": boto_config,
        }
        if region and region.strip():
            client_kwargs["region_name"] = region.strip()
        if endpoint_url:
            client_kwargs["endpoint_url"] = endpoint_url

        return _new_boto3_session().client("s3", **client_kwargs)

    elif role_type == "s3_compatible":
        access_key_id = role.get("access_key_id")
        secret_access_key = role.get("secret_access_key")
        region = role.get("region")
        endpoint_url = role.get("endpoint_url")
        use_ssl = _parse_bool(role.get("use_ssl"), True)
        verify_ssl = _parse_bool(role.get("verify_ssl"), True)
        addressing_style = role.get("addressing_style")
        if not addressing_style:
            # Backwards compatibility for boolean flags
            if _parse_bool(role.get("path_style") or role.get("use_path_style"), False):
                addressing_style = "path"
        boto_config = _get_boto3_config(addressing_style=addressing_style)

        if not access_key_id or not secret_access_key:
            raise ValueError("access_key_id and secret_access_key are required for s3_compatible type")
        if not endpoint_url:
            raise ValueError("endpoint_url is required for s3_compatible type")

        # Trim whitespace from credentials
        access_key_id = access_key_id.strip()
        secret_access_key = secret_access_key.strip()
        endpoint_url = endpoint_url.strip()

        if not access_key_id or not secret_access_key or not endpoint_url:
            raise ValueError("access_key_id, secret_access_key, and endpoint_url cannot be empty after trimming")

        client_kwargs = {
            "aws_access_key_id": access_key_id,
            "aws_secret_access_key": secret_access_key,
            "endpoint_url": endpoint_url,
            "use_ssl": use_ssl,
            "verify": verify_ssl,
            "config": boto_config,
        }
        if region and region.strip():
            client_kwargs["region_name"] = region.strip()

        return _new_boto3_session().client("s3", **client_kwargs)

    else:
        raise ValueError(f"Unknown role type: {role_type}")


def get_s3_client(role_name: Optional[str] = None) -> AnyType:
    """
    Get S3 client for the specified role (cached).

    On cache miss, after creation we probe the client with a lightweight
    call (list_buckets, falling back to head_bucket on the role's first
    allowed_bucket if list_buckets is denied). If the probe raises, the
    client is NOT cached and the failure is propagated as a typed
    S3OperationError so callers see the real error code immediately
    instead of caching a broken client.

    Concurrency: the whole check-build-probe-store sequence on a cache miss
    is guarded by `_s3_clients_lock` (double-checked locking, same shape as
    database.py's get_engine). The lock is held ACROSS the network I/O
    (client build + probe) rather than released and re-acquired — see the
    module-level design note above `_s3_clients_lock` for why that's the
    right tradeoff here: misses are rare (first request per role, or after
    invalidation), so serializing them avoids duplicate STS AssumeRole calls
    / duplicate probes for concurrent first-requests, at a cost that only
    ever applies to that rare cold-start window — every cache HIT (the
    overwhelming majority of calls) returns before the lock is ever touched.

    Args:
        role_name: Name of the role to use, or None for default

    Returns:
        boto3 S3 client
    """
    # Import here to avoid circular dependency
    from another_s3_manager.config import load_config
    from another_s3_manager.errors import (
        RoleNotFoundError,
        S3AccessDeniedError,
        S3OperationError,
        classify_boto_error,
    )

    # Use cache key based on role name
    cache_key = role_name or "default"

    # Return cached client if available (lock-free fast path)
    if cache_key in _s3_clients_cache:
        return _s3_clients_cache[cache_key]

    with _s3_clients_lock:
        # Double-checked locking: another thread may have built and cached
        # this exact role's client while we were waiting for the lock.
        if cache_key in _s3_clients_cache:
            return _s3_clients_cache[cache_key]

        # Load config and find role
        config = load_config(force_reload=False)
        roles = config.get("roles", [])

        if role_name:
            role = next((r for r in roles if r.get("name") == role_name), None)
            if not role:
                raise RoleNotFoundError(f"Role '{role_name}' not found in configuration")
        else:
            # Use first role
            role = roles[0] if roles else None

            if not role:
                # Fallback to default AWS credentials
                role = {"name": "Default", "type": "default", "description": "Use default AWS credentials"}

        # Create client
        try:
            role_type = role.get("type", "unknown")
            logger.debug(f"Creating S3 client for role '{role_name or 'default'}' (type: {role_type})")
            client = _create_s3_client_from_role(role)
        except Exception:
            logger.error(
                f"Failed to create S3 client for role '{role_name or 'default'}'",
                extra={
                    "role_name": role_name,
                    "role_type": role.get("type"),
                    "role_arn": role.get("role_arn") if role.get("type") == "assume_role" else None,
                },
                exc_info=True,
            )
            raise

        # Probe the client to surface bad config (invalid region, unreachable
        # endpoint, expired credentials) BEFORE caching. Roles with
        # allowed_buckets configured are expected to lack ListAllMyBuckets
        # permission — fall back to head_bucket. We iterate ALL allowed_buckets
        # (not just the first) so a single deleted/renamed bucket out-of-band
        # doesn't brick the entire role for users who only access the others.
        try:
            client.list_buckets()
        except Exception as probe_error:
            typed = classify_boto_error(probe_error)
            if isinstance(typed, S3AccessDeniedError):
                allowed_buckets = role.get("allowed_buckets") or []
                if isinstance(allowed_buckets, list) and allowed_buckets:
                    # Try each allowed bucket until one succeeds. As long as at
                    # least ONE responds, the credentials are valid — cache the
                    # client. Per-bucket NoSuchBucket / AccessDenied for the rest
                    # will surface on the actual operation, not at probe time.
                    head_failures: list[tuple[str, S3OperationError]] = []
                    for bucket_name in allowed_buckets:
                        try:
                            client.head_bucket(Bucket=str(bucket_name))
                            break  # success — fall through to cache
                        except Exception as head_error:
                            head_failures.append((str(bucket_name), classify_boto_error(head_error)))
                    else:
                        # Loop exhausted without break — every allowed bucket failed.
                        # Surface the most-recent typed error with context about which
                        # buckets were tried, so admins can spot config-vs-runtime issues.
                        last_typed = head_failures[-1][1]
                        bucket_summary = ", ".join(f"{name} ({err.code})" for name, err in head_failures)
                        logger.error(
                            f"S3 client probe (head_bucket) failed for ALL allowed_buckets on role "
                            f"'{role_name or 'default'}': {bucket_summary}"
                        )
                        raise type(last_typed)(
                            code=last_typed.code,
                            message=(
                                f"All allowed_buckets failed for this role: {bucket_summary}. "
                                "Check the bucket names + credentials in the role config."
                            ),
                        ) from probe_error
                else:
                    # No allowed_buckets configured AND the role's creds can't
                    # list all buckets. Wrap with the same friendly message that
                    # the legacy /api/buckets handler used (PR #14 contract) so
                    # frontend keeps showing actionable guidance, and add the
                    # fix path for admins.
                    logger.error(
                        f"S3 client probe denied for role '{role_name or 'default'}' and no allowed_buckets configured"
                    )
                    raise S3AccessDeniedError(
                        code=typed.code,
                        message=(
                            "Your credentials don't have permission to list all buckets. "
                            "This is normal for scoped tokens (R2, MinIO, AWS IAM with bucket-scoped policies). "
                            "Edit this role and fill in 'Allowed Buckets' with the bucket names you want to access, "
                            "or grant ListAllMyBuckets."
                        ),
                    ) from probe_error
            else:
                logger.error(
                    f"S3 client probe failed for role '{role_name or 'default'}': "
                    f"code={typed.code} status={typed.http_status}"
                )
                raise typed from probe_error

        _s3_clients_cache[cache_key] = client
        logger.debug(f"Successfully created, probed and cached S3 client for role '{role_name or 'default'}'")
        return client


def _execute_with_retry_inner(role_name: Optional[str], callback: Callable[[AnyType], T]) -> T:
    """
    Inner retry loop for S3 operations with automatic credential refresh.
    Does not record metrics — called by execute_with_s3_retry which handles that.
    """
    # Import HTTPException here to avoid circular dependency
    from fastapi import HTTPException

    attempts = 0
    last_error: Optional[BaseException] = None

    while attempts < 2:
        try:
            client = get_s3_client(role_name)
        except Exception as client_error:
            # Check if this is an expired credentials error
            is_expired = _is_expired_credentials_error(client_error)

            if is_expired and attempts == 0:
                # First attempt failed with expired credentials, clear cache and retry
                from another_s3_manager.metrics import s3_retries_total

                s3_retries_total.labels(reason="credentials_expired").inc()
                logger.warning(
                    f"Failed to get S3 client for role '{role_name}' (expired credentials detected), "
                    f"clearing cache and retrying",
                    extra={
                        "role_name": role_name,
                        "attempt": attempts + 1,
                        "error_type": type(client_error).__name__,
                    },
                )
                invalidate_s3_client(role_name)
                _clear_boto3_cached_credentials()
                attempts += 1
                continue  # Retry once
            else:
                # Second attempt failed or not an expired credentials error
                logger.error(
                    f"Failed to get S3 client for role '{role_name}'",
                    extra={"role_name": role_name, "attempt": attempts + 1},
                    exc_info=True,
                )
                raise

        try:
            return callback(client)
        except HTTPException:
            # HTTPException should be propagated directly without retry
            raise
        except Exception as exc:  # noqa: BLE001 - propagate precise error later
            last_error = exc
            is_expired = _is_expired_credentials_error(exc)

            # Log the error for debugging
            error_code = ""
            if hasattr(exc, "response") and exc.response:
                if isinstance(exc.response, dict):
                    error_code = exc.response.get("Error", {}).get("Code", "")

            logger.warning(
                f"S3 operation failed for role '{role_name}'",
                extra={
                    "role_name": role_name,
                    "attempt": attempts + 1,
                    "error_type": type(exc).__name__,
                    "error_code": error_code,
                    "is_expired_credentials": is_expired,
                },
                exc_info=True,
            )

            if attempts == 0 and is_expired:
                from another_s3_manager.metrics import s3_retries_total

                # Same expired-credential retry as the get_s3_client() branch above,
                # but triggered by the operation itself. Count it too, or the metric
                # under-reports credential churn.
                s3_retries_total.labels(reason="credentials_expired").inc()
                logger.info(
                    "Invalidating cached client for role '%s' due to expired credentials; "
                    "forcing eks-pod-identity refresh",
                    role_name or "default",
                )
                invalidate_s3_client(role_name)
                _clear_boto3_cached_credentials()
                attempts += 1
                continue
            break

    if last_error:
        if _is_expired_credentials_error(last_error):
            raise RuntimeError(
                "AWS credentials for this role have expired and automatic refresh failed. "
                "Please re-authenticate the container or refresh the service account token."
            ) from last_error
        raise last_error

    raise RuntimeError("Unexpected S3 execution failure without exception")


def execute_with_s3_retry(role_name: Optional[str], operation: str, callback: Callable[[AnyType], T]) -> T:
    """
    Run an S3 operation with automatic credential refresh on expiration.

    Records s3_operations_total and s3_operation_duration_seconds metrics.
    Counts only the final outcome — retries do not produce duplicate counter increments.

    Args:
        role_name: Role name used to resolve the client.
        operation: Operation label for metrics ('list'|'get'|'put'|'delete'|'head').
        callback: Callable receiving the S3 client and returning any value.

    Returns:
        Result of callback execution.

    Raises:
        Exception: Re-raises the original exception if retry is not possible.
    """
    from another_s3_manager.errors import error_code_label
    from another_s3_manager.metrics import (
        s3_operation_duration_seconds,
        s3_operations_total,
        safe_role_label,
    )

    role_lbl = safe_role_label(role_name or "unknown")
    start = time.perf_counter()
    try:
        result = _execute_with_retry_inner(role_name, callback)
        s3_operations_total.labels(role=role_lbl, operation=operation, error_code="none").inc()
        return result
    except Exception as exc:
        s3_operations_total.labels(role=role_lbl, operation=operation, error_code=error_code_label(exc)).inc()
        raise
    finally:
        s3_operation_duration_seconds.labels(operation=operation).observe(time.perf_counter() - start)


def clear_s3_clients_cache() -> None:
    """Clear the S3 clients cache AND the underlying boto3/botocore credential cache.

    A bare dict clear is insufficient for roles backed by `assume_role` (STS) or
    AWS `profile` credentials: boto3/botocore keeps its own credential cache on
    the default session, so a new client built after the dict clear would still
    inherit the OLD assumed-role / profile credentials until they naturally
    expire (~1h for STS). The credential flush matches what the per-role
    `invalidate_s3_client + _clear_boto3_cached_credentials` retry sites do.
    """
    global _s3_clients_cache
    _s3_clients_cache.clear()
    _clear_boto3_cached_credentials()


# ---------------------------------------------------------------------------
# Permission-aware helpers for both web routes and MCP tools
# ---------------------------------------------------------------------------


def validate_role_access(role_name: Optional[str], user_dict: Dict[str, Any]) -> Optional[str]:
    """
    Validate that user_dict permits using role_name.

    Raises PermissionError (not HTTPException) — callers translate to the
    appropriate boundary error (HTTP 403 or McpError).

    Returns the validated role name, or None if role_name is None.
    """
    if role_name is None:
        return None

    # Admins have access to all roles.
    if user_dict.get("is_admin", False):
        return role_name

    allowed_roles = user_dict.get("allowed_roles", [])
    if role_name not in allowed_roles:
        raise PermissionError(f"Access denied: You don't have permission to use role '{role_name}'")

    return role_name


def _validate_bucket_access(role: str, bucket: str, user_dict: Dict[str, Any]) -> None:
    """
    Validate role access and bucket access in one call.

    Raises PermissionError if the user cannot use `role` OR if `bucket`
    is not in the role's allowed_buckets (when that list is configured).
    """
    # Role-level check (raises PermissionError if not allowed).
    validate_role_access(role, user_dict)

    # Bucket-level check.
    from another_s3_manager.config import load_config

    config = load_config(force_reload=False)
    roles = config.get("roles", [])
    role_config = next((r for r in roles if r.get("name") == role), None)
    if role_config is None:
        # Role not found in config — s3_client.get_s3_client will raise ValueError later.
        return
    allowed_buckets = role_config.get("allowed_buckets")
    if allowed_buckets and bucket not in allowed_buckets:
        raise PermissionError(f"bucket '{bucket}' not in allowed_buckets for role '{role}'")


# Role types that sign with temporary (STS) credentials — a presigned URL
# cannot outlive the credentials that signed it, so long TTLs may expire early.
_TEMPORARY_CREDENTIAL_ROLE_TYPES = frozenset({"assume_role", "profile"})


def role_uses_temporary_credentials(role_name: str) -> bool:
    """Return True if `role_name` signs with temporary STS credentials.

    Used to decide whether a long-lived presigned URL needs a warning that it
    may stop working when the role's session expires. Unknown roles return
    False (no false alarm).
    """
    config = load_config(force_reload=False)
    role_config = next((r for r in config.get("roles", []) if r.get("name") == role_name), None)
    if role_config is None:
        return False
    return role_config.get("type") in _TEMPORARY_CREDENTIAL_ROLE_TYPES


def list_buckets_for_role(role: str, user_dict: Dict[str, Any]) -> list:
    """
    Return list of bucket names accessible via `role` for `user_dict`.

    Raises PermissionError if the user cannot use `role`.
    If the role has allowed_buckets configured, returns that list directly.
    Otherwise lists all buckets via S3 (requires s3:ListAllMyBuckets).
    """
    validated_role = validate_role_access(role, user_dict)

    from another_s3_manager.config import load_config

    config = load_config(force_reload=False)
    roles = config.get("roles", [])
    role_config = (
        next((r for r in roles if r.get("name") == validated_role), None)
        if validated_role
        else (roles[0] if roles else None)
    )

    if role_config and "allowed_buckets" in role_config and role_config["allowed_buckets"]:
        allowed_buckets = role_config["allowed_buckets"]
        if isinstance(allowed_buckets, list):
            return allowed_buckets
        raise ValueError("allowed_buckets must be a list")

    def fetch_buckets(s3_client):
        response = s3_client.list_buckets()
        return [bucket["Name"] for bucket in response["Buckets"]]

    return execute_with_s3_retry(validated_role, "list", fetch_buckets)


def list_objects_for_role(role: str, bucket: str, path: str, user_dict: Dict[str, Any]) -> list:
    """
    List objects in `bucket` under `path` for `role`.

    Returns list of file-object dicts (same shape as /api/buckets/{b}/files).
    Raises PermissionError on role/bucket access violation.
    """
    _validate_bucket_access(role, bucket, user_dict)
    validated_role = validate_role_access(role, user_dict)

    prefix = path + "/" if path else ""

    def fetch_files(s3_client):
        files = []
        directories: set = set()

        paginator = s3_client.get_paginator("list_objects_v2")
        pages = paginator.paginate(Bucket=bucket, Prefix=prefix, Delimiter="/")

        for page in pages:
            if "CommonPrefixes" in page:
                for prefix_obj in page["CommonPrefixes"]:
                    dir_name = prefix_obj["Prefix"][len(prefix) :].rstrip("/")
                    if dir_name and dir_name not in directories:
                        directories.add(dir_name)
                        files.append({"name": dir_name, "is_directory": True, "size": 0})

            if "Contents" in page:
                for obj in page["Contents"]:
                    if obj["Key"].endswith("/") and obj["Size"] == 0:
                        continue
                    file_name = obj["Key"][len(prefix) :]
                    if file_name:
                        files.append(
                            {
                                "name": file_name,
                                "is_directory": False,
                                "size": obj["Size"],
                                "last_modified": obj["LastModified"].isoformat(),
                            }
                        )

        files.sort(key=lambda x: (not x["is_directory"], x["name"].lower()))
        return files

    return execute_with_s3_retry(validated_role, "list", fetch_files)


def list_objects_recursive_for_role(
    role: str,
    bucket: str,
    prefix: str,
    user_dict: Dict[str, Any],
    max_keys: int = 1000,
    continuation_token: Optional[str] = None,
    max_page_size: int = 10_000,
) -> Dict[str, Any]:
    """List ALL objects under `prefix` recursively (no Delimiter), with pagination.

    Designed for MCP agents that want to see/count an entire subtree without
    walking it dir-by-dir (which would mean N+1 calls). Hard ceiling: max_page_size
    keys per call (default 10000; the per-S3-request limit of 1000 is S3's own and unchanged).

    Returns:
        {
            "files": [{key, size, last_modified}, ...],   # flat keys, no is_directory
            "is_truncated": bool,
            "next_continuation_token": str | None,        # pass back to continue
            "key_count": int,                             # number returned this page
        }

    Note: `prefix` is used verbatim (no trailing slash injection); pass
    "logs/2026/" to scope to that subtree, "" to scan from bucket root.
    """
    _validate_bucket_access(role, bucket, user_dict)
    validated_role = validate_role_access(role, user_dict)

    # S3's hard limit per ListObjectsV2 call is 1000; for larger pages, paginate.
    # The safety ceiling on a single call comes from the caller (config-driven
    # mcp_list_max_page_size for the MCP tool) instead of being invented here —
    # s3_client does the clamping, it just takes the bound as an argument.
    max_page_size = max(1, max_page_size)
    max_keys = max(1, min(max_keys, max_page_size))

    def fetch(s3_client) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {
            "Bucket": bucket,
            "Prefix": prefix,
            "MaxKeys": min(max_keys, 1000),  # per-call cap
        }
        if continuation_token:
            kwargs["ContinuationToken"] = continuation_token

        files: list = []
        next_token: Optional[str] = None
        is_truncated = False

        # Paginate up to max_keys total. Stop early once we have enough.
        while True:
            resp = s3_client.list_objects_v2(**kwargs)
            for obj in resp.get("Contents", []) or []:
                # Skip empty "directory marker" objects (key ends with /).
                if obj["Key"].endswith("/") and obj["Size"] == 0:
                    continue
                files.append(
                    {
                        "key": obj["Key"],
                        "size": obj["Size"],
                        "last_modified": obj["LastModified"].isoformat(),
                    }
                )
                if len(files) >= max_keys:
                    break

            if len(files) >= max_keys:
                # Caller asked for at most max_keys; signal truncation if S3
                # also has more or we cut mid-page.
                is_truncated = bool(resp.get("IsTruncated")) or len(resp.get("Contents", []) or []) >= kwargs["MaxKeys"]
                next_token = resp.get("NextContinuationToken") if is_truncated else None
                break

            if resp.get("IsTruncated"):
                kwargs["ContinuationToken"] = resp["NextContinuationToken"]
                continue

            break

        return {
            "files": files,
            "is_truncated": is_truncated,
            "next_continuation_token": next_token,
            "key_count": len(files),
        }

    return execute_with_s3_retry(validated_role, "list", fetch)


def _human_bytes(size: int) -> str:
    """Format a byte count as a short human string, e.g. 52428800 -> '50.0 MB'.

    Binary steps (1024) with the conventional short unit labels the web UI uses.
    """
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024:
            return f"{int(value)} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


# Bucket-summary tunables (summarize_bucket_for_role). Named so the response's
# hard caps are greppable, and so the two unrelated meanings of "1000" (the S3
# per-request page size vs. the mcp_summary_max_keys floor) don't read as the
# same constant.
_S3_PAGE_SIZE = 1000  # Max entries per ListObjectsV2 call (S3's own ceiling).
_MIN_SUMMARY_MAX_KEYS = 1000  # Server-side floor for the `max_keys` walk cap.
_TOP_PREFIXES = 20  # How many prefixes are rendered in the response.
_TOP_EXTENSIONS = 20  # How many extensions are rendered in the response.
_TOP_LARGEST = 10  # How many largest-object entries are rendered.
# Cap on the rendered "ext" string — an oversized basename suffix (e.g. 900
# chars) is not a real file extension and must not inflate the response.
_MAX_EXTENSION_LENGTH = 16


def summarize_bucket_for_role(
    role: str,
    bucket: str,
    prefix: str,
    user_dict: Dict[str, Any],
    max_keys: int,
    prefix_scan_pages: int = 20,
) -> Dict[str, Any]:
    """Summarize a bucket (or a prefix subtree) in one bounded, honest response.

    Two-step walk (see the 2026-07-12 big-bucket ergonomics design):

    Step 1 — a Delimiter="/" listing scoped to `prefix` enumerates the
    immediate child prefixes. Bounded by `prefix_scan_pages` pages (1000
    entries each): a level holding hundreds of thousands of loose objects
    would otherwise cost the very walk we are avoiding. Budget exhausted →
    `prefix_list_complete: False` — never silently.

    Step 2 — a recursive walk (no Delimiter, 1000 keys per request) under
    `prefix`, capped at `max_keys`, aggregating counts, bytes, an extension
    histogram, top-10 largest objects, the modified range and root_objects.
    Zero-byte directory markers (keys ending "/") are skipped, consistent
    with list_objects_recursive_for_role.

    Why two steps: S3 returns keys lexicographically, so a capped recursive
    walk alone only ever sees the alphabetically-earliest part of the bucket;
    a "top prefixes" section built from that would be a lie. The delimiter
    listing answers the cheaper "which prefixes exist" question first, and the
    per-prefix `coverage` field (complete / partial / not_scanned) tells the
    agent exactly which numbers it may trust.

    Honesty on cap-hit (2026-07-13): total_objects/total_bytes are nulled and
    per-prefix entries carry `coverage` when `complete` is False — but
    root_objects, extensions[_count]/extensions_truncated, largest_objects
    and oldest/newest_modified are ALL computed from that same capped walk
    too, and by lexicographic bad luck can under-report rather than merely
    look "small" (e.g. a prefix that alone exceeds max_keys can hide a loose
    root object, or the single largest object in the bucket, if either sorts
    after `scan_stopped_at`). A top-level `note` string spells this out in
    plain language whenever `complete` is False; `None` when the walk
    finished. See test_summary_partial_scan_underreports_root_and_largest.

    The response is bounded by design: top-20 prefixes, top-20 extensions
    (each "ext" capped at _MAX_EXTENSION_LENGTH chars), top-10 largest
    objects — never scales with object count. The real bound is roughly 30
    rendered entries (20 prefixes + 10 largest objects) times the maximum S3
    key length (~1024 bytes, but inflated via UTF-8 encoding if non-ASCII).
    With the test seed (~900-byte keys), this stays well under 40 KB (see
    test_summary_response_stays_small for the realistic worst-case math).

    Args:
        role: Role name (validated against user_dict).
        bucket: Bucket name (validated against the role's allowed_buckets).
        prefix: Normalized S3 prefix ("" for bucket root, otherwise "sub/path/").
        user_dict: Authenticated user dict ({username, is_admin, allowed_roles}).
        max_keys: Walk cap (config: mcp_summary_max_keys). Floor: 1000.
        prefix_scan_pages: Step-1 page budget (config: mcp_summary_prefix_scan_pages).
            Floor: 1. Passed in — s3_client does no config lookups in the hot path.

    Raises PermissionError on role/bucket access violation.
    """
    _validate_bucket_access(role, bucket, user_dict)
    validated_role = validate_role_access(role, user_dict)

    # Server-side floors: a pathological config value (0, negative) cannot
    # disable the walk or the prefix scan entirely.
    max_keys = max(_MIN_SUMMARY_MAX_KEYS, int(max_keys))
    # Floor is defensive-only: Step 1 is a do-while (issues page 1
    # unconditionally before checking IsTruncated), so any budget <= 1 already
    # yields exactly one page. Clamping to 1 prevents misinterpretation on
    # pathological values.
    prefix_scan_pages = max(1, int(prefix_scan_pages))

    def fetch(s3_client) -> Dict[str, Any]:
        # ---- Step 1: enumerate immediate child prefixes (Delimiter="/") ----
        step1_prefixes: list = []
        prefix_list_complete = True
        step1_kwargs: Dict[str, Any] = {
            "Bucket": bucket,
            "Prefix": prefix,
            "Delimiter": "/",
            "MaxKeys": _S3_PAGE_SIZE,
        }
        pages = 0
        while True:
            resp = s3_client.list_objects_v2(**step1_kwargs)
            pages += 1
            for cp in resp.get("CommonPrefixes", []) or []:
                step1_prefixes.append(cp["Prefix"])
            if not resp.get("IsTruncated"):
                break
            if pages >= prefix_scan_pages:
                # Budget exhausted before the delimiter listing finished:
                # prefixes may exist that we never even enumerated. Say so.
                prefix_list_complete = False
                break
            step1_kwargs["ContinuationToken"] = resp["NextContinuationToken"]

        # ---- Step 2: recursive walk (no Delimiter), capped at max_keys ----
        scanned_objects = 0
        scanned_bytes = 0
        root_objects = 0
        complete = True
        oldest = None
        newest = None
        last_scanned_key: Optional[str] = None
        ext_stats: Dict[str, list] = {}  # ext -> [objects, bytes]
        prefix_stats: Dict[str, list] = {}  # immediate child prefix -> [objects, bytes]
        largest_heap: list = []  # min-heap of (size, key, LastModified datetime), max _TOP_LARGEST entries

        walk_kwargs: Dict[str, Any] = {"Bucket": bucket, "Prefix": prefix, "MaxKeys": _S3_PAGE_SIZE}
        stopped = False
        while not stopped:
            resp = s3_client.list_objects_v2(**walk_kwargs)
            for obj in resp.get("Contents", []) or []:
                key = obj["Key"]
                # Skip empty "directory marker" objects (key ends with /),
                # consistent with list_objects_recursive_for_role.
                if key.endswith("/") and obj["Size"] == 0:
                    continue
                if scanned_objects >= max_keys:
                    # Cap already reached and another real key exists.
                    complete = False
                    stopped = True
                    break
                scanned_objects += 1
                size = obj["Size"]
                scanned_bytes += size
                lm = obj["LastModified"]
                if oldest is None or lm < oldest:
                    oldest = lm
                if newest is None or lm > newest:
                    newest = lm
                last_scanned_key = key

                remainder = key[len(prefix) :]
                slash = remainder.find("/")
                if slash == -1:
                    # Directly under `prefix` — counted from the WALK, not from
                    # Step 1 (whose Contents are bounded by the page budget and
                    # would silently under-report on loose-object-heavy levels).
                    root_objects += 1
                else:
                    child = prefix + remainder[: slash + 1]
                    stats = prefix_stats.setdefault(child, [0, 0])
                    stats[0] += 1
                    stats[1] += size

                basename = remainder.rsplit("/", 1)[-1]
                if "." in basename and not basename.endswith("."):
                    # Cap the rendered extension: an oversized basename suffix
                    # (e.g. a 900-char "extension") is not a real file
                    # extension and must not be allowed to inflate the response.
                    ext = basename.rsplit(".", 1)[-1].lower()[:_MAX_EXTENSION_LENGTH]
                else:
                    ext = "(none)"
                estats = ext_stats.setdefault(ext, [0, 0])
                estats[0] += 1
                estats[1] += size

                # Keep the raw datetime on the heap; format only the (at most
                # _TOP_LARGEST) survivors below. isoformat() on every scanned
                # object here would be wasted work at the default 50k cap.
                heapq.heappush(largest_heap, (size, key, lm))
                if len(largest_heap) > _TOP_LARGEST:
                    heapq.heappop(largest_heap)

            if stopped:
                break
            if resp.get("IsTruncated"):
                if scanned_objects >= max_keys:
                    # Cap reached exactly at a page boundary with more pages
                    # left. Conservative: even if the remaining pages held only
                    # directory markers, we report incomplete — we understate
                    # coverage, never overstate it.
                    complete = False
                    break
                walk_kwargs["ContinuationToken"] = resp["NextContinuationToken"]
            else:
                break

        scan_stopped_at: Optional[str] = None if complete else last_scanned_key

        # ---- Coverage classification ----
        # Union walk-discovered prefixes so a Step-1 budget exhaustion does not
        # hide prefixes the walk actually has data for. prefix_count reports
        # len(all_prefixes) (not Step 1's raw count) so it can never contradict
        # the `prefixes` list below, which is built from this same union — see
        # the NOTE next to `prefix_count` in the response dict.
        all_prefixes = sorted(set(step1_prefixes) | set(prefix_stats.keys()))
        entries = []
        for p in all_prefixes:
            if complete:
                coverage = "complete"
            elif scan_stopped_at is not None and scan_stopped_at.startswith(p):
                coverage = "partial"
            elif scan_stopped_at is not None and p < scan_stopped_at:
                # Keys arrive in lexicographic order: every key under p sorts
                # before scan_stopped_at, so the walk passed fully through p.
                coverage = "complete"
            else:
                coverage = "not_scanned"
            if coverage == "not_scanned":
                objects_n: Optional[int] = None
                bytes_n: Optional[int] = None
            else:
                counts = prefix_stats.get(p, [0, 0])
                objects_n, bytes_n = counts[0], counts[1]
            entries.append({"prefix": p, "objects": objects_n, "bytes": bytes_n, "coverage": coverage})

        # Top-20 selection: scanned prefixes ranked by objects desc first,
        # remaining slots filled with not_scanned prefixes in key order; the
        # final list is presented in key order so the complete -> partial ->
        # not_scanned progression reads naturally.
        scanned_entries = [e for e in entries if e["coverage"] != "not_scanned"]
        scanned_entries.sort(key=lambda e: (-(e["objects"] or 0), e["prefix"]))
        selected = scanned_entries[:_TOP_PREFIXES]
        if len(selected) < _TOP_PREFIXES:
            not_scanned_entries = [e for e in entries if e["coverage"] == "not_scanned"]
            selected.extend(not_scanned_entries[: _TOP_PREFIXES - len(selected)])
        selected.sort(key=lambda e: e["prefix"])

        ext_entries = [{"ext": ext, "objects": stats[0], "bytes": stats[1]} for ext, stats in ext_stats.items()]
        ext_entries.sort(key=lambda e: (-e["objects"], e["ext"]))

        # Format only the (at most _TOP_LARGEST) heap survivors — see the
        # comment at the heappush call for why isoformat() is deferred here.
        largest = [
            {"key": key, "size": size, "last_modified": lm.isoformat()}
            for size, key, lm in sorted(largest_heap, reverse=True)
        ]

        # Honesty note (2026-07-13, final-review BLOCKING 2): root_objects,
        # extensions[_count]/extensions_truncated and largest_objects, and
        # oldest/newest_modified are all computed from the SAME capped walk
        # as total_objects/total_bytes — but unlike those two (nulled when
        # complete=False) they read as plain facts with no built-in signal
        # that they can under-report. S3 returns keys lexicographically, so
        # e.g. a bucket where one prefix alone exceeds max_keys never lets
        # the walk reach a loose root object or a bigger file that sorts
        # later — root_objects/largest_objects would then be confidently
        # wrong, not just incomplete. Spell that out for whatever reads this
        # cold (an AI agent, not a human who can infer the caveat from
        # `complete: false` alone).
        note: Optional[str] = None
        if not complete:
            note = (
                f"PARTIAL SCAN: only the first {scanned_objects} objects were visited, in S3's "
                f"lexicographic key order, stopping at '{scan_stopped_at}'. root_objects, "
                "extensions, largest_objects, oldest_modified and newest_modified reflect ONLY "
                "this scanned range and can UNDER-REPORT — e.g. a prefix that alone exceeds the "
                "scan cap can hide a loose object at the bucket root, or the single largest "
                "object in the bucket, if either sorts after scan_stopped_at. Narrow with `path` "
                "to a specific prefix, or raise mcp_summary_max_keys, for a trustworthy answer."
            )

        return {
            "bucket": bucket,
            "path": prefix,
            "complete": complete,
            "note": note,
            "scanned_objects": scanned_objects,
            "scanned_bytes": scanned_bytes,
            "scanned_bytes_human": _human_bytes(scanned_bytes),
            "total_objects": scanned_objects if complete else None,
            "total_bytes": scanned_bytes if complete else None,
            "total_bytes_human": _human_bytes(scanned_bytes) if complete else None,
            "scan_stopped_at": scan_stopped_at,
            "root_objects": root_objects,
            "prefixes": selected,
            # NOTE: intentionally len(all_prefixes), not len(step1_prefixes).
            # Step 1's CommonPrefixes are a superset of anything the walk can
            # discover whenever prefix_list_complete is True, so this is
            # unchanged for normal buckets. When Step 1's budget is exhausted
            # (prefix_list_complete=False) it becomes an honest lower bound
            # instead of contradicting `prefixes` above, which is built from
            # this same union and can otherwise be non-empty while the raw
            # Step-1 count is zero.
            "prefix_count": len(all_prefixes),
            "prefix_list_complete": prefix_list_complete,
            "prefixes_truncated": len(all_prefixes) > _TOP_PREFIXES,
            "extensions": ext_entries[:_TOP_EXTENSIONS],
            "extension_count": len(ext_entries),
            "extensions_truncated": len(ext_entries) > _TOP_EXTENSIONS,
            "largest_objects": largest,
            "oldest_modified": oldest.isoformat() if oldest else None,
            "newest_modified": newest.isoformat() if newest else None,
        }

    return execute_with_s3_retry(validated_role, "list", fetch)


def list_objects_paginated_for_role(
    role: Optional[str],
    bucket: str,
    path: str,
    user_dict: Dict[str, Any],
    max_keys: int,
    continuation_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Paginated non-recursive listing with CommonPrefixes (directories).

    Directories appear ONLY on the first page (when `continuation_token` is
    None). Subsequent pages return `directories: []` and continue iterating
    files via S3's NextContinuationToken.

    First-page implementation note: S3's MaxKeys caps Contents + CommonPrefixes
    combined, so a small page size (e.g. 50) would silently drop directories
    that lie past that window. To guarantee the /v2 UI sees every direct
    sub-folder up front, the first page issues TWO list_objects_v2 calls — one
    with MaxKeys=1000 to enumerate every CommonPrefix, then one with the
    caller's MaxKeys to fetch the first page of files. Real-world folders
    very rarely have >1000 direct sub-directories; if that ever happens, the
    overflow is silently dropped (acceptable: hidden directories are also
    hidden from `list_objects_for_role`, the legacy helper).

    Race window: a directory created between the discovery call and the
    file-page call within the same first-page request will not appear in
    this response; it surfaces on the next first-page reload. Cost: N+1 S3
    calls for an N-page listing — the +1 is the directory-discovery call.

    Returns:
        {
            "directories": [{name, is_directory, size}, ...],   # only on first page
            "files":       [{name, is_directory, size, last_modified}, ...],
            "next_token":  str | None,
            "has_more":    bool,
        }
    """
    _validate_bucket_access(role, bucket, user_dict)
    validated_role = validate_role_access(role, user_dict)

    # Defensive clamp — route already validates 1..1000 via FastAPI Query
    # constraints, but the helper is called directly from tests too.
    max_keys = max(1, min(max_keys, 1000))

    prefix = path + "/" if path else ""

    def fetch(s3_client) -> Dict[str, Any]:
        directories: list = []
        if continuation_token is None:
            # First page: dedicated directory-discovery call. MaxKeys=1000 is
            # S3's per-call ceiling; this is the most CommonPrefixes a single
            # ListObjectsV2 can ever surface in one shot.
            dir_resp = s3_client.list_objects_v2(
                Bucket=bucket,
                Prefix=prefix,
                Delimiter="/",
                MaxKeys=1000,
            )
            for prefix_obj in dir_resp.get("CommonPrefixes", []) or []:
                dir_name = prefix_obj["Prefix"][len(prefix) :].rstrip("/")
                if dir_name:
                    directories.append(
                        {
                            "name": dir_name,
                            "is_directory": True,
                            "size": 0,
                        }
                    )
            directories.sort(key=lambda d: d["name"].lower())

        # File-page call (also the only call on subsequent pages).
        file_kwargs: Dict[str, Any] = {
            "Bucket": bucket,
            "Prefix": prefix,
            "Delimiter": "/",
            "MaxKeys": max_keys,
        }
        if continuation_token:
            file_kwargs["ContinuationToken"] = continuation_token

        file_resp = s3_client.list_objects_v2(**file_kwargs)

        files: list = []
        for obj in file_resp.get("Contents", []) or []:
            # Skip empty directory-marker objects (key ends with /).
            if obj["Key"].endswith("/") and obj["Size"] == 0:
                continue
            file_name = obj["Key"][len(prefix) :]
            if not file_name:
                continue
            files.append(
                {
                    "name": file_name,
                    "is_directory": False,
                    "size": obj["Size"],
                    "last_modified": obj["LastModified"].isoformat(),
                }
            )
        files.sort(key=lambda f: f["name"].lower())

        is_truncated = bool(file_resp.get("IsTruncated"))
        next_token = file_resp.get("NextContinuationToken") if is_truncated else None

        return {
            "directories": directories,
            "files": files,
            "next_token": next_token,
            "has_more": is_truncated,
        }

    return execute_with_s3_retry(validated_role, "list", fetch)


def list_objects_client_load_for_role(
    role: Optional[str],
    bucket: str,
    path: str,
    user_dict: Dict[str, Any],
    max_client_load: int,
    continuation_token: Optional[str] = None,
    name_prefix: str = "",
) -> Dict[str, Any]:
    """Aggregate S3 pages up to `max_client_load` objects for the /v2 client.

    The /v2 UI holds the result in memory and paginates/filters/searches it
    client-side (vanilla-style), so this returns a chunk of up to
    `max_client_load` objects in one logical load instead of one S3 page.

    Directories (CommonPrefixes) and files (Contents) are BOTH counted toward
    `max_client_load` and BOTH can appear on any chunk — a single Delimiter
    walk pages through the level in S3 key order, so continuation (Load more /
    Load all / lazy scroll) resumes uniformly regardless of whether the next
    objects are folders or files. A level made entirely of sub-folders
    paginates exactly like a level made entirely of files; the caller
    accumulates `directories` across chunks the same way it accumulates
    `files`.

    The per-S3-call MaxKeys is capped at `min(1000, remaining_budget)` so the
    S3 page boundary aligns with the chunk boundary: when the chunk fills, the
    returned NextContinuationToken points exactly past the last emitted object,
    making continuation resumable at the correct offset.

    `name_prefix` (default "") narrows results to children of the folder whose
    NAME starts with it: S3 filters on `<base><name_prefix>` while child names
    are still stripped relative to `<base>`, so they stay folder-relative
    (e.g. a folder `4f2a1c/` matched by name_prefix="4f2a" displays as "4f2a1c").

    Returns:
        {
            "directories": [...],   # this chunk's sub-folders
            "files":       [...],   # this chunk's files
            "truncated":   bool,    # True if S3 has more beyond this chunk
            "next_token":  str | None,
        }
    """
    _validate_bucket_access(role, bucket, user_dict)
    validated_role = validate_role_access(role, user_dict)

    # Defensive clamp. 1..200000 — high enough for the 595k-folder "Load all"
    # case to drain in a handful of chunks, low enough to refuse absurd values.
    max_client_load = max(1, min(max_client_load, 200_000))

    # `base` is the folder prefix used to strip child names; `s3_prefix` is what
    # S3 filters on. name_prefix="" → s3_prefix == base (normal folder listing).
    base = path + "/" if path else ""
    s3_prefix = base + name_prefix

    def fetch(s3_client) -> Dict[str, Any]:
        # Directories (CommonPrefixes) and files (Contents) are BOTH objects at
        # this level and both count toward max_client_load. A single Delimiter
        # walk pages through the whole level in S3 key order, so continuation
        # (Load more / Load all / lazy scroll) resumes uniformly whether the
        # next objects are folders, files, or a mix — a level made entirely of
        # sub-folders paginates exactly like a level made entirely of files.
        directories: list = []
        files: list = []
        token = continuation_token
        truncated = False
        next_token: Optional[str] = None

        # Defensive bound on S3 round-trips per chunk. Every returned entry
        # (folder or file) counts toward the budget, so ceil(budget/1000) pages
        # always fill it; the slack only absorbs pages thinned by skipped
        # self-markers. This is what makes a 800k-sub-folder level return a
        # bounded chunk in one call instead of grinding the whole keyspace.
        max_pages = (max_client_load // 1000) + 8
        pages = 0

        while (len(directories) + len(files)) < max_client_load and pages < max_pages:
            pages += 1
            # Cap MaxKeys at the remaining budget so the S3 page boundary aligns
            # with the chunk boundary and the continuation token is correct.
            remaining = max_client_load - (len(directories) + len(files))
            kwargs: Dict[str, Any] = {
                "Bucket": bucket,
                "Prefix": s3_prefix,
                "Delimiter": "/",
                "MaxKeys": min(1000, remaining),
            }
            if token:
                kwargs["ContinuationToken"] = token

            resp = s3_client.list_objects_v2(**kwargs)

            for prefix_obj in resp.get("CommonPrefixes", []) or []:
                dir_name = prefix_obj["Prefix"][len(base) :].rstrip("/")
                if dir_name:
                    directories.append(
                        {
                            "name": dir_name,
                            "is_directory": True,
                            "size": 0,
                        }
                    )

            for obj in resp.get("Contents", []) or []:
                # Skip empty directory-marker objects (key ends with /).
                if obj["Key"].endswith("/") and obj["Size"] == 0:
                    continue
                file_name = obj["Key"][len(base) :]
                if not file_name:
                    continue
                files.append(
                    {
                        "name": file_name,
                        "is_directory": False,
                        "size": obj["Size"],
                        "last_modified": obj["LastModified"].isoformat(),
                    }
                )

            if resp.get("IsTruncated"):
                token = resp.get("NextContinuationToken")
                if (len(directories) + len(files)) >= max_client_load or pages >= max_pages:
                    truncated = True
                    next_token = token
                    break
                # else loop to pull the next S3 page into this same chunk
            else:
                truncated = False
                next_token = None
                break

        directories.sort(key=lambda d: d["name"].lower())
        files.sort(key=lambda f: f["name"].lower())

        return {
            "directories": directories,
            "files": files,
            "truncated": truncated,
            "next_token": next_token,
        }

    return execute_with_s3_retry(validated_role, "list", fetch)


def head_object_for_role(role: str, bucket: str, path: str, user_dict: Dict[str, Any]) -> int:
    """
    Return the ContentLength (bytes) of an object in `bucket` at `path`.

    Raises PermissionError on role/bucket access violation.
    Raises FileNotFoundError if the object does not exist.
    """
    from botocore.exceptions import ClientError as _ClientError

    _validate_bucket_access(role, bucket, user_dict)
    validated_role = validate_role_access(role, user_dict)

    def do_head(s3_client):
        try:
            response = s3_client.head_object(Bucket=bucket, Key=path)
            return response["ContentLength"]
        except _ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "") if hasattr(e, "response") else ""
            if error_code in {"404", "NoSuchKey"}:
                raise FileNotFoundError(f"Object '{path}' not found in bucket '{bucket}'") from e
            raise

    return execute_with_s3_retry(validated_role, "head", do_head)


def get_object_metadata_for_role(role: str, bucket: str, path: str, user_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return object metadata (size, last_modified, content_type, etag) via HEAD.

    Unlike head_object_for_role (which returns just the size for the read_file
    pipeline), this returns the full metadata dict for the MCP get_object_metadata
    tool so an agent can inspect a file without downloading it.

    Raises PermissionError on role/bucket access violation.
    Raises FileNotFoundError if the object does not exist.
    """
    from botocore.exceptions import ClientError as _ClientError

    _validate_bucket_access(role, bucket, user_dict)
    validated_role = validate_role_access(role, user_dict)

    def do_head(s3_client):
        try:
            resp = s3_client.head_object(Bucket=bucket, Key=path)
        except _ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "") if hasattr(e, "response") else ""
            if error_code in {"404", "NoSuchKey"}:
                raise FileNotFoundError(f"Object '{path}' not found in bucket '{bucket}'") from e
            raise
        last_modified = resp.get("LastModified")
        return {
            "size": resp.get("ContentLength", 0),
            "last_modified": last_modified.isoformat() if last_modified is not None else None,
            "content_type": resp.get("ContentType"),
            "etag": (resp.get("ETag") or "").strip('"') or None,
        }

    return execute_with_s3_retry(validated_role, "head", do_head)


def read_object_for_role(role: str, bucket: str, path: str, user_dict: Dict[str, Any]) -> bytes:
    """
    Download and return the full body of an object in `bucket` at `path`.

    Raises PermissionError on role/bucket access violation.
    Raises FileNotFoundError if the object does not exist.
    Increments the s3_bytes_total metric with direction="download".
    """
    from botocore.exceptions import ClientError as _ClientError

    from another_s3_manager.metrics import s3_bytes_total, safe_role_label

    _validate_bucket_access(role, bucket, user_dict)
    validated_role = validate_role_access(role, user_dict)

    def do_get(s3_client):
        try:
            response = s3_client.get_object(Bucket=bucket, Key=path)
            body: bytes = response["Body"].read()
            s3_bytes_total.labels(
                role=safe_role_label(validated_role or "unknown"), bucket=bucket, direction="download"
            ).inc(len(body))
            return body
        except _ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "") if hasattr(e, "response") else ""
            if error_code in {"404", "NoSuchKey"}:
                raise FileNotFoundError(f"Object '{path}' not found in bucket '{bucket}'") from e
            raise

    return execute_with_s3_retry(validated_role, "get", do_get)


def iter_object_for_role(
    role: str,
    bucket: str,
    path: str,
    user_dict: Dict[str, Any],
    chunk_size: int = 8192,
) -> Tuple[Dict[str, Any], Iterator[bytes]]:
    """Stream object body in chunks for ``role``.

    Returns ``(metadata, body_iterator)`` where ``metadata`` is::

        {"content_length": int, "content_type": str}

    and ``body_iterator`` lazily yields ``bytes`` chunks of at most
    ``chunk_size`` bytes. Increments ``s3_bytes_total`` (direction="download")
    exactly once with the full ``content_length`` BEFORE the body starts
    flowing, so the metric reflects the requested object size even if the
    client disconnects mid-stream (mirrors ``read_object_for_role``).

    Raises ``PermissionError`` on role/bucket access violation.
    Raises ``FileNotFoundError`` if the object does not exist.
    """
    from botocore.exceptions import ClientError as _ClientError

    from another_s3_manager.metrics import s3_bytes_total, safe_role_label

    _validate_bucket_access(role, bucket, user_dict)
    validated_role = validate_role_access(role, user_dict)

    def do_fetch(s3_client):
        try:
            return s3_client.get_object(Bucket=bucket, Key=path)
        except _ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "") if hasattr(e, "response") else ""
            if error_code in {"404", "NoSuchKey"}:
                raise FileNotFoundError(f"Object '{path}' not found in bucket '{bucket}'") from e
            raise

    response = execute_with_s3_retry(validated_role, "get", do_fetch)

    content_length = response.get("ContentLength", 0)
    content_type = response.get("ContentType", "application/octet-stream")

    if content_length:
        s3_bytes_total.labels(
            role=safe_role_label(validated_role or "unknown"), bucket=bucket, direction="download"
        ).inc(content_length)

    def body_iter() -> Iterator[bytes]:
        body = response["Body"]
        try:
            while True:
                chunk = body.read(chunk_size)
                if not chunk:
                    break
                yield chunk
        finally:
            if hasattr(body, "close"):
                try:
                    body.close()
                except Exception:
                    pass

    metadata = {"content_length": content_length, "content_type": content_type}
    return metadata, body_iter()


def read_object_range_for_role(
    role: str, bucket: str, path: str, start: int, end: int, user_dict: Dict[str, Any]
) -> bytes:
    """
    Download and return a byte range of an object in `bucket` at `path`.

    Uses boto3 Range parameter: bytes=start-end (inclusive).
    Raises PermissionError on role/bucket access violation.
    Raises FileNotFoundError if the object does not exist.
    Increments the s3_bytes_total metric (direction="download") for the returned slice size.
    """
    from botocore.exceptions import ClientError as _ClientError

    from another_s3_manager.metrics import s3_bytes_total, safe_role_label

    _validate_bucket_access(role, bucket, user_dict)
    validated_role = validate_role_access(role, user_dict)

    def do_get_range(s3_client):
        try:
            response = s3_client.get_object(Bucket=bucket, Key=path, Range=f"bytes={start}-{end}")
            body: bytes = response["Body"].read()
            s3_bytes_total.labels(
                role=safe_role_label(validated_role or "unknown"), bucket=bucket, direction="download"
            ).inc(len(body))
            return body
        except _ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "") if hasattr(e, "response") else ""
            if error_code in {"404", "NoSuchKey"}:
                raise FileNotFoundError(f"Object '{path}' not found in bucket '{bucket}'") from e
            raise

    return execute_with_s3_retry(validated_role, "get", do_get_range)


# Extensions for which we force `Content-Type: <type>; charset=utf-8` on the
# presigned URL. S3 typically returns these as `text/plain` or
# `application/octet-stream` without a charset — Chrome/Safari then guess
# Latin-1 and Cyrillic / CJK / emoji renders as mojibake when opened in a
# new tab. Overriding the response Content-Type via the presigned URL
# (boto3 `ResponseContentType` param) fixes the rendering without re-uploading
# the object.
#
# `.html`/`.htm` and `.svg` are INTENTIONALLY EXCLUDED — overriding their
# Content-Type to a renderable `text/html` / `image/svg+xml` would let an
# authenticated user upload a malicious HTML/SVG file and share its presigned
# URL as a phishing page on a "trusted" S3 origin. They keep S3's stored
# Content-Type (typically octet-stream after AppFlow → browser downloads).
# Likewise, `.js`/`.css` are excluded — no reason to force them inline.
_TEXT_EXTENSION_TO_MIME = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".csv": "text/csv",
    ".tsv": "text/tab-separated-values",
    ".log": "text/plain",
    ".json": "application/json",
    ".yaml": "text/yaml",
    ".yml": "text/yaml",
    ".xml": "application/xml",
    ".py": "text/x-python",
    ".sh": "application/x-sh",
    ".sql": "application/sql",
    ".toml": "application/toml",
    ".ini": "text/plain",
    ".conf": "text/plain",
    ".srt": "text/plain",
    ".vtt": "text/vtt",
}


def _utf8_text_content_type_for(path: str) -> Optional[str]:
    """Return `<mime>; charset=utf-8` for known text extensions, else None.

    Inline-displayed text files served from S3 without a charset render as
    mojibake for non-ASCII content (Cyrillic, CJK, emoji) because the browser
    falls back to Latin-1. We attach an explicit charset only for extensions
    we're confident are UTF-8 text — everything else keeps S3's stored
    Content-Type so binary downloads (zip, pdf, png, …) aren't broken.
    """
    lower = path.lower()
    for ext, mime in _TEXT_EXTENSION_TO_MIME.items():
        if lower.endswith(ext):
            return f"{mime}; charset=utf-8"
    return None


def generate_presigned_url_for_role(
    role: str,
    bucket: str,
    path: str,
    user_dict: Dict[str, Any],
    expires_in: int = 3600,
) -> str:
    """
    Generate a boto3 presigned GET URL for an object in `bucket` at `path`.

    The URL is signed with the role's credentials and is valid for `expires_in`
    seconds (default 1 hour). Anyone holding the URL can fetch the object until
    it expires — no session cookie required. Use for shareable links and for
    browser-side <img>/<video> tags that can't carry the auth cookie reliably
    (e.g. third-party CDNs, copy-to-clipboard flows).

    For text extensions in `_TEXT_EXTENSION_TO_MIME`, the URL embeds a
    `ResponseContentType: <mime>; charset=utf-8` override so the browser
    renders Cyrillic / CJK / emoji correctly when the link is opened in a new
    tab. Without this, S3 typically serves text files without a charset and
    the browser guesses wrong.

    Raises PermissionError on role/bucket access violation.
    """
    _validate_bucket_access(role, bucket, user_dict)
    validated_role = validate_role_access(role, user_dict)

    params: Dict[str, Any] = {"Bucket": bucket, "Key": path}
    utf8_content_type = _utf8_text_content_type_for(path)
    if utf8_content_type is not None:
        params["ResponseContentType"] = utf8_content_type

    def do_presign(s3_client):
        return s3_client.generate_presigned_url(
            "get_object",
            Params=params,
            ExpiresIn=expires_in,
        )

    from another_s3_manager.metrics import (
        presigned_url_ttl_seconds,
        presigned_urls_total,
        safe_role_label,
    )

    url = execute_with_s3_retry(validated_role, "get", do_presign)
    presigned_urls_total.labels(role=safe_role_label(validated_role or "unknown"), bucket=bucket).inc()
    presigned_url_ttl_seconds.observe(expires_in)
    return url


def put_object_for_role(
    role: str,
    bucket: str,
    path: str,
    content: bytes,
    user_dict: Dict[str, Any],
    content_type: str = "application/octet-stream",
    content_disposition: Optional[str] = None,
) -> None:
    """
    Upload `content` to `bucket`/`path` using `role`.

    Raises PermissionError on role/bucket access violation.
    Increments s3_bytes_total (direction="upload") and s3_objects_total (operation="upload") on success.
    """
    from another_s3_manager.metrics import s3_bytes_total, s3_objects_total, safe_role_label

    _validate_bucket_access(role, bucket, user_dict)
    validated_role = validate_role_access(role, user_dict)

    def do_put(s3_client):
        put_params: Dict[str, Any] = {
            "Bucket": bucket,
            "Key": path,
            "Body": content,
            "ContentType": content_type,
        }
        if content_disposition:
            put_params["ContentDisposition"] = content_disposition
        s3_client.put_object(**put_params)
        s3_bytes_total.labels(role=safe_role_label(validated_role or "unknown"), bucket=bucket, direction="upload").inc(
            len(content)
        )
        s3_objects_total.labels(
            role=safe_role_label(validated_role or "unknown"), bucket=bucket, operation="upload"
        ).inc()

    execute_with_s3_retry(validated_role, "put", do_put)


def upload_fileobj_for_role(
    role: str,
    bucket: str,
    path: str,
    fileobj: BinaryIO,
    user_dict: Dict[str, Any],
    content_type: str = "application/octet-stream",
    content_disposition: Optional[str] = None,
    size: Optional[int] = None,
) -> None:
    """
    Stream `fileobj` to `bucket`/`path` using `role` via boto3's managed
    transfer (upload_fileobj): no full-body copy in RAM and automatic
    multipart above the transfer threshold, which lifts put_object's 5 GB
    single-request ceiling to the S3 5 TB object maximum.

    Used by the web upload route with the multipart parser's spooled temp
    file. The MCP upload path stays on put_object_for_role (bytes) — do not
    merge the two: their signatures are separate contracts.

    `size` is used only for s3_bytes_total accounting (the caller knows the
    exact spooled size); pass None to skip byte accounting.

    Raises PermissionError on role/bucket access violation.
    Increments s3_bytes_total (direction="upload") and s3_objects_total
    (operation="upload") exactly once, on success.
    """
    from another_s3_manager.metrics import s3_bytes_total, s3_objects_total, safe_role_label

    _validate_bucket_access(role, bucket, user_dict)
    validated_role = validate_role_access(role, user_dict)

    def do_put(s3_client):
        # execute_with_s3_retry may invoke this callback a SECOND time after a
        # credential refresh — rewind first, or the retry uploads 0 bytes.
        fileobj.seek(0)
        extra_args: Dict[str, Any] = {"ContentType": content_type}
        if content_disposition:
            extra_args["ContentDisposition"] = content_disposition
        s3_client.upload_fileobj(fileobj, bucket, path, ExtraArgs=extra_args)
        s3_bytes_total.labels(role=safe_role_label(validated_role or "unknown"), bucket=bucket, direction="upload").inc(
            size or 0
        )
        s3_objects_total.labels(
            role=safe_role_label(validated_role or "unknown"), bucket=bucket, operation="upload"
        ).inc()

    execute_with_s3_retry(validated_role, "put", do_put)


def copy_object_for_role(
    role: str,
    source_bucket: str,
    source_path: str,
    dest_bucket: str,
    dest_path: str,
    user_dict: Dict[str, Any],
) -> None:
    """
    Server-side copy of an object within a single role's credentials.

    Both source and destination buckets must be accessible to `role` (present in
    its allowed_buckets when that list is configured). Uses S3 CopyObject, so the
    body is copied by the storage backend without downloading — but only within
    ONE credential set (same role). Cross-role / cross-provider copy would need
    download+upload and is intentionally not supported here.

    Raises PermissionError on role/bucket access violation.
    Raises FileNotFoundError if the source object does not exist.
    """
    from botocore.exceptions import ClientError as _ClientError

    from another_s3_manager.metrics import s3_objects_total, safe_role_label

    # Validate BOTH buckets — a role scoped to specific allowed_buckets must be
    # allowed to write the destination, not just read the source.
    _validate_bucket_access(role, source_bucket, user_dict)
    _validate_bucket_access(role, dest_bucket, user_dict)
    validated_role = validate_role_access(role, user_dict)

    def do_copy(s3_client):
        try:
            s3_client.copy_object(
                Bucket=dest_bucket,
                Key=dest_path,
                CopySource={"Bucket": source_bucket, "Key": source_path},
            )
            s3_objects_total.labels(
                role=safe_role_label(validated_role or "unknown"),
                bucket=dest_bucket,  # the copy lands in the destination
                operation="copy",
            ).inc()
        except _ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "") if hasattr(e, "response") else ""
            if error_code in {"404", "NoSuchKey"}:
                raise FileNotFoundError(f"Source object '{source_path}' not found in bucket '{source_bucket}'") from e
            raise

    execute_with_s3_retry(validated_role, "put", do_copy)


def delete_object_for_role(role: str, bucket: str, path: str, user_dict: Dict[str, Any]) -> dict:
    """
    Delete a file or recursively delete a directory from `bucket`.

    `path` ending with "/" is treated as a directory (recursive delete).
    Without a trailing "/", exactly ONE key is deleted — the key must match
    `path` verbatim. This is NOT a prefix match: deleting "notes.txt" must
    never also remove "notes.txt.bak" just because the latter starts with the
    former (a real data-loss bug this function used to have, when it treated
    the single-file case as "delete everything list_objects_v2 returned for
    Prefix=path").

    Raises PermissionError on role/bucket access violation.
    Raises FileNotFoundError if the object/directory does not exist.
    Returns {"message": ..., "count": N}.
    """
    from another_s3_manager.metrics import s3_objects_total, safe_role_label

    _validate_bucket_access(role, bucket, user_dict)
    validated_role = validate_role_access(role, user_dict)

    is_directory = path.endswith("/")
    prefix = path.rstrip("/")

    def do_delete(s3_client):
        deleted_count = 0

        if is_directory:
            # Directory delete lists the "prefix/" subtree and takes every key
            # under it (recursive) — this genuinely needs every page.
            paginator = s3_client.get_paginator("list_objects_v2")
            pages = paginator.paginate(Bucket=bucket, Prefix=prefix + "/")

            objects_to_delete = [{"Key": obj["Key"]} for page in pages for obj in page.get("Contents", []) or []]

            if not objects_to_delete:
                # Note: we deliberately do NOT fall back to a blind
                # delete_object() call here and hope it raises for a missing
                # key — real S3's DeleteObject is idempotent and succeeds
                # silently even when the key does not exist, so existence
                # must be established from the listing above.
                raise FileNotFoundError(f"File or directory '{path}' not found")

            for i in range(0, len(objects_to_delete), 1000):
                batch = objects_to_delete[i : i + 1000]
                s3_client.delete_objects(Bucket=bucket, Delete={"Objects": batch, "Quiet": True})
                deleted_count += len(batch)
        else:
            # Single-key existence + exact-match check in ONE list call
            # instead of paginating the entire prefix subtree. S3 returns
            # Contents in UTF-8 lexicographic key order, and a string that is
            # a strict prefix of another always sorts before it — so if
            # `prefix` exists as an exact key, it is necessarily the FIRST
            # result of Prefix=prefix, MaxKeys=1. That settles existence
            # without walking hundreds of pages under a hot prefix (e.g.
            # deleting "logs/2026" out of 200k keys named "logs/2026...").
            # head_object(Bucket, Key=prefix) would work too (one request,
            # no listing) — list_objects_v2 is used here so a NoSuchKey
            # ClientError never has to be threaded through as "not found"
            # for this branch, keeping existence-detection uniform with the
            # directory branch above (both derive it from a Contents list).
            response = s3_client.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=1)
            contents = response.get("Contents", []) or []
            if not contents or contents[0]["Key"] != prefix:
                raise FileNotFoundError(f"File or directory '{path}' not found")

            # Exact match confirmed — delete_object is equivalent to, and
            # cheaper than, the batch API for a single key.
            s3_client.delete_object(Bucket=bucket, Key=prefix)
            deleted_count = 1

        s3_objects_total.labels(
            role=safe_role_label(validated_role or "unknown"), bucket=bucket, operation="delete"
        ).inc(deleted_count)

        return {"message": f"Successfully deleted {deleted_count} object(s)", "count": deleted_count}

    return execute_with_s3_retry(validated_role, "delete", do_delete)
