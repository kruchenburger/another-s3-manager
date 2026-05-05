"""
S3 client management module
"""

import logging
import time
from datetime import datetime
from typing import Any, Callable, Dict, Optional, TypeVar
from typing import Any as AnyType

import boto3
from botocore.config import Config
from botocore.credentials import RefreshableCredentials
from botocore.exceptions import ClientError, CredentialRetrievalError, MetadataRetrievalError
from botocore.session import Session as BotocoreSession

from another_s3_manager.constants import S3_USE_SSL, S3_VERIFY_SSL

# Cache for S3 clients per role
_s3_clients_cache: Dict[str, AnyType] = {}
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
            except Exception:  # noqa: BLE001 - best effort cleanup
                pass
            try:
                inner_session = getattr(default_session, "_session", None)
                if inner_session is not None and hasattr(inner_session, "_credentials"):
                    inner_session._credentials = None
            except Exception:
                pass

        module_session = getattr(boto3, "_session", None)
        if module_session is not None and hasattr(module_session, "_credentials"):
            try:
                module_session._credentials = None
            except Exception:
                pass

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
        return boto3.client("s3", **client_kwargs)

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

        def refresh_assumed_role_credentials():
            """Refresh credentials by assuming the role again using current pod identity credentials."""
            try:
                logger.debug(f"Refreshing credentials for assumed role: {role_arn}")
                # Create a fresh STS client that will use current pod identity credentials
                sts_client = boto3.client("sts", use_ssl=use_ssl, verify=verify_ssl, config=boto_config)

                assumed_role = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="s3-file-manager-session")
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
                # Get initial credentials
                sts_client = boto3.client("sts", use_ssl=use_ssl, verify=verify_ssl, config=boto_config)

                logger.info(f"Attempting to assume role: {role_arn}")
                assumed_role = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="s3-file-manager-session")
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
                    # Second attempt failed or not an expired token error
                    logger.error(
                        f"Failed to retrieve credentials for STS client (needed to assume role {role_arn})",
                        extra={
                            "role_arn": role_arn,
                            "error_type": "CredentialRetrievalError",
                            "attempt": sts_attempts + 1,
                        },
                        exc_info=True,
                    )
                    raise ValueError(
                        f"Unable to retrieve AWS credentials needed to assume role {role_arn}. "
                        f"In Kubernetes, ensure IRSA (IAM Roles for Service Accounts) or eks-pod-identity is configured, "
                        f"or that the pod has access to instance profile credentials. "
                        f"Error: {str(e)}"
                    ) from e
            except ClientError as e:
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
                # Re-raise with more context
                if error_code == "AccessDenied":
                    raise ValueError(
                        f"Access denied when trying to assume role {role_arn}. "
                        f"Check that the pod/service account has permission to assume this role. "
                        f"Error: {error_msg}"
                    ) from e
                raise ValueError(f"Failed to assume role {role_arn}: {error_msg or str(e)}") from e
            except Exception as e:
                error_type = type(e).__name__
                error_msg = str(e)
                # Check for NoCredentialsError
                if "NoCredentialsError" in error_type or "Unable to locate credentials" in error_msg:
                    logger.error(
                        f"No AWS credentials found (needed to assume role {role_arn})",
                        extra={
                            "role_arn": role_arn,
                            "error_type": error_type,
                        },
                        exc_info=True,
                    )
                    raise ValueError(
                        f"Unable to locate AWS credentials needed to assume role {role_arn}. "
                        f"In Kubernetes, ensure IRSA (IAM Roles for Service Accounts) or eks-pod-identity is configured, "
                        f"or that the pod has access to instance profile credentials. "
                        f"Error: {error_msg}"
                    ) from e

                logger.error(
                    f"Unexpected error while assuming role {role_arn}",
                    extra={"role_arn": role_arn, "error_type": error_type},
                    exc_info=True,
                )
                raise ValueError(f"Unexpected error while assuming role {role_arn}: {error_msg}") from e

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

        return boto3.client("s3", **client_kwargs)

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

        return boto3.client("s3", **client_kwargs)

    else:
        raise ValueError(f"Unknown role type: {role_type}")


def get_s3_client(role_name: Optional[str] = None) -> AnyType:
    """
    Get S3 client for the specified role (cached).

    Args:
        role_name: Name of the role to use, or None for default

    Returns:
        boto3 S3 client
    """
    # Import here to avoid circular dependency
    from another_s3_manager.config import load_config

    # Use cache key based on role name
    cache_key = role_name or "default"

    # Return cached client if available
    if cache_key in _s3_clients_cache:
        return _s3_clients_cache[cache_key]

    # Load config and find role
    config = load_config(force_reload=False)
    roles = config.get("roles", [])

    if role_name:
        role = next((r for r in roles if r.get("name") == role_name), None)
        if not role:
            raise ValueError(f"Role '{role_name}' not found in configuration")
    else:
        # Use first role
        role = roles[0] if roles else None

        if not role:
            # Fallback to default AWS credentials
            role = {"name": "Default", "type": "default", "description": "Use default AWS credentials"}

    # Create and cache client
    try:
        role_type = role.get("type", "unknown")
        logger.debug(f"Creating S3 client for role '{role_name or 'default'}' (type: {role_type})")
        client = _create_s3_client_from_role(role)
        _s3_clients_cache[cache_key] = client
        logger.debug(f"Successfully created and cached S3 client for role '{role_name or 'default'}'")
        return client
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
    from another_s3_manager.metrics import (
        s3_operation_duration_seconds,
        s3_operations_total,
        safe_role_label,
    )

    role_lbl = safe_role_label(role_name or "unknown")
    start = time.perf_counter()
    try:
        result = _execute_with_retry_inner(role_name, callback)
        s3_operations_total.labels(role=role_lbl, operation=operation, result="ok").inc()
        return result
    except Exception:
        s3_operations_total.labels(role=role_lbl, operation=operation, result="error").inc()
        raise
    finally:
        s3_operation_duration_seconds.labels(operation=operation).observe(time.perf_counter() - start)


def clear_s3_clients_cache() -> None:
    """Clear the S3 clients cache."""
    global _s3_clients_cache
    _s3_clients_cache.clear()


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
) -> Dict[str, Any]:
    """List ALL objects under `prefix` recursively (no Delimiter), with pagination.

    Designed for MCP agents that want to see/count an entire subtree without
    walking it dir-by-dir (which would mean N+1 calls). Hard ceiling: 10000
    keys per call (S3's own ListObjectsV2 limit).

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
    # We cap MaxKeys here for safety so a single MCP call can't return more than
    # 10k entries even if a future caller asks for it.
    max_keys = max(1, min(max_keys, 10_000))

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


def read_object_for_role(role: str, bucket: str, path: str, user_dict: Dict[str, Any]) -> bytes:
    """
    Download and return the full body of an object in `bucket` at `path`.

    Raises PermissionError on role/bucket access violation.
    Raises FileNotFoundError if the object does not exist.
    Increments the s3_bytes_downloaded_total metric.
    """
    from botocore.exceptions import ClientError as _ClientError

    from another_s3_manager.metrics import s3_bytes_downloaded_total, safe_role_label

    _validate_bucket_access(role, bucket, user_dict)
    validated_role = validate_role_access(role, user_dict)

    def do_get(s3_client):
        try:
            response = s3_client.get_object(Bucket=bucket, Key=path)
            body: bytes = response["Body"].read()
            s3_bytes_downloaded_total.labels(role=safe_role_label(validated_role or "unknown"), bucket=bucket).inc(
                len(body)
            )
            return body
        except _ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "") if hasattr(e, "response") else ""
            if error_code in {"404", "NoSuchKey"}:
                raise FileNotFoundError(f"Object '{path}' not found in bucket '{bucket}'") from e
            raise

    return execute_with_s3_retry(validated_role, "get", do_get)


def read_object_range_for_role(
    role: str, bucket: str, path: str, start: int, end: int, user_dict: Dict[str, Any]
) -> bytes:
    """
    Download and return a byte range of an object in `bucket` at `path`.

    Uses boto3 Range parameter: bytes=start-end (inclusive).
    Raises PermissionError on role/bucket access violation.
    Raises FileNotFoundError if the object does not exist.
    Increments the s3_bytes_downloaded_total metric for the returned slice size.
    """
    from botocore.exceptions import ClientError as _ClientError

    from another_s3_manager.metrics import s3_bytes_downloaded_total, safe_role_label

    _validate_bucket_access(role, bucket, user_dict)
    validated_role = validate_role_access(role, user_dict)

    def do_get_range(s3_client):
        try:
            response = s3_client.get_object(Bucket=bucket, Key=path, Range=f"bytes={start}-{end}")
            body: bytes = response["Body"].read()
            s3_bytes_downloaded_total.labels(role=safe_role_label(validated_role or "unknown"), bucket=bucket).inc(
                len(body)
            )
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

    return execute_with_s3_retry(validated_role, "get", do_presign)


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
    Increments the s3_bytes_uploaded_total metric on success.
    """
    from another_s3_manager.metrics import s3_bytes_uploaded_total, safe_role_label

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
        s3_bytes_uploaded_total.labels(role=safe_role_label(validated_role or "unknown"), bucket=bucket).inc(
            len(content)
        )

    execute_with_s3_retry(validated_role, "put", do_put)


def delete_object_for_role(role: str, bucket: str, path: str, user_dict: Dict[str, Any]) -> dict:
    """
    Delete a file or recursively delete a directory from `bucket`.

    `path` ending with "/" is treated as a directory (recursive delete).
    Raises PermissionError on role/bucket access violation.
    Raises FileNotFoundError if the object/directory does not exist.
    Returns {"message": ..., "count": N}.
    """
    from botocore.exceptions import ClientError as _ClientError

    _validate_bucket_access(role, bucket, user_dict)
    validated_role = validate_role_access(role, user_dict)

    is_directory = path.endswith("/")
    prefix = path.rstrip("/")

    def do_delete(s3_client):
        deleted_count = 0
        paginator = s3_client.get_paginator("list_objects_v2")
        pages = paginator.paginate(Bucket=bucket, Prefix=prefix + ("/" if is_directory else ""))

        objects_to_delete = []
        for page in pages:
            if "Contents" in page:
                for obj in page["Contents"]:
                    objects_to_delete.append({"Key": obj["Key"]})

        if not is_directory and not objects_to_delete:
            try:
                s3_client.delete_object(Bucket=bucket, Key=prefix)
                deleted_count = 1
            except _ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "") if hasattr(e, "response") else ""
                if error_code in ("404", "NoSuchKey"):
                    raise FileNotFoundError(f"File or directory '{path}' not found") from e
                raise
        else:
            if objects_to_delete:
                for i in range(0, len(objects_to_delete), 1000):
                    batch = objects_to_delete[i : i + 1000]
                    s3_client.delete_objects(Bucket=bucket, Delete={"Objects": batch, "Quiet": True})
                    deleted_count += len(batch)

        if deleted_count == 0:
            raise FileNotFoundError(f"File or directory '{path}' not found")

        return {"message": f"Successfully deleted {deleted_count} object(s)", "count": deleted_count}

    return execute_with_s3_retry(validated_role, "delete", do_delete)
