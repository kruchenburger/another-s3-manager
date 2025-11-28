"""
S3 client management module
"""
import os
import logging
from datetime import datetime
from typing import Optional, Dict, Any, Any as AnyType, Callable, TypeVar
import boto3
from botocore.exceptions import ClientError, CredentialRetrievalError, MetadataRetrievalError
from botocore.config import Config
from botocore.credentials import RefreshableCredentials
from botocore.session import Session as BotocoreSession

try:
    from constants import S3_USE_SSL, S3_VERIFY_SSL
except ImportError:
    # Fallback for direct execution
    S3_USE_SSL = True
    S3_VERIFY_SSL = True


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
                logger.debug(
                    "MetadataRetrievalError with expired token detected, treating as expired credentials"
                )
                return True

        if isinstance(chained_error, CredentialRetrievalError):
            provider_name = getattr(chained_error, "provider", "unknown")
            # Check if it's from container-role provider (eks-pod-identity)
            if provider_name and "container" in provider_name.lower():
                message = str(chained_error).lower()
                if any(phrase in message for phrase in expired_phrases):
                    logger.debug(
                        "CredentialRetrievalError from container-role provider with expired token"
                    )
                    return True
            logger.debug(
                "CredentialRetrievalError from provider '%s' treated as expired credentials",
                provider_name,
            )
            return True

        message = str(chained_error).lower()
        if any(phrase in message for phrase in expired_phrases):
            if any(hint in message for hint in eks_identity_hints):
                logger.warning(
                    "Detected expired pod identity token, requesting fresh credentials"
                )
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
        'signature_version': 's3v4',
        'retries': {'max_attempts': 3},
        'connect_timeout': 10,  # 10 seconds connection timeout
        'read_timeout': 30,      # 30 seconds read timeout (for large uploads)
    }
    if addressing_style:
        config_kwargs['s3'] = {'addressing_style': addressing_style}
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
            'use_ssl': use_ssl,
            'verify': verify_ssl,
            'config': boto_config,
        }
        if endpoint_url:
            client_kwargs['endpoint_url'] = endpoint_url
        return boto3.client('s3', **client_kwargs)

    elif role_type == "profile":
        profile_name = role.get("profile_name")
        if not profile_name:
            raise ValueError("profile_name is required for profile type")
        session = boto3.Session(profile_name=profile_name)
        client_kwargs = {
            'use_ssl': use_ssl,
            'verify': verify_ssl,
            'config': boto_config,
        }
        if endpoint_url:
            client_kwargs['endpoint_url'] = endpoint_url
        return session.client('s3', **client_kwargs)

    elif role_type == "assume_role":
        role_arn = role.get("role_arn")
        if not role_arn:
            raise ValueError("role_arn is required for assume_role type")

        def refresh_assumed_role_credentials():
            """Refresh credentials by assuming the role again using current pod identity credentials."""
            try:
                logger.debug(f"Refreshing credentials for assumed role: {role_arn}")
                # Create a fresh STS client that will use current pod identity credentials
                sts_client = boto3.client(
                    'sts',
                    use_ssl=use_ssl,
                    verify=verify_ssl,
                    config=boto_config
                )

                assumed_role = sts_client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="s3-file-manager-session"
                )
                creds = assumed_role['Credentials']

                # Get expiration time - keep as string for RefreshableCredentials
                expiration = creds.get('Expiration')
                # RefreshableCredentials expects expiry_time as string, not datetime
                if expiration is not None and isinstance(expiration, datetime):
                    # Convert datetime to ISO format string
                    expiration = expiration.isoformat()
                elif expiration is not None and not isinstance(expiration, str):
                    expiration = None

                logger.debug(f"Successfully refreshed credentials for role {role_arn}, expires at: {expiration}")

                return {
                    'access_key': creds['AccessKeyId'],
                    'secret_key': creds['SecretAccessKey'],
                    'token': creds['SessionToken'],
                    'expiry_time': expiration  # String or None
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
                sts_client = boto3.client(
                    'sts',
                    use_ssl=use_ssl,
                    verify=verify_ssl,
                    config=boto_config
                )

                logger.info(f"Attempting to assume role: {role_arn}")
                assumed_role = sts_client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="s3-file-manager-session"
                )
                initial_credentials = assumed_role['Credentials']

                # Get expiration time - keep as string for RefreshableCredentials
                expiration = initial_credentials.get('Expiration')
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
                        }
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
                        exc_info=True
                    )
                    raise ValueError(
                        f"Unable to retrieve AWS credentials needed to assume role {role_arn}. "
                        f"In Kubernetes, ensure IRSA (IAM Roles for Service Accounts) or eks-pod-identity is configured, "
                        f"or that the pod has access to instance profile credentials. "
                        f"Error: {str(e)}"
                    ) from e
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '') if hasattr(e, 'response') and e.response else ''
                error_msg = e.response.get('Error', {}).get('Message', '') if hasattr(e, 'response') and e.response else ''
                logger.error(
                    f"Failed to assume role {role_arn}",
                    extra={
                        "role_arn": role_arn,
                        "error_code": error_code,
                        "error_message": error_msg,
                    },
                    exc_info=True
                )
                # Re-raise with more context
                if error_code == 'AccessDenied':
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
                        exc_info=True
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
                    exc_info=True
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
                'access_key': initial_credentials['AccessKeyId'],
                'secret_key': initial_credentials['SecretAccessKey'],
                'token': initial_credentials['SessionToken'],
                'expiry_time': expiration  # Can be None if not provided
            },
            refresh_using=refresh_assumed_role_credentials,
            method='assume-role'
        )

        # Create a botocore session with refreshable credentials
        botocore_session = BotocoreSession()
        botocore_session._credentials = refreshable_creds

        client_kwargs = {
            'use_ssl': use_ssl,
            'verify': verify_ssl,
            'config': boto_config,
        }
        if endpoint_url:
            client_kwargs['endpoint_url'] = endpoint_url

        logger.info(f"Creating S3 client with auto-refreshable assumed role credentials for {role_arn}")
        return botocore_session.create_client('s3', **client_kwargs)

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
            'aws_access_key_id': access_key_id,
            'aws_secret_access_key': secret_access_key,
            'use_ssl': use_ssl,
            'verify': verify_ssl,
            'config': boto_config,
        }
        if region and region.strip():
            client_kwargs['region_name'] = region.strip()
        if endpoint_url:
            client_kwargs['endpoint_url'] = endpoint_url

        return boto3.client('s3', **client_kwargs)

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
            'aws_access_key_id': access_key_id,
            'aws_secret_access_key': secret_access_key,
            'endpoint_url': endpoint_url,
            'use_ssl': use_ssl,
            'verify': verify_ssl,
            'config': boto_config,
        }
        if region and region.strip():
            client_kwargs['region_name'] = region.strip()

        return boto3.client('s3', **client_kwargs)

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
    from config import load_config

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
    except Exception as e:
        logger.error(
            f"Failed to create S3 client for role '{role_name or 'default'}'",
            extra={
                "role_name": role_name,
                "role_type": role.get("type"),
                "role_arn": role.get("role_arn") if role.get("type") == "assume_role" else None,
            },
            exc_info=True
        )
        raise


def execute_with_s3_retry(role_name: Optional[str], callback: Callable[[AnyType], T]) -> T:
    """
    Run an S3 operation with automatic credential refresh on expiration.

    Args:
        role_name: Role name used to resolve the client.
        callback: Callable receiving the S3 client and returning any value.

    Returns:
        Result of callback execution.

    Raises:
        Exception: Re-raises the original exception if retry is not possible.
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
                    }
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
                    exc_info=True
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
            if hasattr(exc, 'response') and exc.response:
                if isinstance(exc.response, dict):
                    error_code = exc.response.get('Error', {}).get('Code', '')

            logger.warning(
                f"S3 operation failed for role '{role_name}'",
                extra={
                    "role_name": role_name,
                    "attempt": attempts + 1,
                    "error_type": type(exc).__name__,
                    "error_code": error_code,
                    "is_expired_credentials": is_expired,
                },
                exc_info=True
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


def clear_s3_clients_cache() -> None:
    """Clear the S3 clients cache."""
    global _s3_clients_cache
    _s3_clients_cache.clear()

