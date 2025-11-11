"""
S3 client management module
"""
import os
from typing import Optional, Dict, Any, Any as AnyType
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config

try:
    from constants import S3_USE_SSL, S3_VERIFY_SSL
except ImportError:
    # Fallback for direct execution
    S3_USE_SSL = True
    S3_VERIFY_SSL = True


# Cache for S3 clients per role
_s3_clients_cache: Dict[str, AnyType] = {}


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
        credentials = assumed_role['Credentials']

        client_kwargs = {
            'aws_access_key_id': credentials['AccessKeyId'],
            'aws_secret_access_key': credentials['SecretAccessKey'],
            'aws_session_token': credentials['SessionToken'],
            'use_ssl': use_ssl,
            'verify': verify_ssl,
            'config': boto_config,
        }
        if endpoint_url:
            client_kwargs['endpoint_url'] = endpoint_url
        return boto3.client('s3', **client_kwargs)

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
    client = _create_s3_client_from_role(role)
    _s3_clients_cache[cache_key] = client

    return client


def clear_s3_clients_cache() -> None:
    """Clear the S3 clients cache."""
    global _s3_clients_cache
    _s3_clients_cache.clear()

