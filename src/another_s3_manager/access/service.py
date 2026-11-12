"""Application API for access policies, independent of transports."""

from another_s3_manager.access import policies
from another_s3_manager.access.errors import AccessDenied

_WRITE_MESSAGES = {
    "writes_disabled": "Server config disables MCP writes",
    "read_only_token": "This token is read-only",
    "deletion_disabled": "Deletion is disabled in server config",
}


def allowed_roles(user: dict, config: dict) -> list[str]:
    return policies.granted_roles(user, config)


def require_role(role: str | None, user: dict, config: dict) -> str:
    if role is None or not role.strip():
        raise AccessDenied("role_required", "A role is required for this request.")
    if not policies.role_is_granted(role, user, config):
        raise AccessDenied("role_not_allowed", f"Access denied: You don't have permission to use role '{role}'")
    return role


def require_bucket(role: str, bucket: str, user: dict, config: dict) -> None:
    """Check the bucket after the caller's role and role-existence checks.

    Keep these checks separate: legacy adapters load configuration between
    them, and role existence has adapter-specific error handling.
    """
    role_config = next((r for r in config.get("roles", []) if r.get("name") == role), None)
    if role_config is None:
        # Callers check existence first; fail closed if one ever does not.
        raise AccessDenied("role_not_found", f"Role '{role}' not found in configuration")
    if not policies.bucket_is_allowed(role_config, bucket):
        raise AccessDenied("bucket_not_allowed", f"bucket '{bucket}' not in allowed_buckets for role '{role}'")


def require_not_deletion_disabled(config: dict) -> None:
    if policies.deletion_disabled(config):
        raise AccessDenied("deletion_disabled", _WRITE_MESSAGES["deletion_disabled"])


def require_write(token_is_read_only: bool, tool_name: str, config: dict) -> None:
    reason = policies.write_denial(token_is_read_only, tool_name, config)
    if reason is not None:
        raise AccessDenied(reason, _WRITE_MESSAGES[reason], {"tool": tool_name})
