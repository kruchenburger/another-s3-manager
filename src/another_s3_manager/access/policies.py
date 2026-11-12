"""Access decisions over supplied configuration; no adapter dependencies."""

import os
from collections.abc import Collection


def effective_allowed_roles(stored: list[str], config_role_names: Collection[str]) -> list[str]:
    """Return stored grants that still exist in configuration, preserving order."""
    # This protects new application-authorized operations, not already issued
    # presigned URLs (valid until expiry). An in-flight request authenticated
    # before a same-name delete/recreate is not guaranteed to be rechecked.
    # External restoration of a name can revive grants: identities have no generations.
    names = set(config_role_names)
    return [name for name in stored if name in names]


def granted_roles(user: dict, config: dict) -> list[str]:
    names = [role["name"] for role in config.get("roles", []) if role.get("name")]
    if user.get("is_admin", False):
        return names
    return effective_allowed_roles(user.get("allowed_roles", []), set(names))


def role_is_granted(role: str, user: dict, config: dict) -> bool:
    return bool(user.get("is_admin", False)) or role in granted_roles(user, config)


def bucket_is_allowed(role_config: dict, bucket: str) -> bool:
    allowed = role_config.get("allowed_buckets")
    return not allowed or bucket in allowed


def deletion_disabled(config: dict) -> bool:
    if os.getenv("DISABLE_DELETION", "").lower() == "true":
        return True
    return bool(config.get("disable_deletion", False))


def deletion_allowed(config: dict, role_name: str | None) -> bool:
    if deletion_disabled(config):
        return False
    if role_name is None:
        return True
    role = next((r for r in config.get("roles", []) if r.get("name") == role_name), None)
    return role is not None and role.get("allow_delete", True) is True


def write_denial(token_is_read_only: bool, tool_name: str, config: dict) -> str | None:
    if config.get("mcp_disable_writes", False):
        return "writes_disabled"
    if token_is_read_only:
        return "read_only_token"
    if tool_name == "delete_file" and not deletion_allowed(config, None):
        return "deletion_disabled"
    return None
