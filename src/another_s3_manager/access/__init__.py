"""Public application API for the Access context."""

from another_s3_manager.access import service as _service
from another_s3_manager.access.errors import AccessDenied
from another_s3_manager.access.policies import deletion_allowed, deletion_disabled, effective_allowed_roles
from another_s3_manager.access.service import (
    allowed_roles,
    require_bucket,
    require_destructive,
    require_not_deletion_disabled,
    require_role,
    require_role_name,
    require_write,
)


def require_delete(role_name: str | None, config: dict) -> None:
    """Delegate the public deletion gate to the application service."""
    _service.require_delete(role_name, config)


__all__ = [
    "AccessDenied",
    "allowed_roles",
    "deletion_allowed",
    "deletion_disabled",
    "effective_allowed_roles",
    "require_role_name",
    "require_bucket",
    "require_delete",
    "require_destructive",
    "require_not_deletion_disabled",
    "require_role",
    "require_write",
]
