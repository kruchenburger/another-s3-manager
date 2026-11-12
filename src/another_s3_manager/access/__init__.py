"""Public application API for the Access context."""

from another_s3_manager.access.errors import AccessDenied
from another_s3_manager.access.service import (
    allowed_roles,
    require_bucket,
    require_delete,
    require_not_deletion_disabled,
    require_role,
    require_write,
)

__all__ = [
    "AccessDenied",
    "allowed_roles",
    "require_bucket",
    "require_delete",
    "require_not_deletion_disabled",
    "require_role",
    "require_write",
]
