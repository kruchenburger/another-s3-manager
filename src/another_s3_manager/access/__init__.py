"""Public application API for the Access context."""

from another_s3_manager.access import service as _service
from another_s3_manager.access.errors import (
    AccessDenied,
    AuthenticationError,
)
from another_s3_manager.access.passwords import (
    hash_password,
    pwd_context,
    verify_password,
)
from another_s3_manager.access.policies import deletion_allowed, deletion_disabled, effective_allowed_roles
from another_s3_manager.access.principal import (
    BearerAuthentication,
    Principal,
    account_identity,
)
from another_s3_manager.access.service import (
    allowed_roles,
    authenticate_bearer,
    authenticate_local,
    authenticate_session,
    check_ban,
    principal_for,
    record_login_attempt,
    require_bucket,
    require_destructive,
    require_not_deletion_disabled,
    require_role,
    require_role_name,
    require_transfer,
    require_write,
    session_token_is_wellformed,
)
from another_s3_manager.access.sessions import (
    create_access_token,
    decode_session_payload,
    generate_csrf_token,
    get_jwt_secret_key,
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
    "require_transfer",
    "require_write",
    "AuthenticationError",
    "Principal",
    "BearerAuthentication",
    "account_identity",
    "hash_password",
    "verify_password",
    "pwd_context",
    "get_jwt_secret_key",
    "generate_csrf_token",
    "create_access_token",
    "decode_session_payload",
    "authenticate_session",
    "authenticate_bearer",
    "authenticate_local",
    "principal_for",
    "session_token_is_wellformed",
    "check_ban",
    "record_login_attempt",
]
