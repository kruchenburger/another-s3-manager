"""Public application API for the Access context."""

from another_s3_manager.access import service as _service
from another_s3_manager.access.errors import (
    CURRENT_ACCOUNT_DENIALS,
    AccessDenied,
    AuthenticationError,
)
from another_s3_manager.access.oidc import (
    consume_login_transaction,
    find_identity,
    register_login_transaction,
)
from another_s3_manager.access.oidc.discovery import discovery_for
from another_s3_manager.access.oidc.settings import oidc_settings
from another_s3_manager.access.oidc.transactions import CookieOperation, OidcCompletion, OidcStart
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
    change_own_password,
    check_ban,
    complete_oidc_login,
    delete_account,
    local_login_allowed,
    managed_by_sso,
    oidc_runtime,
    principal_for,
    record_login_attempt,
    recover_local_account,
    require_bucket,
    require_destructive,
    require_not_deletion_disabled,
    require_role,
    require_role_name,
    require_transfer,
    require_write,
    session_identity,
    session_token_is_wellformed,
    start_oidc_login,
    update_account,
)
from another_s3_manager.access.sessions import (
    create_access_token,
    decode_session_payload,
    generate_csrf_token,
    get_jwt_secret_key,
    issue_session,
    validate_lifetime_minutes,
)
from another_s3_manager.access.users import prune_role_grants, reset_admin_password, role_grants_lock


def require_delete(role_name: str | None, config: dict) -> None:
    """Delegate the public deletion gate to the application service."""
    _service.require_delete(role_name, config)


__all__ = [
    "update_account",
    "delete_account",
    "change_own_password",
    "issue_session",
    "validate_lifetime_minutes",
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

__all__ += ["find_identity", "register_login_transaction", "consume_login_transaction"]

__all__ += ["CURRENT_ACCOUNT_DENIALS"]

__all__ += ["reset_admin_password"]


__all__ += ["oidc_settings", "role_grants_lock"]


__all__ += [
    "start_oidc_login",
    "complete_oidc_login",
    "oidc_runtime",
    "managed_by_sso",
    "local_login_allowed",
    "recover_local_account",
    "session_identity",
    "discovery_for",
]


__all__ += ["prune_role_grants"]

__all__ += ["OidcStart", "OidcCompletion", "CookieOperation"]
