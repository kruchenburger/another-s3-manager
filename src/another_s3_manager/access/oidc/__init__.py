"""OIDC persistence API; no network, callback or claim-mapping behavior."""

from .identities import find_identity, insert_identity
from .transactions import consume_login_transaction, register_login_transaction

__all__ = ["find_identity", "insert_identity", "register_login_transaction", "consume_login_transaction"]
