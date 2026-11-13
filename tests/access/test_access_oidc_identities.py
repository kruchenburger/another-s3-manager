"""Identity insertion participates in an Access-owned transaction."""

import pytest
from sqlalchemy.exc import IntegrityError

from another_s3_manager import access, users
from another_s3_manager.access import oidc
from another_s3_manager.access.oidc.identities import find_identity, insert_identity
from another_s3_manager.database import session_scope


def test_identity_insertion_is_internal():
    for package in (access, oidc):
        assert "insert_identity" not in package.__all__
        assert not hasattr(package, "insert_identity")


def test_identity_insert_rollback_uniqueness_and_user_cascade():
    owner = users.create_user("alice", "hash")
    with pytest.raises(RuntimeError), session_scope() as session:
        insert_identity(session, user_id=owner["id"], issuer="issuer", subject="rollback")
        raise RuntimeError("Abort provisioning")
    assert find_identity("issuer", "rollback") is None
    with session_scope() as session:
        insert_identity(session, user_id=owner["id"], issuer="issuer", subject="subject")
    for issuer, subject in (("issuer", "subject"), ("issuer", "another")):
        with pytest.raises(IntegrityError), session_scope() as session:
            insert_identity(session, user_id=owner["id"], issuer=issuer, subject=subject)
    assert find_identity("issuer", "subject")["user_id"] == owner["id"]
    users.delete_user("alice")
    assert find_identity("issuer", "subject") is None
