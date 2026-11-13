import pytest

from another_s3_manager import access, move_jobs, s3_client, users
from another_s3_manager.database import session_scope
from another_s3_manager.errors import MoveError
from another_s3_manager.models import User


def test_recreated_same_id_username_and_created_at_rejects_old_session_and_job():
    old = users.create_user("alice", "hash")
    old = users.get_user_by_id(old["id"])
    token = access.issue_session(access.Principal(old), method="pwd", lifetime_minutes=180)
    identity = move_jobs.owner_identity(old)
    with session_scope() as session:
        timestamp = session.get(User, old["id"]).created_at
    users.delete_user("alice")
    with session_scope() as session:
        session.add(User(id=old["id"], username="alice", password_hash="hash", created_at=timestamp))
    new = users.get_user_by_id(old["id"])
    assert old["created_at"] == new["created_at"]
    assert old["auth_generation"] != new["auth_generation"]
    assert identity == s3_client.account_identity(old) == access.account_identity(old)
    assert identity != move_jobs.owner_identity(new)
    with pytest.raises(access.AuthenticationError) as error:
        access.authenticate_session(token)
    assert error.value.code == "ACCOUNT_REPLACED"
    with pytest.raises(MoveError) as error:
        s3_client.require_current_account(old, "Default", snapshot=(new, {}))
    assert error.value.code == "ACCESS_DENIED"


def test_principals_require_generation():
    with pytest.raises(ValueError):
        access.Principal({"id": 1, "username": "alice", "auth_generation": ""})
