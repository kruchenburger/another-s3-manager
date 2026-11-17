import pytest


def test_local_recovery_validates_then_commits_atomically(monkeypatch):
    from another_s3_manager import access, users
    from another_s3_manager.database import session_scope
    from another_s3_manager.models import User

    user = users.create_user("sso", "!", is_admin=True, allowed_roles=["Default"])
    with session_scope() as session:
        row = session.get(User, user["id"])
        row.auth_source = "oidc"
        row.mapping_mode_applied = "initial"
        row.is_disabled = True
    before = users.get_user_by_id(user["id"])
    with pytest.raises(access.AccessDenied):
        access.recover_local_account("sso", password="!")
    assert users.get_user_by_id(user["id"]) == before
    access.recover_local_account("sso", password="RecoveredPassword1")
    after = users.get_user_by_id(user["id"])
    assert after["auth_source"] == "local" and after["is_disabled"] is True
    assert after["session_epoch"] == before["session_epoch"] + 1
    assert after["allowed_roles"] == ["Default"] and after["is_admin"] is True
    assert access.verify_password("RecoveredPassword1", after["password_hash"])
    access.recover_local_account("sso", enable=True)
    enabled = users.get_user_by_id(user["id"])
    assert enabled["is_disabled"] is False
    assert enabled["password_hash"] == after["password_hash"]
    assert enabled["session_epoch"] == after["session_epoch"]


def test_recovery_target_identity_and_replacement():
    from another_s3_manager import access, users
    from another_s3_manager.database import session_scope
    from another_s3_manager.models import User

    assert access.recovery_target_identity("missing") is None
    user = users.create_user("target", "!")
    identity = access.recovery_target_identity("target")
    assert identity == (user["id"], user["auth_generation"])
    with session_scope() as session:
        session.get(User, user["id"]).auth_generation = "replacement-generation"
    before = users.get_user_by_id(user["id"])
    with pytest.raises(access.AuthenticationError) as error:
        access.recover_local_account("target", enable=True, expected_identity=identity)
    assert error.value.code == "ACCOUNT_REPLACED"
    assert users.get_user_by_id(user["id"]) == before
