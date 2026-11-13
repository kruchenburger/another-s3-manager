import pytest

from another_s3_manager import access


def test_empty_install_seed_wrong_password_and_admin_exemption():
    from another_s3_manager import users

    assert users.count_users() == 0
    for _ in range(4):
        with pytest.raises(access.AuthenticationError) as error:
            access.authenticate_local("admin", "wrong", {})
        assert error.value.code == "invalid_password"
    assert users.count_users() == 1
    assert users.load_bans() == {}
    user = access.authenticate_local("admin", "admin123", {}).to_user_dict()
    assert user["is_admin"] is True
    assert user["password_set_via"] == "env"


def test_local_ban_and_success_reset(monkeypatch):
    from another_s3_manager import users
    from another_s3_manager.access import service

    users.create_user("alice", access.hash_password("correct"))
    # Fix the clock so the exact remaining-minute message is deterministic.
    monkeypatch.setattr(service.time, "time", lambda: 2000000000)
    for _ in range(2):
        with pytest.raises(access.AuthenticationError):
            access.authenticate_local("alice", "wrong", {})
    access.authenticate_local("alice", "correct", {})
    assert service._login_attempts["alice"]["failed_count"] == 0
    for _ in range(3):
        with pytest.raises(access.AuthenticationError):
            access.authenticate_local("alice", "wrong", {})
    with pytest.raises(access.AuthenticationError) as error:
        access.authenticate_local("alice", "correct", {})
    assert (error.value.code, error.value.message) == ("banned", "Account is banned. Try again in 60 minutes.")
