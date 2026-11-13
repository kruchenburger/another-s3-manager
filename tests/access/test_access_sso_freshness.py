from datetime import UTC, datetime, timedelta

import pytest
from tests.test_oidc_login_integration import begin

from another_s3_manager import access


@pytest.mark.parametrize("event", ["pat", "local", "config", "enable", "request", "bad_token", "mapping_denied"])
def test_only_successful_sso_renews_exact_seven_day_deadline(oidc, event):
    import asyncio

    from another_s3_manager import config
    from another_s3_manager.access import tokens, users

    query, cookies = begin(oidc)
    result = asyncio.run(access.complete_oidc_login(query, cookies))
    before = users.get_user_by_username("reader")
    now = datetime.now(UTC).replace(tzinfo=None)
    assert timedelta(days=7) - timedelta(seconds=2) < before["sso_authz_valid_until"] - now <= timedelta(days=7)
    if event == "pat":
        _, pat = tokens.create_token(before["id"], "test", True, 1024)
        access.authenticate_bearer("Bearer " + pat, config.load_config)
    elif event == "local":
        with pytest.raises(access.AuthenticationError):
            access.authenticate_local("reader", "!", config.load_config())
    elif event == "config":
        config.save_config(config.load_config())
    elif event == "enable":
        users.update_user("reader", is_disabled=True)
        access.recover_local_account("reader", enable=True)
    elif event == "request":
        access.authenticate_session(result.session)
    elif event == "bad_token":
        oidc.token_changes = {"nonce": "wrong"}
        q, c = begin(oidc)
        assert asyncio.run(access.complete_oidc_login(q, c)).session is None
    elif event == "mapping_denied":
        cfg = config.load_config()
        cfg["auth"]["oidc"]["role_mapping"]["rules"] = []
        config.save_config(cfg)
        q, c = begin(oidc)
        assert asyncio.run(access.complete_oidc_login(q, c)).session is None
    after = users.get_user_by_username("reader")
    if event == "mapping_denied":
        assert after["sso_authz_valid_until"] < before["sso_authz_valid_until"]
    else:
        assert after["sso_authz_valid_until"] == before["sso_authz_valid_until"]


@pytest.mark.parametrize(
    "mode,deadline,denied",
    [
        ("sync", None, True),
        ("sync", -1, True),
        ("sync", 0, True),
        ("sync", 60, False),
        ("initial", None, False),
        ("initial", -1, False),
    ],
)
def test_deadline_before_equal_after_session_pat_and_download(mode, deadline, denied, app_client):
    user = {
        "id": 123,
        "username": "reader",
        "auth_generation": "generation",
        "auth_source": "oidc",
        "mapping_mode_applied": mode,
        "sso_authz_valid_until": None if deadline is None else datetime.now(UTC) + timedelta(seconds=deadline),
    }
    if denied:
        with pytest.raises(access.AuthenticationError) as error:
            access.principal_for(123, _snapshot=user)
        assert error.value.code == "SSO_AUTHZ_EXPIRED"
    else:
        assert access.principal_for(123, _snapshot=user).username == "reader"
    from another_s3_manager import config
    from another_s3_manager.access import tokens, users
    from another_s3_manager.database import session_scope
    from another_s3_manager.models import User

    row = users.create_user("reader", "!", allowed_roles=["Default"])
    with session_scope() as session:
        stored = session.get(User, row["id"])
        stored.auth_source = "oidc"
        stored.mapping_mode_applied = mode
        stored.sso_authz_valid_until = user["sso_authz_valid_until"]
    row = users.get_user_by_id(row["id"])
    session_token = access.issue_session(access.Principal(row), method="oidc", lifetime_minutes=5)
    _, pat = tokens.create_token(row["id"], "freshness", True, 1024)
    for authenticate in (
        lambda: access.authenticate_session(session_token),
        lambda: access.authenticate_bearer("Bearer " + pat, config.load_config),
    ):
        if denied:
            with pytest.raises(access.AuthenticationError) as error:
                authenticate()
            assert error.value.code == "SSO_AUTHZ_EXPIRED"
        else:
            authenticate()
    if denied:
        response = app_client.get(
            "/api/buckets/test/download", params={"role": "Default", "path": "file", "token": session_token}
        )
        assert response.status_code == 401


@pytest.mark.parametrize(
    "applied,current", [("sync", "initial"), ("initial", "sync"), ("sync", "sync"), ("initial", "initial")]
)
@pytest.mark.parametrize("event", ["config", "success", "denied", "disabled"])
def test_mode_switch_transition_table(applied, current, event):
    from another_s3_manager import config
    from another_s3_manager.access import users
    from another_s3_manager.access.oidc.identities import commit_login, insert_identity
    from another_s3_manager.models import User

    user = users.create_user("subject", "!", allowed_roles=["Default"], is_admin=True)
    old_deadline = datetime.now(UTC) + timedelta(days=1) if applied == "sync" else None
    with users.write_scope() as session:
        row = session.get(User, user["id"])
        row.auth_source = "oidc"
        row.mapping_mode_applied = applied
        row.sso_authz_valid_until = old_deadline
        row.is_disabled = event == "disabled"
        insert_identity(session, user_id=row.id, issuer="https://op.example", subject="subject")
    before = users.get_user_by_id(user["id"])
    cfg = config.load_config()
    cfg["auth"] = {
        "oidc": {
            "role_mapping": {
                "mode": current,
                "rules": [] if event == "denied" else [{"claim": "groups", "value": "team", "roles": ["Default"]}],
            }
        }
    }
    config.save_config(cfg)
    assert users.get_user_by_id(user["id"])["mapping_mode_applied"] == applied
    if event == "config":
        assert users.get_user_by_id(user["id"])["session_epoch"] == before["session_epoch"]
        return
    now = datetime.now(UTC)
    token, error, _ = commit_login(
        {"iss": "https://op.example", "sub": "subject", "groups": ["team"]},
        cfg,
        access.oidc_settings(cfg),
        before,
        now=now,
    )
    after = users.get_user_by_id(user["id"])
    if event == "disabled":
        assert token is None and error == "disabled"
        assert after == before
    elif event == "denied":
        assert token is None and error == "no_access"
        assert after["mapping_mode_applied"] == applied
        assert after["session_epoch"] == before["session_epoch"] + 1
        assert after["allowed_roles"] == ([] if current == "sync" else ["Default"])
        assert after["is_admin"] is (current == "initial")
        assert after["default_role"] == (None if current == "sync" else "Default")
    else:
        assert token and error is None
        assert after["mapping_mode_applied"] == current
        assert after["is_admin"] is (current == "initial")
        assert after["sso_authz_valid_until"] == (
            None if current == "initial" else (now + timedelta(days=7)).replace(tzinfo=None)
        )
