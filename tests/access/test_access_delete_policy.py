import pytest

from another_s3_manager.access import AccessDenied, policies, service


@pytest.mark.parametrize("env", [False, True])
@pytest.mark.parametrize("global_flag", [False, True])
@pytest.mark.parametrize("role_flag", [None, True, False])
@pytest.mark.parametrize("admin", [False, True])
def test_delete_permission_matrix(monkeypatch, env, global_flag, role_flag, admin):
    monkeypatch.setenv("DISABLE_DELETION", str(env).lower())
    role = {"name": "storage"}
    if role_flag is not None:
        role["allow_delete"] = role_flag
    config = {"disable_deletion": global_flag, "roles": [role]}
    user = {"is_admin": admin, "allowed_roles": ["storage"]}
    assert service.allowed_roles(user, config) == ["storage"]
    expected = not env and not global_flag and role_flag is not False
    assert policies.deletion_allowed(config, "storage") is expected
    if expected:
        assert service.require_delete("storage", config) is None
    else:
        with pytest.raises(AccessDenied) as caught:
            service.require_delete("storage", config)
        assert caught.value.code == ("DELETION_DISABLED" if env or global_flag else "DELETION_DISABLED_FOR_ROLE")
        if not env and not global_flag:
            assert str(caught.value) == "Deleting is turned off for role 'storage'"


@pytest.mark.parametrize("value", ["false", "true", 0, 1, None, [], {}])
def test_non_boolean_delete_permission_fails_closed(monkeypatch, value):
    monkeypatch.delenv("DISABLE_DELETION", raising=False)
    config = {"roles": [{"name": "storage", "allow_delete": value}]}
    assert policies.deletion_allowed(config, "storage") is False
    with pytest.raises(AccessDenied) as caught:
        service.require_delete("storage", config)
    assert caught.value.code == "DELETION_DISABLED_FOR_ROLE"


@pytest.mark.parametrize("roles", [[], [{"name": "renamed"}]])
def test_missing_named_role_denies_delete_but_none_checks_only_instance(monkeypatch, roles):
    monkeypatch.delenv("DISABLE_DELETION", raising=False)
    config = {"roles": roles}
    assert policies.deletion_allowed(config, "missing") is False
    with pytest.raises(AccessDenied) as caught:
        service.require_delete("missing", config)
    assert caught.value.code == "DELETION_DISABLED_FOR_ROLE"
    assert policies.deletion_allowed(config, None) is True
    assert service.require_delete(None, config) is None
    config["disable_deletion"] = True
    assert policies.deletion_allowed(config, None) is False
