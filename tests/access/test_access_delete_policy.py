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
