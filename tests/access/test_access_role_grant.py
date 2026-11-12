import pytest

from another_s3_manager.access import AccessDenied, require_role
from another_s3_manager.access.policies import effective_allowed_roles


@pytest.mark.parametrize("stored,expected", [([], []), (["gone"], []), (["b", "a", "b", "gone"], ["b", "a", "b"])])
def test_grants_keep_only_configured_roles_in_stored_order(stored, expected):
    assert effective_allowed_roles(stored, {"a", "b"}) == expected


def test_legacy_grant_helper_is_the_same_object():
    from another_s3_manager import users

    assert users.effective_allowed_roles is effective_allowed_roles


@pytest.mark.parametrize("role", [None, "", "  "])
def test_empty_role_is_denied_even_for_admin(role):
    with pytest.raises(AccessDenied) as caught:
        require_role(role, {"is_admin": True}, {})
    assert caught.value.code == "role_required"
    assert str(caught.value) == "A role is required for this request."
    assert isinstance(caught.value, PermissionError)


def test_role_grant_is_filtered_by_current_config():
    with pytest.raises(AccessDenied) as caught:
        require_role("gone", {"allowed_roles": ["gone"]}, {"roles": [{"name": "a"}]})
    assert caught.value.code == "role_not_allowed"
    assert str(caught.value) == "Access denied: You don't have permission to use role 'gone'"
    assert caught.value.message == str(caught.value)


def test_granted_role_is_returned_without_normalizing():
    assert require_role(" a ", {"allowed_roles": [" a "]}, {"roles": [{"name": " a "}]}) == " a "


def test_denial_details_are_not_shared():
    first = AccessDenied("a", "message")
    second = AccessDenied("b", "other")
    first.details["role"] = "a"
    assert second.details == {}
