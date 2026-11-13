import pytest
from hypothesis import given
from hypothesis import strategies as st

from another_s3_manager.access.oidc.mapping import evaluate_mapping


def configured(claim="groups", value="/team/sub", roles=None, admin=False):
    return {
        "roles": [{"name": "read"}],
        "auth": {
            "oidc": {
                "role_mapping": {
                    "rules": [
                        {"claim": claim, "value": value, "roles": ["read"] if roles is None else roles, "admin": admin}
                    ]
                }
            }
        },
    }


@pytest.mark.parametrize(
    "value,allowed",
    [
        ("/team/sub", True),
        (["/team/sub"], True),
        ("sub", False),
        ("/TEAM/sub", False),
        (42, False),
        (["/team/sub", 1], False),
        ({"x": "/team/sub"}, False),
    ],
)
def test_keycloak_full_path_is_literal(value, allowed):
    assert evaluate_mapping({"groups": value}, configured()).eligible is allowed


def test_flat_group_is_literal():
    assert evaluate_mapping({"groups": ["data-team"]}, configured(value="data-team")).roles == ("read",)


@pytest.mark.parametrize("verified", [None, False, "true", 1, True])
def test_hd_requires_boolean_verified_email(verified):
    assert evaluate_mapping(
        {"hd": "example.com", "email_verified": verified}, configured("hd", "example.com")
    ).eligible is (verified is True)


def test_entra_overage_requires_another_effective_rule(caplog):
    claims = {"groups": ["/team/sub"], "_claim_names": {"groups": "source"}}
    assert not evaluate_mapping(claims, configured()).eligible
    assert "overage" in caplog.text
    assert evaluate_mapping({**claims, "roles": "admin"}, configured("roles", "admin", roles=[], admin=True)).admin


def test_dotted_union_and_unknown_roles():
    cfg = configured("realm_access.roles", "admin", roles=["missing"], admin=False)
    assert not evaluate_mapping({"realm_access": {"roles": ["admin"]}}, cfg).eligible
    cfg["auth"]["oidc"]["role_mapping"]["rules"].append({"claim": "groups", "value": "reader", "roles": ["read"]})
    assert evaluate_mapping({"groups": "reader"}, cfg).roles == ("read",)


@given(st.lists(st.text(max_size=25), max_size=15))
def test_mapping_never_grants_unconfigured_role(groups):
    result = evaluate_mapping({"groups": groups}, configured())
    assert set(result.roles) <= {"read"}
    assert result.admin is False
