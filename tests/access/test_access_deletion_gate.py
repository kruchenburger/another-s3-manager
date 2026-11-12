import pytest

from another_s3_manager.access import AccessDenied, require_not_deletion_disabled
from another_s3_manager.access.policies import deletion_disabled


@pytest.mark.parametrize(
    "env,flag,expected",
    [
        (None, False, False),
        (None, True, True),
        ("false", False, False),
        ("false", True, True),
        ("true", False, True),
        ("true", True, True),
        ("TRUE", False, True),
        ("1", False, False),
        (" true ", False, False),
    ],
)
def test_deletion_is_disabled_by_env_or_config(monkeypatch, env, flag, expected):
    if env is None:
        monkeypatch.delenv("DISABLE_DELETION", raising=False)
    else:
        monkeypatch.setenv("DISABLE_DELETION", env)
    config = {"disable_deletion": flag}
    assert deletion_disabled(config) is expected
    if expected:
        with pytest.raises(AccessDenied) as caught:
            require_not_deletion_disabled(config)
        assert caught.value.code == "deletion_disabled"
        assert str(caught.value) == "Deletion is disabled in server config"
    else:
        assert require_not_deletion_disabled(config) is None


def test_legacy_gate_does_not_load_config_when_env_disables_deletion(monkeypatch):
    from another_s3_manager import config

    monkeypatch.setenv("DISABLE_DELETION", "true")

    def unexpected_load():
        pytest.fail("Config must not be loaded after the env short circuit")

    monkeypatch.setattr(config, "load_config", unexpected_load)
    assert config.is_deletion_disabled() is True
