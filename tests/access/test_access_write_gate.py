import pytest

from another_s3_manager.access import AccessDenied, require_write
from another_s3_manager.access.policies import write_denial


@pytest.mark.parametrize(
    "disabled,readonly,deletion,tool,reason,message",
    [
        (True, True, True, "delete_file", "writes_disabled", "Server config disables MCP writes"),
        (True, False, False, "upload_file", "writes_disabled", "Server config disables MCP writes"),
        (False, True, True, "delete_file", "read_only_token", "This token is read-only"),
        (False, False, True, "delete_file", "deletion_disabled", "Deletion is disabled in server config"),
        (False, False, True, "copy_object", None, None),
        (False, False, True, "upload_file", None, None),
        (False, False, False, "delete_file", None, None),
    ],
)
def test_write_gates_keep_server_token_deletion_priority(
    monkeypatch, disabled, readonly, deletion, tool, reason, message
):
    monkeypatch.delenv("DISABLE_DELETION", raising=False)
    config = {"mcp_disable_writes": disabled, "disable_deletion": deletion}
    assert write_denial(readonly, tool, config) == reason
    if reason is None:
        assert require_write(readonly, tool, config) is None
    else:
        with pytest.raises(AccessDenied) as caught:
            require_write(readonly, tool, config)
        assert caught.value.code == reason
        assert str(caught.value) == message
        assert caught.value.details == {"tool": tool}
