from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from another_s3_manager import mcp_server
from another_s3_manager.access import AccessDenied, service


@pytest.mark.parametrize(
    "reason,code,message",
    [
        ("writes_disabled", "READ_ONLY_SERVER", "Server config disables MCP writes"),
        ("read_only_token", "READ_ONLY_TOKEN", "This token is read-only"),
        ("deletion_disabled", "DELETION_DISABLED", "Deletion is disabled in server config"),
    ],
)
def test_mcp_maps_write_denials_and_counts_exact_metric_reason(monkeypatch, reason, code, message):
    policy = Mock(side_effect=AccessDenied(reason, message, {"tool": "delete_file"}))
    monkeypatch.setattr(service, "require_write", policy)
    counter = Mock()
    monkeypatch.setattr(mcp_server, "mcp_writes_denied_total", counter)
    config = {}
    with pytest.raises(mcp_server.McpError) as caught:
        mcp_server.assert_write_allowed(SimpleNamespace(is_read_only=False), "delete_file", config)
    policy.assert_called_once_with(False, "delete_file", config)
    assert caught.value.code == code
    assert caught.value.message == message
    assert caught.value.details == {"tool": "delete_file"}
    counter.labels.assert_called_once_with(tool="delete_file", reason=reason)
    counter.labels.return_value.inc.assert_called_once_with()


def test_mcp_permitted_write_does_not_increment_denials(monkeypatch):
    policy = Mock(return_value=None)
    monkeypatch.setattr(service, "require_write", policy)
    counter = Mock()
    monkeypatch.setattr(mcp_server, "mcp_writes_denied_total", counter)
    mcp_server.assert_write_allowed(SimpleNamespace(is_read_only=False), "upload_file", {})
    policy.assert_called_once_with(False, "upload_file", {})
    counter.labels.assert_not_called()


def test_mcp_delete_calls_access_policy(monkeypatch):
    guard = Mock(side_effect=AccessDenied("DELETION_DISABLED_FOR_ROLE", "Deleting is turned off for role 'r'"))
    counter = Mock()
    monkeypatch.setattr(service, "require_delete", guard)
    monkeypatch.setattr(mcp_server, "mcp_writes_denied_total", counter)
    with pytest.raises(mcp_server.McpError) as caught:
        mcp_server.assert_write_allowed(SimpleNamespace(is_read_only=False), "delete_file", {}, "r")
    guard.assert_called_once_with("r", {})
    assert caught.value.code == "DELETION_DISABLED_FOR_ROLE"
    assert caught.value.message == "Deleting is turned off for role 'r'"
    counter.labels.assert_called_once_with(tool="delete_file", reason="role_deletion_disabled")
