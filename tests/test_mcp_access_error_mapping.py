from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from another_s3_manager import access as service
from another_s3_manager import mcp_server
from another_s3_manager.access import AccessDenied


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


@pytest.mark.parametrize(
    "denial,context,code,message,details,metric",
    [
        (
            "writes_disabled",
            "gate",
            "READ_ONLY_SERVER",
            "Server config disables MCP writes",
            {"tool": "copy_object"},
            "writes_disabled",
        ),
        (
            "read_only_token",
            "gate",
            "READ_ONLY_TOKEN",
            "This token is read-only",
            {"tool": "copy_object"},
            "read_only_token",
        ),
        (
            "deletion_disabled",
            "gate",
            "DELETION_DISABLED",
            "Deletion is disabled in server config",
            {"tool": "copy_object"},
            "deletion_disabled",
        ),
        (
            "DELETION_DISABLED",
            "gate",
            "DELETION_DISABLED",
            "Deletion is disabled in server config",
            {"tool": "copy_object"},
            "deletion_disabled",
        ),
        (
            "DELETION_DISABLED_FOR_ROLE",
            "gate",
            "DELETION_DISABLED_FOR_ROLE",
            "revoked",
            {"tool": "copy_object"},
            "role_deletion_disabled",
        ),
        ("bucket_not_allowed", "delete", "BUCKET_NOT_ALLOWED", "revoked", {}, None),
        ("role_required", "delete", "ROLE_NOT_ALLOWED", "revoked", {}, None),
        ("role_not_allowed", "move", "ROLE_NOT_ALLOWED", "revoked", {}, None),
        ("role_not_found", "move", "ROLE_NOT_ALLOWED", "revoked", {}, None),
        (
            "DELETION_DISABLED",
            "delete",
            "DELETION_DISABLED",
            "Deletion is disabled in server config. 2 object(s) were deleted before the change.",
            {"count": 2},
            "deletion_disabled",
        ),
        (
            "DELETION_DISABLED_FOR_ROLE",
            "delete",
            "DELETION_DISABLED_FOR_ROLE",
            "revoked. 2 object(s) were deleted before the change.",
            {"count": 2},
            "role_deletion_disabled",
        ),
        (
            "DELETION_DISABLED",
            "move",
            "DELETION_DISABLED",
            "Deletion is disabled in server config (delete_source requires it)",
            {"tool": "copy_object"},
            "deletion_disabled",
        ),
        (
            "DELETION_DISABLED_FOR_ROLE",
            "move",
            "DELETION_DISABLED_FOR_ROLE",
            "revoked",
            {"tool": "copy_object"},
            "role_deletion_disabled",
        ),
        ("DELETION_DISABLED", "copied", "DELETION_DISABLED", "Copied, source kept", {}, "deletion_disabled"),
        (
            "DELETION_DISABLED_FOR_ROLE",
            "copied",
            "DELETION_DISABLED_FOR_ROLE",
            "Copied, source kept",
            {},
            "role_deletion_disabled",
        ),
        (
            "bucket_not_allowed",
            "copied",
            "BUCKET_NOT_ALLOWED",
            "Copied, source kept. Access to the bucket is no longer allowed.",
            {},
            None,
        ),
        (
            "role_not_allowed",
            "copied",
            "ROLE_NOT_ALLOWED",
            "Copied, source kept. Access to the role is no longer allowed.",
            {},
            None,
        ),
        (
            "writes_disabled",
            "copied",
            "READ_ONLY_SERVER",
            "Copied, source kept. Server config disables MCP writes",
            {},
            "writes_disabled",
        ),
        (
            "read_only_token",
            "copied",
            "READ_ONLY_TOKEN",
            "Copied, source kept. This token is read-only",
            {},
            "read_only_token",
        ),
    ],
)
def test_access_error_table_preserves_context(monkeypatch, denial, context, code, message, details, metric):
    counter = Mock()
    monkeypatch.setattr(mcp_server, "mcp_writes_denied_total", counter)
    result = mcp_server._access_error(AccessDenied(denial, "revoked", {"count": 2}), "copy_object", context=context)
    assert result.code == code
    assert result.message == message
    assert result.details == details
    if metric:
        counter.labels.assert_called_once_with(tool="copy_object", reason=metric)
        counter.labels.return_value.inc.assert_called_once_with()
    else:
        counter.labels.assert_not_called()
