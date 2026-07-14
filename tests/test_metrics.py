"""Tests for Prometheus metrics endpoint and registry definitions."""

import os
from pathlib import Path

import pytest

from another_s3_manager.mcp_server import McpError, assert_write_allowed


def test_metrics_endpoint_returns_prometheus_text(app_client):
    resp = app_client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    # Should contain at least one of our defined metrics
    assert "as3m_http_requests_total" in body


def test_metrics_endpoint_open_when_password_unset(app_client, monkeypatch):
    monkeypatch.delenv("METRICS_PASSWORD", raising=False)
    resp = app_client.get("/metrics")
    assert resp.status_code == 200


def test_metrics_endpoint_requires_basic_auth_when_password_set(app_client, monkeypatch):
    monkeypatch.setenv("METRICS_PASSWORD", "secret123")
    resp = app_client.get("/metrics")
    assert resp.status_code == 401
    resp_ok = app_client.get("/metrics", auth=("metrics", "secret123"))
    assert resp_ok.status_code == 200
    resp_bad = app_client.get("/metrics", auth=("metrics", "wrong"))
    assert resp_bad.status_code == 401


def test_http_request_counter_uses_path_template_not_concrete_url(app_client):
    """Bounded cardinality: hitting /api/me should label path_template='/api/me' (route pattern)."""
    app_client.get("/api/me")  # any known route
    resp = app_client.get("/metrics")
    body = resp.text
    # Look for a labeled path_template in the metric output
    assert 'path_template="/api/me"' in body or "/api/me" in body


def test_app_info_metric_present(app_client):
    resp = app_client.get("/metrics")
    assert "as3m_app_info" in resp.text


def _seed_user(username: str, password: str) -> None:
    from another_s3_manager.auth import hash_password
    from another_s3_manager.database import session_scope
    from another_s3_manager.models import User

    with session_scope() as session:
        session.add(User(username=username, password_hash=hash_password(password), is_admin=False))


def _sample(name: str, labels: dict) -> float:
    from another_s3_manager.metrics import REGISTRY

    return REGISTRY.get_sample_value(name, labels) or 0.0


def test_auth_login_metrics_count_success_and_failure(app_client):
    """auth_logins_total must increment on both login outcomes (was defined but unwired)."""
    ok_before = _sample("as3m_auth_logins_total", {"result": "success"})
    bad_before = _sample("as3m_auth_logins_total", {"result": "invalid_password"})

    resp = app_client.post("/api/login", data={"username": "admin", "password": "nope"})
    assert resp.status_code == 401
    resp = app_client.post("/api/login", data={"username": "admin", "password": "admin123"})
    assert resp.status_code == 200

    assert _sample("as3m_auth_logins_total", {"result": "success"}) == ok_before + 1
    assert _sample("as3m_auth_logins_total", {"result": "invalid_password"}) == bad_before + 1

    body = app_client.get("/metrics").text
    assert 'as3m_auth_logins_total{result="success"}' in body


def test_auth_banned_login_metric_and_active_bans_gauge(app_client):
    """A login attempt against a banned account counts as result=banned, and
    auth_bans_active reports the live number of active bans at scrape time."""
    banned_before = _sample("as3m_auth_logins_total", {"result": "banned"})

    _seed_user("metrics_bob", "Sup3rSecret1")
    for _ in range(3):
        resp = app_client.post("/api/login", data={"username": "metrics_bob", "password": "wrong"})
        assert resp.status_code == 401

    # 4th attempt hits the banned branch — even with the correct password
    resp = app_client.post("/api/login", data={"username": "metrics_bob", "password": "Sup3rSecret1"})
    assert resp.status_code == 403

    assert _sample("as3m_auth_logins_total", {"result": "banned"}) == banned_before + 1

    body = app_client.get("/metrics").text
    assert "as3m_auth_bans_active 1.0" in body  # fresh per-test DB → exactly one active ban


def test_ban_increments_the_counter(monkeypatch):
    import another_s3_manager.auth as auth
    import another_s3_manager.users as users

    before = _sample("as3m_auth_bans_total", {})

    saved: dict = {}
    monkeypatch.setattr(users, "load_bans", lambda: {})
    monkeypatch.setattr(users, "save_bans", lambda bans: saved.update(bans))

    _seed_user("victim", "pw12345678")  # non-admin, so the ban path is reachable
    for _ in range(3):
        auth.record_login_attempt("victim", success=False)

    assert "victim" in saved
    assert _sample("as3m_auth_bans_total", {}) == before + 1


def test_admin_is_never_banned_and_never_counted(monkeypatch):
    """Admins are exempt by design (DoS protection on the predictable name)."""
    import another_s3_manager.auth as auth
    import another_s3_manager.users as users

    before = _sample("as3m_auth_bans_total", {})
    monkeypatch.setattr(users, "load_bans", lambda: {})
    monkeypatch.setattr(users, "save_bans", lambda bans: None)

    for _ in range(5):
        auth.record_login_attempt("admin", success=False)

    assert _sample("as3m_auth_bans_total", {}) == before


OLD_NAMES = [
    "http_requests_total",
    "http_request_duration_seconds",
    "auth_logins_total",
    "auth_bans_active",
    "s3_operations_total",
    "s3_operation_duration_seconds",
    "s3_bytes_uploaded_total",
    "s3_bytes_downloaded_total",
    "mcp_tool_calls_total",
    "mcp_tool_duration_seconds",
    "mcp_bytes_read_total",
    "mcp_tool_response_bytes",
    "mcp_auth_failures_total",
    "mcp_active_tokens",
    "app_info",
    "app_db_query_duration_seconds",
]


def test_every_app_metric_is_namespaced(app_client):
    """No metric we own may be exported under its old, unprefixed name."""
    body = app_client.get("/metrics").text
    for old in OLD_NAMES:
        # A bare old name at the start of a line is the exposition format's
        # own series/HELP/TYPE prefix. `as3m_<old>` must not trigger this.
        # Histograms emit sample lines with _bucket/_count/_sum suffixes that
        # never match the bare old name, but this test catches failed histogram
        # renames via the # HELP / # TYPE lines, which prometheus_client emits
        # with the bare metric name for every registered family.
        for line in body.splitlines():
            payload = line.removeprefix("# HELP ").removeprefix("# TYPE ")
            assert not payload.startswith(old + " "), f"{old} is still exported unprefixed"
            assert not payload.startswith(old + "{"), f"{old} is still exported unprefixed"


def test_namespaced_names_are_present(app_client):
    body = app_client.get("/metrics").text
    assert "as3m_http_requests_total" in body
    assert "as3m_app_info" in body
    assert "as3m_db_query_duration_seconds" in body


def test_platform_collector_registered(app_client):
    assert "python_info" in app_client.get("/metrics").text


@pytest.mark.skipif(not os.path.exists("/proc"), reason="ProcessCollector only exports on Linux")
def test_process_collector_registered(app_client):
    body = app_client.get("/metrics").text
    assert "process_cpu_seconds_total" in body
    assert "process_resident_memory_bytes" in body


def test_s3_operations_success_is_labelled_none(monkeypatch):
    from another_s3_manager import s3_client as sc

    monkeypatch.setattr(sc, "_execute_with_retry_inner", lambda _role, _cb: "ok")

    labels = {"role": "r1", "operation": "list", "error_code": "none"}
    before = _sample("as3m_s3_operations_total", labels)
    assert sc.execute_with_s3_retry("r1", "list", lambda _client: "ok") == "ok"
    assert _sample("as3m_s3_operations_total", labels) == before + 1


def test_s3_operations_failure_is_labelled_by_cause(monkeypatch):
    from another_s3_manager import s3_client as sc
    from another_s3_manager.errors import S3AccessDeniedError

    def _boom(_role, _callback):
        raise S3AccessDeniedError("AccessDenied", "nope")

    monkeypatch.setattr(sc, "_execute_with_retry_inner", _boom)

    labels = {"role": "r1", "operation": "get", "error_code": "access_denied"}
    before = _sample("as3m_s3_operations_total", labels)
    with pytest.raises(S3AccessDeniedError):
        sc.execute_with_s3_retry("r1", "get", lambda _c: None)
    assert _sample("as3m_s3_operations_total", labels) == before + 1


def test_bytes_counter_has_direction_label():
    from another_s3_manager.metrics import s3_bytes_total

    s3_bytes_total.labels(role="r1", bucket="b1", direction="upload").inc(10)
    s3_bytes_total.labels(role="r1", bucket="b1", direction="download").inc(4)
    assert _sample("as3m_s3_bytes_total", {"role": "r1", "bucket": "b1", "direction": "upload"}) >= 10
    assert _sample("as3m_s3_bytes_total", {"role": "r1", "bucket": "b1", "direction": "download"}) >= 4


def test_old_byte_counters_are_gone():
    from another_s3_manager import metrics

    assert not hasattr(metrics, "s3_bytes_uploaded_total")
    assert not hasattr(metrics, "s3_bytes_downloaded_total")


def test_folder_delete_counts_every_object_not_every_api_call(monkeypatch):
    """Deleting a prefix of N keys must add N, not the number of delete_objects batches."""
    import another_s3_manager.s3_client as sc

    labels = {"role": "r1", "bucket": "b1", "operation": "delete"}
    before = _sample("as3m_s3_objects_total", labels)

    # 2,500 keys => 3 batched delete_objects calls, but 2,500 objects.
    keys = [{"Key": f"folder/{i}"} for i in range(2500)]

    class _FakeClient:
        def get_paginator(self, _name):
            class _P:
                def paginate(self, **_kw):
                    return [{"Contents": keys}]

            return _P()

        def delete_objects(self, **_kw):
            return {}

    monkeypatch.setattr(sc, "_validate_bucket_access", lambda *a, **k: None)
    monkeypatch.setattr(sc, "validate_role_access", lambda role, _u: role)
    monkeypatch.setattr(sc, "execute_with_s3_retry", lambda _r, _op, cb: cb(_FakeClient()))

    result = sc.delete_object_for_role("r1", "b1", "folder/", {"username": "u"})

    assert result["count"] == 2500
    assert _sample("as3m_s3_objects_total", labels) == before + 2500


def test_upload_and_copy_count_one_object_each():
    from another_s3_manager.metrics import s3_objects_total

    for op in ("upload", "copy"):
        labels = {"role": "r1", "bucket": "b1", "operation": op}
        before = _sample("as3m_s3_objects_total", labels)
        s3_objects_total.labels(**labels).inc()
        assert _sample("as3m_s3_objects_total", labels) == before + 1


def test_expired_credentials_retry_is_counted_on_client_acquisition(monkeypatch):
    """Branch A: get_s3_client() raises expired creds, the retry succeeds — counted once."""
    import another_s3_manager.s3_client as sc

    labels = {"reason": "credentials_expired"}
    before = _sample("as3m_s3_retries_total", labels)

    attempts = {"n": 0}

    def _get_client(_role_name):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise RuntimeError("ExpiredToken")
        return object()

    monkeypatch.setattr(sc, "get_s3_client", _get_client)
    monkeypatch.setattr(sc, "_is_expired_credentials_error", lambda _e: True)

    assert sc._execute_with_retry_inner("r1", lambda _client: "ok") == "ok"
    assert attempts["n"] == 2
    assert _sample("as3m_s3_retries_total", labels) == before + 1


def test_expired_credentials_retry_is_counted_on_operation(monkeypatch):
    """Branch B: the client is fine but the S3 OPERATION raises expired creds.

    `_execute_with_retry_inner` has a second retry branch for a mid-operation
    expiry — it clears caches and re-runs the callback. That branch must also
    increment the counter, or credential churn during operations is invisible.
    """
    import another_s3_manager.s3_client as sc

    labels = {"reason": "credentials_expired"}
    before = _sample("as3m_s3_retries_total", labels)

    monkeypatch.setattr(sc, "get_s3_client", lambda _role_name: object())
    monkeypatch.setattr(sc, "_is_expired_credentials_error", lambda _e: True)
    monkeypatch.setattr(sc, "invalidate_s3_client", lambda _role_name: None)
    monkeypatch.setattr(sc, "_clear_boto3_cached_credentials", lambda: None)

    calls = {"n": 0}

    def _callback(_client):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("ExpiredToken")  # operation fails on expired creds
        return "ok"

    assert sc._execute_with_retry_inner("r1", _callback) == "ok"
    assert calls["n"] == 2  # a real retry happened
    assert _sample("as3m_s3_retries_total", labels) == before + 1


def test_sts_and_refresh_counters_exist_and_label_result():
    from another_s3_manager.metrics import credentials_refreshed_total, sts_assume_role_total

    for metric, name in (
        (sts_assume_role_total, "as3m_sts_assume_role_total"),
        (credentials_refreshed_total, "as3m_credentials_refreshed_total"),
    ):
        for result in ("ok", "error"):
            labels = {"role": "r1", "result": result}
            before = _sample(name, labels)
            metric.labels(**labels).inc()
            assert _sample(name, labels) == before + 1


def test_presigned_url_generation_is_counted(monkeypatch):
    import another_s3_manager.s3_client as sc

    labels = {"role": "r1", "bucket": "b1"}
    before = _sample("as3m_presigned_urls_total", labels)
    ttl_before = _sample("as3m_presigned_url_ttl_seconds_count", {})

    monkeypatch.setattr(sc, "_validate_bucket_access", lambda *a, **k: None)
    monkeypatch.setattr(sc, "validate_role_access", lambda role, _u: role)
    monkeypatch.setattr(sc, "execute_with_s3_retry", lambda _r, _op, cb: "https://signed")

    url = sc.generate_presigned_url_for_role("r1", "b1", "k.txt", {"username": "u"}, expires_in=900)

    assert url == "https://signed"
    assert _sample("as3m_presigned_urls_total", labels) == before + 1
    assert _sample("as3m_presigned_url_ttl_seconds_count", {}) == ttl_before + 1


def test_in_flight_gauge_returns_to_zero_after_request(app_client):
    app_client.get("/api/me")
    assert _sample("as3m_http_requests_in_flight", {}) == 0.0


def test_in_flight_gauge_returns_to_zero_after_exception():
    """The middleware's try/finally must decrement the gauge even when
    call_next raises unhandled — no HTTPException, no global handler to
    catch it. Exercises `_http_metrics` directly (call_next is the hook the
    middleware itself receives from Starlette, so faking it here tests real
    production code, not an internal implementation detail) rather than
    routing through the app, since a route registered after the SPA
    catch-all route would be unreachable (see main.py's route-ordering
    invariant) and any route caught internally wouldn't let the exception
    escape call_next at all.
    """
    import asyncio

    from another_s3_manager import main as main_module

    async def _raising_call_next(_request):
        raise RuntimeError("boom")

    before = _sample("as3m_http_requests_in_flight", {})
    with pytest.raises(RuntimeError):
        asyncio.run(main_module._http_metrics(object(), _raising_call_next))
    assert _sample("as3m_http_requests_in_flight", {}) == before


def test_oversize_upload_is_counted_as_size_limit(app_client, monkeypatch):
    """A 413 for exceeding max_file_size must be observable, not an anonymous 4xx.

    The upload body-guard middleware now intercepts oversize declared
    Content-Length before the handler runs (413, was a handler-level 400) --
    it increments the same as3m_upload_rejected_total{reason=size_limit}
    counter the handler used to, so the metric assertion is unchanged.
    """
    from another_s3_manager import config as config_module
    from tests.test_main import login

    login(app_client)
    csrf = app_client.get("/api/me").json()["csrf_token"]

    # resolve_max_file_size() now lives in config.py (main.py just imports
    # it — see the MCP upload-guard review's finding 4), so its internal
    # load_config call resolves in config.py's namespace: patch it there,
    # not on main_module.
    monkeypatch.setattr(config_module, "load_config", lambda force_reload=False: {"max_file_size": 10})
    labels = {"reason": "size_limit"}
    before = _sample("as3m_upload_rejected_total", labels)

    # NOTE: bucket name must satisfy S3's 3-63 char rule (sanitize_bucket_name)
    # or the request 400s on bucket validation before ever reaching the
    # size-limit check, undermining what this test is meant to exercise.
    resp = app_client.post(
        "/api/buckets/bkt1/upload",
        files={"file": ("big.bin", b"x" * 100, "application/octet-stream")},
        data={"key": "big.bin", "role": "r1"},
        headers={"X-CSRF-Token": csrf},
    )

    assert resp.status_code == 413
    assert _sample("as3m_upload_rejected_total", labels) == before + 1


# ---------------------------------------------------------------------------
# MCP guard metrics — writes denied, reads refused (Task 11)
# ---------------------------------------------------------------------------


class _Tok:
    """Minimal stub for assert_write_allowed's token parameter."""

    def __init__(self, read_only=False):
        self.is_read_only = read_only


@pytest.mark.parametrize(
    ("token", "config", "tool", "reason"),
    [
        (_Tok(), {"mcp_disable_writes": True}, "upload_file", "writes_disabled"),
        (_Tok(read_only=True), {}, "upload_file", "read_only_token"),
        (_Tok(), {"disable_deletion": True}, "delete_file", "deletion_disabled"),
    ],
)
def test_denied_write_is_counted_with_its_reason(token, config, tool, reason):
    labels = {"tool": tool, "reason": reason}
    before = _sample("as3m_mcp_writes_denied_total", labels)
    with pytest.raises(McpError):
        assert_write_allowed(token, tool, config)
    assert _sample("as3m_mcp_writes_denied_total", labels) == before + 1


def test_allowed_write_counts_nothing():
    labels = {"tool": "upload_file", "reason": "read_only_token"}
    before = _sample("as3m_mcp_writes_denied_total", labels)
    assert_write_allowed(_Tok(), "upload_file", {})
    assert _sample("as3m_mcp_writes_denied_total", labels) == before


def test_reads_refused_counter_labels():
    from another_s3_manager.metrics import mcp_reads_refused_total

    for reason in ("file_too_large", "binary_content"):
        labels = {"tool": "read_file", "reason": reason}
        before = _sample("as3m_mcp_reads_refused_total", labels)
        mcp_reads_refused_total.labels(**labels).inc()
        assert _sample("as3m_mcp_reads_refused_total", labels) == before + 1


# ---------------------------------------------------------------------------
# MCP token gauge + churn counters (Task 12)
# ---------------------------------------------------------------------------


def test_active_tokens_gauge_reflects_the_database(app_client):
    """Regression: the gauge was defined, documented, exported — and always 0."""
    from another_s3_manager.api_tokens import create_token, revoke_token

    _seed_user("gaugeuser", "pw12345678")
    from another_s3_manager.database import session_scope
    from another_s3_manager.models import User

    with session_scope() as s:
        uid = s.query(User).filter_by(username="gaugeuser").one().id

    app_client.get("/metrics")  # a scrape is what triggers set_function
    baseline = _sample("as3m_mcp_active_tokens", {})

    token, _ = create_token(user_id=uid, name="t1", is_read_only=True, max_read_bytes=1024)
    app_client.get("/metrics")
    assert _sample("as3m_mcp_active_tokens", {}) == baseline + 1

    revoke_token(token.id, by_user_id=uid, by_is_admin=False)
    app_client.get("/metrics")
    assert _sample("as3m_mcp_active_tokens", {}) == baseline


def test_token_issue_and_revoke_counters(app_client):
    from another_s3_manager.api_tokens import create_token, revoke_token
    from another_s3_manager.database import session_scope
    from another_s3_manager.models import User

    _seed_user("churnuser", "pw12345678")
    with session_scope() as s:
        uid = s.query(User).filter_by(username="churnuser").one().id

    issued = _sample("as3m_mcp_tokens_issued_total", {})
    revoked = _sample("as3m_mcp_tokens_revoked_total", {})

    token, _ = create_token(user_id=uid, name="t2", is_read_only=False, max_read_bytes=1024)
    assert _sample("as3m_mcp_tokens_issued_total", {}) == issued + 1

    revoke_token(token.id, by_user_id=uid, by_is_admin=False)
    assert _sample("as3m_mcp_tokens_revoked_total", {}) == revoked + 1

    # Revoking twice must not double-count: the second call is a no-op.
    revoke_token(token.id, by_user_id=uid, by_is_admin=False)
    assert _sample("as3m_mcp_tokens_revoked_total", {}) == revoked + 1


# ---------------------------------------------------------------------------
# Users/roles gauges + DB error counter (Task 13)
# ---------------------------------------------------------------------------


def test_users_and_roles_gauges(app_client, monkeypatch):
    _seed_user("gaugecount", "pw12345678")
    app_client.get("/metrics")
    assert _sample("as3m_users", {}) >= 1

    from another_s3_manager import main as main_module

    monkeypatch.setattr(
        main_module, "load_config", lambda force_reload=False: {"roles": [{"name": "a"}, {"name": "b"}]}
    )
    app_client.get("/metrics")
    assert _sample("as3m_roles", {}) == 2.0


def test_db_error_is_counted():
    """A failing statement is still classified by its verb: a bad SELECT is a SELECT."""
    from sqlalchemy import text
    from sqlalchemy.exc import SQLAlchemyError

    from another_s3_manager.database import session_scope

    labels = {"operation": "SELECT"}
    before = _sample("as3m_db_errors_total", labels)

    with pytest.raises(SQLAlchemyError):
        with session_scope() as s:
            s.execute(text("SELECT * FROM table_that_does_not_exist"))

    assert _sample("as3m_db_errors_total", labels) == before + 1


# ---------------------------------------------------------------------------
# Structural guard: every declared metric must be used (Task 14)
# ---------------------------------------------------------------------------

_ALLOWED_WITHOUT_CALL_SITE = {
    # Populated by prometheus_client itself at definition time.
    "app_info",
}


def test_no_dead_metrics():
    """Every declared metric must be referenced somewhere in src/, or be allowlisted.

    Regression guard: `mcp_active_tokens` shipped in v1.0.0 defined, documented
    and exported — and never once written to. It always read 0.
    """
    from prometheus_client.metrics import MetricWrapperBase

    import another_s3_manager.metrics as metrics_module

    src = Path(metrics_module.__file__).parent
    other_sources = "\n".join(p.read_text(encoding="utf-8") for p in src.rglob("*.py") if p.name != "metrics.py")

    declared = {
        name
        for name, obj in vars(metrics_module).items()
        if isinstance(obj, MetricWrapperBase) and not name.startswith("_")
    }
    assert declared, "sanity: no metrics discovered"

    dead = sorted(name for name in declared if name not in _ALLOWED_WITHOUT_CALL_SITE and name not in other_sources)
    assert not dead, f"Declared but never used: {dead}"


# ---------------------------------------------------------------------------
# Zero-series seeding for exact dashboard Totals (Task 15)
# ---------------------------------------------------------------------------


def test_seed_zero_series_pre_creates_fixed_enum_series(monkeypatch):
    """`_seed_zero_series()` must materialize every fixed-enum label combo at 0
    BEFORE any real `.inc()` happens.

    Why this matters: a labeled Counter only creates its per-label-combination
    series on the first `.inc()` -- it is born non-zero, with no earlier `0`
    sample. `increase()`/`rate()` need two samples to compute a delta, so the
    very first real increment of a brand-new series is invisible to Grafana.
    Pre-creating the series at 0 via `.labels(...)` (without incrementing)
    fixes this.

    This test swaps in throwaway Counter objects bound to a private registry
    (via monkeypatch, auto-restored after the test) for the specific series it
    asserts on. `metrics.REGISTRY` is a process-wide singleton that many other
    test files' logins/uploads/etc. increment over the course of a full suite
    run (e.g. test_main.py already drives a real login and a real oversize
    upload before this file even runs) -- asserting `== 0.0` against that
    shared, already-dirtied registry would be order-dependent and flaky.
    `_seed_zero_series()` itself is defined in `metrics.py`, so it resolves
    `upload_rejected_total` etc. via that module's own globals at call time --
    monkeypatching the module attribute is enough to redirect it to the
    scratch objects below.
    """
    from prometheus_client import CollectorRegistry, Counter

    from another_s3_manager import metrics

    scratch = CollectorRegistry()
    fresh_upload_rejected = Counter("as3m_upload_rejected_total", "t", ["reason"], registry=scratch)
    fresh_auth_logins = Counter("as3m_auth_logins_total", "t", ["result"], registry=scratch)
    fresh_db_errors = Counter("as3m_db_errors_total", "t", ["operation"], registry=scratch)
    fresh_s3_retries = Counter("as3m_s3_retries_total", "t", ["reason"], registry=scratch)
    fresh_mcp_tool_calls = Counter("as3m_mcp_tool_calls_total", "t", ["tool", "error_code"], registry=scratch)

    monkeypatch.setattr(metrics, "upload_rejected_total", fresh_upload_rejected)
    monkeypatch.setattr(metrics, "auth_logins_total", fresh_auth_logins)
    monkeypatch.setattr(metrics, "db_errors_total", fresh_db_errors)
    monkeypatch.setattr(metrics, "s3_retries_total", fresh_s3_retries)
    monkeypatch.setattr(metrics, "mcp_tool_calls_total", fresh_mcp_tool_calls)

    # RED proof: nothing has touched the scratch registry yet -- every sample
    # is None, not 0.0. (Confirmed failing pre-implementation: AttributeError,
    # `_seed_zero_series` didn't exist; after adding it as a no-op it still
    # failed here because these samples were still None.)
    assert scratch.get_sample_value("as3m_upload_rejected_total", {"reason": "size_limit"}) is None
    assert scratch.get_sample_value("as3m_auth_logins_total", {"result": "success"}) is None
    assert scratch.get_sample_value("as3m_db_errors_total", {"operation": "SELECT"}) is None
    assert scratch.get_sample_value("as3m_s3_retries_total", {"reason": "credentials_expired"}) is None
    assert scratch.get_sample_value("as3m_mcp_tool_calls_total", {"tool": "list_roles", "error_code": "none"}) is None

    metrics._seed_zero_series()

    assert scratch.get_sample_value("as3m_upload_rejected_total", {"reason": "size_limit"}) == 0.0
    assert scratch.get_sample_value("as3m_auth_logins_total", {"result": "success"}) == 0.0
    assert scratch.get_sample_value("as3m_auth_logins_total", {"result": "invalid_password"}) == 0.0
    assert scratch.get_sample_value("as3m_auth_logins_total", {"result": "banned"}) == 0.0
    assert scratch.get_sample_value("as3m_db_errors_total", {"operation": "SELECT"}) == 0.0
    assert scratch.get_sample_value("as3m_db_errors_total", {"operation": "OTHER"}) == 0.0
    assert scratch.get_sample_value("as3m_s3_retries_total", {"reason": "credentials_expired"}) == 0.0
    assert scratch.get_sample_value("as3m_mcp_tool_calls_total", {"tool": "list_roles", "error_code": "none"}) == 0.0
    assert (
        scratch.get_sample_value(
            "as3m_mcp_tool_calls_total", {"tool": "presigned_url", "error_code": "S3_ACCESS_DENIED"}
        )
        == 0.0
    )


def test_seed_zero_series_does_not_seed_dynamic_role_or_bucket_labels():
    """role/bucket come from admin-editable config or arbitrary bucket names --
    they cannot be enumerated at import time, so counters carrying them
    (s3_bytes_total, s3_objects_total, presigned_urls_total, and also
    s3_operations_total/sts_assume_role_total/credentials_refreshed_total,
    which carry `role` alongside their otherwise-fixed enums) must NOT have a
    guessed value pre-created. Runs against the real, shared REGISTRY: an
    arbitrary made-up label value is guaranteed to be untouched by any other
    test, so no monkeypatch/scratch registry is needed here.
    """
    from another_s3_manager.metrics import REGISTRY, _seed_zero_series

    _seed_zero_series()

    assert (
        REGISTRY.get_sample_value(
            "as3m_s3_bytes_total",
            {"role": "zzz-unused-role-15", "bucket": "zzz-unused-bucket-15", "direction": "upload"},
        )
        is None
    )
    assert (
        REGISTRY.get_sample_value(
            "as3m_s3_operations_total",
            {"role": "zzz-unused-role-15", "operation": "list", "error_code": "none"},
        )
        is None
    )
    assert (
        REGISTRY.get_sample_value(
            "as3m_sts_assume_role_total",
            {"role": "zzz-unused-role-15", "result": "ok"},
        )
        is None
    )


def test_seed_zero_series_covers_mcp_guard_counters():
    """Sanity coverage for the remaining MCP guard counters _seed_zero_series
    seeds (mcp_auth_failures_total, mcp_writes_denied_total,
    mcp_reads_refused_total). Uses `is not None` rather than `== 0.0` because
    these are asserted against the real, shared REGISTRY, which other test
    files may have already incremented by the time this test runs -- the
    point here is proving the series exists (was pre-created), not its exact
    value; the exact-0.0 behavior is already proven in isolation above.
    """
    from another_s3_manager.metrics import REGISTRY, _seed_zero_series

    _seed_zero_series()

    assert REGISTRY.get_sample_value("as3m_mcp_auth_failures_total", {"reason": "malformed"}) is not None
    assert REGISTRY.get_sample_value("as3m_mcp_auth_failures_total", {"reason": "invalid_token"}) is not None
    assert (
        REGISTRY.get_sample_value(
            "as3m_mcp_writes_denied_total", {"tool": "delete_file", "reason": "deletion_disabled"}
        )
        is not None
    )
    assert (
        REGISTRY.get_sample_value("as3m_mcp_reads_refused_total", {"tool": "read_file", "reason": "file_too_large"})
        is not None
    )
