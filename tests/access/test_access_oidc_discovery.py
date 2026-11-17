import socket

import httpx
import pytest

from another_s3_manager import access
from another_s3_manager.access.oidc.discovery import OidcUnavailable, Outbound, resolve_destination


def test_peer_is_checked_before_request_bytes(monkeypatch):
    from another_s3_manager.access.oidc.discovery import PinnedBackend, PinnedTransport

    class Socket:
        closed = False

        def settimeout(self, value):
            assert 0 < value <= 5

        def connect(self, address):
            assert address == ("93.184.216.34", 443)

        def getpeername(self):
            return ("127.0.0.1", 443)

        def close(self):
            self.closed = True

    sock = Socket()
    monkeypatch.setattr(socket, "socket", lambda *args: sock)
    backend = PinnedBackend("op.example", 443, {"93.184.216.34"})
    with pytest.raises(OidcUnavailable):
        backend.connect_tcp("op.example", 443, timeout=5)
    assert sock.closed
    transport = PinnedTransport("https://op.example/token", {"93.184.216.34"})
    assert transport._pool._ssl_context.check_hostname is True
    import ssl

    assert transport._pool._ssl_context.verify_mode == ssl.CERT_REQUIRED
    assert transport._pool._network_backend.host == "op.example"
    transport.close()


def test_key_snapshot_replacement_expiry_and_single_refresh(monkeypatch):
    import json

    from another_s3_manager.access.oidc.discovery import Discovery, Snapshot

    settings = access.oidc_settings({})
    client = Discovery(settings)
    metadata = {
        "issuer": "",
        "authorization_endpoint": "https://op.example/auth",
        "token_endpoint": "https://op.example/token",
        "jwks_uri": "https://op.example/jwks",
    }
    clock = [10000.0]
    monkeypatch.setattr("another_s3_manager.access.oidc.discovery.time.monotonic", lambda: clock[0])
    monkeypatch.setattr("another_s3_manager.access.oidc.discovery.resolve_destination", lambda *a: {"93.184.216.34"})
    client.snapshot = Snapshot(json.dumps(metadata), json.dumps({"keys": [{"kid": "old"}]}), 10000, 10000)
    monkeypatch.setattr(client.outbound, "json", lambda *a, **kw: {"keys": [{"kid": "new"}]})
    assert client.retry_keys().jwks == {"keys": [{"kid": "new"}]}
    with pytest.raises(OidcUnavailable):
        client.retry_keys()
    clock[0] += 3601

    def fail(*a, **kw):
        raise OidcUnavailable()

    monkeypatch.setattr(client.outbound, "json", fail)
    with pytest.raises(OidcUnavailable):
        client.current()
    clock[0] += 86400
    with pytest.raises(OidcUnavailable):
        client.current()


def test_background_backoff_does_not_block_local_policy(monkeypatch):
    import asyncio

    from another_s3_manager.access.oidc.discovery import Discovery

    client = Discovery(access.oidc_settings({}))
    delays, attempts = [], []

    def refresh():
        attempts.append(1)
        if len(attempts) < 3:
            raise OidcUnavailable()

    async def sleep(delay):
        delays.append(delay)
        if len(delays) == 3:
            raise asyncio.CancelledError()

    monkeypatch.setattr(client, "refresh", refresh)
    monkeypatch.setattr(asyncio, "sleep", sleep)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(client.run())
    assert delays == [5, 10, 3600]
    assert access.oidc_settings({}).local_login == "all"


@pytest.mark.parametrize(
    "address", ["127.0.0.1", "169.254.169.254", "10.0.0.1", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1"]
)
def test_transport_blocks_private_rebinding_redirects_and_origin_spillover(monkeypatch, address):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", (address, 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443)),
        ],
    )
    with pytest.raises(OidcUnavailable):
        resolve_destination("https://op.example/jwks", access.oidc_settings({}))
    monkeypatch.setenv("OIDC_ALLOWED_PRIVATE_ORIGINS", "https://op.example")
    settings = access.oidc_settings({})
    assert len(resolve_destination("https://op.example/jwks", settings)) >= 1
    for url in ("https://adjacent.example", "https://op.example:444"):
        with pytest.raises(OidcUnavailable):
            resolve_destination(url, settings)


def test_stream_size_and_redirects(monkeypatch):
    monkeypatch.setenv("OIDC_ALLOWED_PRIVATE_ORIGINS", "https://127.0.0.1")
    for response in (
        httpx.Response(302, headers={"Location": "https://127.0.0.1/other"}),
        httpx.Response(200, content=b"x" * (1024 * 1024 + 1)),
        httpx.Response(500, content=b"x" * (1024 * 1024 + 1)),
    ):
        outbound = Outbound(access.oidc_settings({}), httpx.MockTransport(lambda request: response))
        with pytest.raises(OidcUnavailable):
            outbound.json("GET", "https://127.0.0.1")


def test_compressed_response_cannot_bypass_stream_cap(monkeypatch):
    import gzip

    monkeypatch.setenv("OIDC_ALLOWED_PRIVATE_ORIGINS", "https://127.0.0.1")
    payload = gzip.compress(b"x" * (1024 * 1024 + 1))
    # ByteStream prevents HTTPX's preloaded-response shortcut from decompressing first.
    response = httpx.Response(200, headers={"Content-Encoding": "gzip"}, stream=httpx.ByteStream(payload))
    outbound = Outbound(access.oidc_settings({}), httpx.MockTransport(lambda request: response))
    with pytest.raises(OidcUnavailable):
        outbound.json("GET", "https://127.0.0.1")


def test_slow_headers_obey_overall_deadline_and_close_connection(monkeypatch):
    from another_s3_manager.access.oidc import discovery

    clock = [0.0]

    class DrippingServerSocket:
        closed = False
        timeout = 5
        # The server sends a header byte every second, faster than the idle timeout.
        chunks = iter([b"HTTP/1.1 200 OK\r\nX-Slow: "] + [b"a"] * 8 + [b"\r\nContent-Length: 2\r\n\r\n{}"])

        def settimeout(self, timeout):
            self.timeout = timeout

        def connect(self, address):
            pass

        def getpeername(self):
            return ("127.0.0.1", 80)

        def send(self, data):
            return len(data)

        def recv(self, size):
            clock[0] += min(1, self.timeout)
            return next(self.chunks)

        def close(self):
            self.closed = True

    sock = DrippingServerSocket()
    monkeypatch.setattr(discovery.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(socket, "socket", lambda *args: sock)
    monkeypatch.setenv("OIDC_ALLOW_INSECURE_HTTP", "true")
    monkeypatch.setenv("OIDC_ALLOWED_PRIVATE_ORIGINS", "http://127.0.0.1")
    with pytest.raises(OidcUnavailable):
        Outbound(access.oidc_settings({})).json("GET", "http://127.0.0.1")
    assert clock[0] <= 5
    assert sock.closed


def test_discovery_lock_is_available_during_network_wait(monkeypatch):
    import threading

    from another_s3_manager.access.oidc.discovery import Discovery

    client = Discovery(access.oidc_settings({}))
    entered, finish = threading.Event(), threading.Event()

    def wait(*args, **kwargs):
        entered.set()
        assert finish.wait(2)
        raise OidcUnavailable()

    monkeypatch.setattr(client.outbound, "json", wait)
    errors = []

    def refresh():
        try:
            client.refresh()
        except OidcUnavailable:
            errors.append("unavailable")

    worker = threading.Thread(target=refresh)
    worker.start()
    try:
        assert entered.wait(2)
        acquired = client.lock.acquire(blocking=False)
        if acquired:
            client.lock.release()
        assert acquired
    finally:
        finish.set()
        worker.join(2)
    assert errors == ["unavailable"]
    assert client.snapshot is None


@pytest.mark.parametrize(
    "metadata_age,keys_age,state",
    [
        (0, 3599.999, "available"),
        (0, 3600, "stale"),
        (0, 3600.001, "stale"),
        (86399.999, 0, "available"),
        (86400, 0, "expired"),
        (86400.001, 0, "expired"),
    ],
)
def test_snapshot_state_shared_by_runtime_and_current(monkeypatch, metadata_age, keys_age, state):
    from another_s3_manager.access.oidc.discovery import Snapshot

    monkeypatch.setenv("OIDC_ISSUER", "https://op.example")
    monkeypatch.setenv("OIDC_CLIENT_ID", "client")
    monkeypatch.setenv("PUBLIC_URL", "https://asm.example")
    monkeypatch.setenv("COOKIE_SECURE", "true")
    client = access.discovery_for(access.oidc_settings({}))
    monkeypatch.setattr("another_s3_manager.access.oidc.discovery.time.monotonic", lambda: 100000.0)
    snapshot = Snapshot("{}", '{"keys": []}', 100000 - metadata_age, 100000 - keys_age)
    client.snapshot = snapshot
    calls = []

    def refresh(*, keys_only=False):
        calls.append(keys_only)
        return snapshot

    monkeypatch.setattr(client, "refresh", refresh)
    assert client.evaluate_snapshot(snapshot) == state
    assert access.oidc_runtime({})["oidc_available"] is (state == "available")
    assert access.oidc_runtime({}, public=True)["oidc_available"] is (state == "available")
    assert calls == []
    if state == "expired":
        # One rate-limited full refresh, then refused until the limiter window passes.
        assert client.current() is snapshot
        assert calls == [False]
        with pytest.raises(OidcUnavailable, match="metadata_unavailable"):
            client.current()
        assert calls == [False]
    else:
        assert client.current() is snapshot
        assert calls == ([True] if state == "stale" else [])


def test_absent_snapshot_attempts_one_rate_limited_full_refresh(monkeypatch):
    from another_s3_manager.access.oidc.discovery import Discovery

    client = Discovery(access.oidc_settings({}))
    clock = [5000.0]
    monkeypatch.setattr("another_s3_manager.access.oidc.discovery.time.monotonic", lambda: clock[0])
    calls = []

    def refresh(*, keys_only=False):
        calls.append(keys_only)
        raise OidcUnavailable("upstream_failure")

    monkeypatch.setattr(client, "refresh", refresh)
    assert client.evaluate_snapshot(None) == "expired"
    with pytest.raises(OidcUnavailable, match="upstream_failure"):
        client.current()
    with pytest.raises(OidcUnavailable, match="metadata_unavailable"):
        client.current()
    assert calls == [False]
    clock[0] += 60
    with pytest.raises(OidcUnavailable, match="upstream_failure"):
        client.current()
    assert calls == [False, False]
    assert access.oidc_runtime({})["oidc_available"] is False


def enable_oidc(monkeypatch, issuer="https://op.example"):
    monkeypatch.setenv("OIDC_ISSUER", issuer)
    monkeypatch.setenv("OIDC_CLIENT_ID", "asm")
    monkeypatch.setenv("PUBLIC_URL", "https://asm.example")
    monkeypatch.setenv("COOKIE_SECURE", "true")


def test_secret_rotation_keeps_the_published_discovery(monkeypatch, tmp_path):
    from another_s3_manager.access.oidc.settings import client_secret

    enable_oidc(monkeypatch)
    secret = tmp_path / "secret"
    secret.write_text("first-secret\n")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "env-secret")
    monkeypatch.setenv("OIDC_CLIENT_SECRET_FILE", str(secret))
    published = access.discovery_for(access.oidc_settings({}))
    assert client_secret() == "first-secret"
    secret.write_text("second-secret\n")
    assert access.discovery_for(access.oidc_settings({})) is published
    assert client_secret() == "second-secret"
    # Identity fields still replace the instance.
    monkeypatch.setenv("OIDC_ISSUER", "https://other.example")
    assert access.discovery_for(access.oidc_settings({})) is not published


def test_background_task_refreshes_the_published_instance(monkeypatch):
    import asyncio

    from another_s3_manager.access.oidc import discovery

    enable_oidc(monkeypatch)
    orphan = discovery.Discovery(access.oidc_settings({}))
    published = access.discovery_for(access.oidc_settings({}))
    refreshed = []
    monkeypatch.setattr(orphan, "refresh", lambda: refreshed.append("orphan"))
    monkeypatch.setattr(published, "refresh", lambda: refreshed.append("published"))

    async def sleep(delay):
        raise asyncio.CancelledError()

    monkeypatch.setattr(asyncio, "sleep", sleep)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(orphan.run())
    assert refreshed == ["published"]


def test_background_task_survives_unexpected_errors_and_logs_only_a_category(monkeypatch, caplog):
    import asyncio

    from another_s3_manager.access.oidc.discovery import Discovery

    client = Discovery(access.oidc_settings({}))
    attempts, delays = [], []

    def refresh():
        attempts.append(1)
        if len(attempts) == 1:
            raise RecursionError("hostile-body-canary")
        if len(attempts) == 2:
            raise httpx.InvalidURL("invalid-url-canary")

    async def sleep(delay):
        delays.append(delay)
        if len(delays) == 3:
            raise asyncio.CancelledError()

    monkeypatch.setattr(client, "refresh", refresh)
    monkeypatch.setattr(asyncio, "sleep", sleep)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(client.run())
    assert delays == [5, 10, 3600]
    assert caplog.text.count("category=refresh_failed reason=unexpected_error") == 2
    assert "canary" not in caplog.text


@pytest.mark.parametrize(
    "failure", [httpx.InvalidURL("invalid-url-canary"), RecursionError("recursion-canary"), KeyError("key-canary")]
)
def test_outbound_maps_any_unexpected_error_to_upstream_failure(monkeypatch, failure):
    monkeypatch.setenv("OIDC_ALLOWED_PRIVATE_ORIGINS", "https://127.0.0.1")

    def handler(request):
        raise failure

    outbound = Outbound(access.oidc_settings({}), httpx.MockTransport(handler))
    with pytest.raises(OidcUnavailable) as raised:
        outbound.json("GET", "https://127.0.0.1")
    assert raised.value.args == ("upstream_failure",)
    assert raised.value.__cause__ is None and raised.value.__suppress_context__


def fake_sockets(monkeypatch, outcomes):
    """Sockets whose connect outcome depends on the address: refuse, timeout or a peer."""
    attempts = []

    class FakeSocket:
        def __init__(self, family, kind):
            self.family, self.timeout, self.closed, self.peer = family, None, False, None

        def settimeout(self, value):
            self.timeout = value

        def connect(self, address):
            attempts.append((self.family, address[0], self.timeout))
            outcome = outcomes.get(address[0], address[0])
            if outcome == "refuse":
                raise ConnectionRefusedError()
            if outcome == "timeout":
                raise socket.timeout()
            self.peer = outcome

        def getpeername(self):
            return (self.peer, 443)

        def setsockopt(self, *args):
            pass

        def close(self):
            self.closed = True

    monkeypatch.setattr(socket, "socket", FakeSocket)
    return attempts


V6, V4 = "2a00:1450:4001:80b::200e", "151.101.1.69"


def test_resolver_order_is_kept_ipv6_first_without_sorting(monkeypatch):
    from tests.oidc.local_http import resolver_for

    from another_s3_manager.access.oidc.discovery import PinnedBackend

    resolver_for(monkeypatch, {"op.example": [V6, V4, V6]})
    addresses = resolve_destination("https://op.example/jwks", access.oidc_settings({}))
    # Resolver order with duplicates dropped; sorting would put the IPv4 answer first.
    assert addresses == (V6, V4)
    attempts = fake_sockets(monkeypatch, {V6: "refuse", V4: "refuse"})
    with pytest.raises(OidcUnavailable, match="upstream_failure"):
        PinnedBackend("op.example", 443, addresses).connect_tcp("op.example", 443, timeout=5)
    assert [(family, address) for family, address, _ in attempts] == [
        (socket.AF_INET6, V6),
        (socket.AF_INET, V4),
    ]


@pytest.mark.parametrize("first", ["refuse", "timeout"])
def test_unreachable_first_address_falls_back_to_the_next(monkeypatch, first):
    from another_s3_manager.access.oidc.discovery import PinnedBackend

    clock = [100.0]
    monkeypatch.setattr("another_s3_manager.access.oidc.discovery.time.monotonic", lambda: clock[0])
    attempts = fake_sockets(monkeypatch, {V6: first})
    stream = PinnedBackend("op.example", 443, (V6, V4), deadline=104.0).connect_tcp("op.example", 443, timeout=5)
    assert [address for _, address, _ in attempts] == [V6, V4]
    # Each attempt gets an equal share of what remains, the last one all of it.
    assert [timeout for _, _, timeout in attempts] == [2.0, 4.0]
    assert stream._sock.peer == V4


def test_fallback_reaches_a_real_server_through_the_outbound_path(monkeypatch):
    from tests.oidc.local_http import resolver_for, serve

    attempts = []
    real_socket = socket.socket

    class Refusing(real_socket):
        def connect(self, address):
            attempts.append(address[0])
            if address[0] == "203.0.113.7":
                raise ConnectionRefusedError()
            return super().connect(address)

    with serve(lambda request: httpx.Response(200, json={"ok": request.url.path})) as port:
        origin = f"http://op.example:{port}"
        monkeypatch.setenv("OIDC_ALLOW_INSECURE_HTTP", "true")
        monkeypatch.setenv("OIDC_ALLOWED_PRIVATE_ORIGINS", origin)
        resolver_for(monkeypatch, {"op.example": ["203.0.113.7", "127.0.0.1"]})
        monkeypatch.setattr(socket, "socket", Refusing)
        assert Outbound(access.oidc_settings({})).json("GET", origin + "/jwks") == {"ok": "/jwks"}
    assert attempts == ["203.0.113.7", "127.0.0.1"]


def test_all_addresses_failing_is_upstream_failure_within_the_deadline(monkeypatch):
    import time

    from tests.oidc.local_http import resolver_for

    resolver_for(monkeypatch, {"op.example": [V6, V4]})
    attempts = fake_sockets(monkeypatch, {V6: "timeout", V4: "refuse"})
    started = time.monotonic()
    with pytest.raises(OidcUnavailable) as raised:
        Outbound(access.oidc_settings({})).json("GET", "https://op.example/jwks")
    assert raised.value.args == ("upstream_failure",)
    assert time.monotonic() - started < 5
    assert [address for _, address, _ in attempts] == [V6, V4]
    assert all(0 < timeout <= 5 for _, _, timeout in attempts)


def test_peer_outside_the_validated_set_fails_closed(monkeypatch):
    from another_s3_manager.access.oidc.discovery import PinnedBackend

    attempts = fake_sockets(monkeypatch, {V6: "10.0.0.9"})
    with pytest.raises(OidcUnavailable, match="peer_changed"):
        PinnedBackend("op.example", 443, (V6, V4)).connect_tcp("op.example", 443, timeout=5)
    # A mismatched peer is not a reachability problem: no further address is tried.
    assert [address for _, address, _ in attempts] == [V6]


def test_plain_http_endpoint_needs_an_allow_listed_origin(monkeypatch):
    from tests.oidc.local_http import resolver_for

    monkeypatch.setenv("OIDC_ALLOW_INSECURE_HTTP", "true")
    with pytest.raises(OidcUnavailable, match="http_origin_not_listed"):
        resolve_destination("http://op.example/token", access.oidc_settings({}))
    monkeypatch.setenv("OIDC_ALLOWED_PRIVATE_ORIGINS", "http://op.example")
    resolver_for(monkeypatch, {"op.example": ["10.0.0.5"]})
    assert resolve_destination("http://op.example/token", access.oidc_settings({})) == ("10.0.0.5",)
    with pytest.raises(OidcUnavailable, match="http_origin_not_listed"):
        resolve_destination("http://op.example:8080/token", access.oidc_settings({}))


def test_each_connect_attempt_gets_at_least_a_second_while_the_budget_allows(monkeypatch):
    from another_s3_manager.access.oidc.discovery import PinnedBackend

    clock = [100.0]
    monkeypatch.setattr("another_s3_manager.access.oidc.discovery.time.monotonic", lambda: clock[0])
    addresses = tuple(f"203.0.113.{n}" for n in range(1, 11))
    attempts = fake_sockets(monkeypatch, {address: "refuse" for address in addresses})
    with pytest.raises(OidcUnavailable, match="upstream_failure"):
        PinnedBackend("op.example", 443, addresses, deadline=104.0).connect_tcp("op.example", 443, timeout=5)
    # An equal share would be 0.4 s; the floor keeps a fair try per address.
    assert attempts[0][2] == 1.0
    # The floor never exceeds what is left of the overall deadline.
    clock[0] = 103.5
    attempts.clear()
    with pytest.raises(OidcUnavailable):
        PinnedBackend("op.example", 443, addresses[:2], deadline=104.0).connect_tcp("op.example", 443, timeout=5)
    assert attempts[0][2] == 0.5
