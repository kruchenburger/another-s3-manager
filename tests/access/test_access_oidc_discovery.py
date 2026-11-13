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
            assert value == 5

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
