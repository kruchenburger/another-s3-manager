"""Bounded OIDC outbound transport and immutable discovery/key snapshots."""

import asyncio
import ipaddress
import json
import logging
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from contextvars import ContextVar
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpcore
import httpx
from httpcore._backends.sync import SyncStream

from .settings import origin

logger = logging.getLogger(__name__)
MAX_RESPONSE_BYTES = 1024 * 1024
_dns_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="oidc-dns")
_dns_slots = threading.BoundedSemaphore(4)
_request_deadline = ContextVar("oidc_request_deadline", default=None)


def remaining(deadline, timeout=None):
    budget = deadline - time.monotonic()
    if budget <= 0:
        raise OidcUnavailable("request_timeout")
    return min(budget, timeout) if timeout is not None else budget


def resolve_dns(host, port, deadline):
    # A timed-out system resolver keeps its slot until it actually exits; callers
    # cannot accumulate an unbounded queue behind stuck resolver threads.
    if not _dns_slots.acquire(timeout=remaining(deadline)):
        raise OidcUnavailable("resolver_busy")
    try:
        future = _dns_pool.submit(socket.getaddrinfo, host, port, type=socket.SOCK_STREAM)
    except RuntimeError:
        _dns_slots.release()
        raise OidcUnavailable("resolver_unavailable") from None
    future.add_done_callback(lambda _: _dns_slots.release())
    try:
        return future.result(timeout=remaining(deadline))
    except FutureTimeout:
        raise OidcUnavailable("resolver_timeout") from None


class OidcUnavailable(Exception):
    """Sanitized upstream failure; never carries response bodies or credentials."""


def normalized_ip(value):
    address = ipaddress.ip_address(value.split("%", 1)[0])
    return address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address


def resolve_destination(url, settings):
    deadline = _request_deadline.get()
    deadline = deadline if deadline is not None else time.monotonic() + 5
    identity = origin(url, allow_http=settings.allow_http)
    parsed = urlsplit(url)
    try:
        addresses = {str(normalized_ip(parsed.hostname))}
    except ValueError:
        addresses = {
            str(normalized_ip(row[4][0]))
            for row in resolve_dns(
                parsed.hostname, parsed.port or (443 if parsed.scheme.lower() == "https" else 80), deadline
            )
        }
    if not addresses or (
        identity not in settings.private_origins and any(not normalized_ip(ip).is_global for ip in addresses)
    ):
        raise OidcUnavailable("destination_denied")
    return frozenset(addresses)


class DeadlineStream(SyncStream):
    """Enforce the same deadline on every header/body read and partial write."""

    def __init__(self, sock, deadline):
        super().__init__(sock)
        self.deadline = deadline

    def read(self, max_bytes, timeout=None):
        try:
            data = super().read(max_bytes, timeout=remaining(self.deadline, timeout))
            remaining(self.deadline)
            return data
        except BaseException:
            self.close()
            raise

    def write(self, buffer, timeout=None):
        try:
            while buffer:
                self._sock.settimeout(remaining(self.deadline, timeout))
                sent = self._sock.send(buffer)
                if not sent:
                    raise OidcUnavailable("connection_closed")
                buffer = buffer[sent:]
            remaining(self.deadline)
        except BaseException:
            self.close()
            raise

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        stream = None
        try:
            stream = super().start_tls(ssl_context, server_hostname, remaining(self.deadline, timeout))
            remaining(self.deadline)
            return DeadlineStream(stream.get_extra_info("socket"), self.deadline)
        except BaseException:
            (stream or self).close()
            raise


class PinnedBackend(httpcore.NetworkBackend):
    def __init__(self, host, port, addresses, deadline=None):
        self.host, self.port, self.addresses = host, port, addresses
        self.deadline = deadline

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if host != self.host or port != self.port:
            raise OidcUnavailable("origin_changed")
        address = sorted(self.addresses)[0]
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        deadline = self.deadline if self.deadline is not None else time.monotonic() + 5
        try:
            sock.settimeout(remaining(deadline, timeout))
            # Numeric socket.connect never performs a second DNS lookup.
            sock.connect((address, port))
            if str(normalized_ip(sock.getpeername()[0])) != address:
                raise OidcUnavailable("peer_changed")
            for option in socket_options or ():
                sock.setsockopt(*option)
            remaining(deadline)
            return DeadlineStream(sock, deadline)
        except BaseException:
            sock.close()
            raise


class PinnedTransport(httpx.HTTPTransport):
    def __init__(self, url, addresses, deadline=None):
        parsed = urlsplit(url)
        # HTTPX adapter uses this pool; HTTP core retains the URL hostname for TLS/SNI.
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl.create_default_context(),
            max_connections=1,
            max_keepalive_connections=0,
            retries=0,
            network_backend=PinnedBackend(
                parsed.hostname, parsed.port or (443 if parsed.scheme.lower() == "https" else 80), addresses, deadline
            ),
        )


class Outbound:
    def __init__(self, settings, transport=None):
        self.settings, self.transport = settings, transport

    def json(self, method, url, **kwargs):
        deadline = time.monotonic() + 5
        token = _request_deadline.set(deadline)
        try:
            addresses = resolve_destination(url, self.settings)
            transport = self.transport or PinnedTransport(url, addresses, deadline)
            with httpx.Client(
                transport=transport,
                timeout=remaining(deadline),
                follow_redirects=False,
                trust_env=False,
                headers={"Accept-Encoding": "identity"},
            ) as client:
                with client.stream(method, url, **kwargs) as response:
                    remaining(deadline)
                    if response.headers.get("content-encoding", "identity").lower() != "identity":
                        raise OidcUnavailable("compressed_response")
                    data = bytearray()
                    for chunk in response.iter_bytes():
                        remaining(deadline)
                        if len(data) + len(chunk) > MAX_RESPONSE_BYTES:
                            raise OidcUnavailable("response_limit")
                        data.extend(chunk)
                    if response.status_code != 200:
                        raise OidcUnavailable("upstream_status")
                    result = json.loads(data)
                    if not isinstance(result, dict):
                        raise OidcUnavailable("invalid_json")
                    return result
        except (OSError, ValueError, httpx.HTTPError, httpcore.NetworkError, httpcore.TimeoutException):
            raise OidcUnavailable("upstream_failure") from None
        finally:
            _request_deadline.reset(token)


@dataclass(frozen=True)
class Snapshot:
    metadata_json: str
    jwks_json: str
    metadata_at: float
    keys_at: float

    @property
    def metadata(self):
        return json.loads(self.metadata_json)

    @property
    def jwks(self):
        return json.loads(self.jwks_json)


class Discovery:
    def __init__(self, settings, outbound=None):
        self.settings = settings
        self.outbound = outbound or Outbound(settings)
        self.snapshot = None
        self.last_refetch = float("-inf")
        self.lock = threading.RLock()
        self.refresh_lock = threading.Lock()

    def refresh(self, *, keys_only=False):
        if not self.refresh_lock.acquire(timeout=5):
            raise OidcUnavailable("refresh_busy")
        try:
            with self.lock:
                previous = self.snapshot
            now = time.monotonic()
            metadata = (
                previous.metadata
                if keys_only and previous
                else self.outbound.json("GET", self.settings.issuer.rstrip("/") + "/.well-known/openid-configuration")
            )
            if metadata.get("issuer") != self.settings.issuer:
                raise OidcUnavailable("issuer_mismatch")
            for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                if not isinstance(metadata.get(name), str):
                    raise OidcUnavailable("missing_endpoint")
                resolve_destination(metadata[name], self.settings)
            methods = metadata.get("code_challenge_methods_supported")
            if methods is not None and (not isinstance(methods, list) or "S256" not in methods):
                raise OidcUnavailable("pkce_unsupported")
            keys = self.outbound.json("GET", metadata["jwks_uri"])
            if not isinstance(keys.get("keys"), list):
                raise OidcUnavailable("invalid_keys")
            snapshot = Snapshot(
                json.dumps(metadata),
                json.dumps(keys),
                previous.metadata_at if keys_only and previous else now,
                now,
            )
            with self.lock:
                self.snapshot = snapshot
            return snapshot
        finally:
            self.refresh_lock.release()

    def current(self):
        with self.lock:
            now = time.monotonic()
            if self.snapshot is None or now - self.snapshot.metadata_at >= 86400:
                raise OidcUnavailable("metadata_unavailable")
            if now - self.snapshot.keys_at < 3600:
                return self.snapshot
        return self.refresh(keys_only=True)

    def retry_keys(self):
        with self.lock:
            now = time.monotonic()
            if now - self.last_refetch < 60:
                raise OidcUnavailable("key_refresh_limited")
            self.last_refetch = now
        return self.refresh(keys_only=True)

    async def run(self):
        delay = 5
        while True:
            try:
                await asyncio.to_thread(self.refresh)
                delay = 5
                await asyncio.sleep(3600)
            except (OidcUnavailable, ValueError):
                from another_s3_manager.metrics import oidc_discovery_errors_total

                oidc_discovery_errors_total.inc()
                logger.warning("OIDC discovery unavailable category=refresh_failed")
                await asyncio.sleep(delay)
                delay = min(delay * 2, 300)


_discovery = None


def discovery_for(settings):
    global _discovery
    fields = ("issuer", "client_id", "public_url", "client_secret", "allow_http", "private_origins")
    if _discovery is None or any(getattr(_discovery.settings, name) != getattr(settings, name) for name in fields):
        _discovery = Discovery(settings)
    return _discovery
