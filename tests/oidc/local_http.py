"""A loopback HTTP server that answers through an httpx-style handler (tests only).

It lets OIDC tests use the real outbound path (resolver validation, pinned connect,
peer check, deadline stream) instead of an httpx MockTransport.
"""

import socket
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx


@contextmanager
def serve(handle, host_name="op.example"):
    """Serve `handle(httpx.Request) -> httpx.Response` on 127.0.0.1; yield the port."""

    class Handler(BaseHTTPRequestHandler):
        def _answer(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            port = self.server.server_address[1]
            request = httpx.Request(
                self.command, f"http://{host_name}:{port}{self.path}", content=body, headers=dict(self.headers)
            )
            response = handle(request)
            content = response.read()
            self.send_response(response.status_code)
            self.send_header("Content-Type", response.headers.get("content-type", "application/json"))
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        do_GET = _answer
        do_POST = _answer

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def resolver_for(monkeypatch, answers):
    """Patch getaddrinfo: `answers` maps host -> ordered list of IP strings."""
    original = socket.getaddrinfo

    def getaddrinfo(host, port, *args, **kwargs):
        if host in answers:
            return [
                (socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))
                for ip in answers[host]
            ]
        return original(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
