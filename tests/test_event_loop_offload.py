"""Behavioural proof that blocking boto3 calls no longer stall the event loop.

R001: every `*_for_role` helper in s3_client.py does synchronous, blocking
network I/O. Before this fix, most call sites (web routes AND MCP tools)
invoked them directly from `async def` handlers, so the WHOLE event loop
stalled for the duration of the call — every other request, from every other
user, waited.

Unit tests that merely assert `run_in_threadpool` was called are close to
worthless (they test the mock, not the behaviour). These tests instead fire a
slow S3 operation and, while it is in flight, prove a cheap, unrelated
operation still makes progress on the SAME event loop. That is only possible
if the slow operation actually yielded the loop (i.e. was offloaded to a
worker thread) instead of blocking it with a synchronous call.

Design note (learned the hard way while writing these): a naive
`asyncio.gather(slow_call(), cheap_call())` — or "sleep a bit, then fire the
cheap call and time it" — is NOT a reliable discriminator. A raw
`time.sleep()` inside an `async def` blocks the whole OS thread, which also
delays the delivery of any *other* pending callback (including the test's
own `asyncio.sleep(N)` wakeup or a task that hasn't reached its first
`await` yet) — so a badly-timed race can measure the cheap operation
*after* the slow one already finished and wrongly report "responsive" even
on unfixed code. This was caught empirically: an earlier version of the
HTTP-level test below passed even with the fix reverted. The reliable
signal is not "who wins a timing race" but "does the event loop make ANY
independent progress WHILE the slow call is still pending" — measured here
by polling/ticking on a shared, external time reference (`t0`) captured
before either coroutine starts, and checking that the FIRST poll/tick
lands soon after `t0` (not only after the slow call has already returned).
"""

import asyncio
import time
from unittest.mock import patch

import httpx
import pytest

from another_s3_manager import api_tokens as svc
from another_s3_manager.database import session_scope
from another_s3_manager.mcp_server import _current_request
from another_s3_manager.models import User, UserRole

# Long enough that a truly-blocked event loop would visibly delay the cheap
# concurrent operation (flakiness margin), short enough the suite stays fast.
SLOW_SECONDS = 0.4


# ---------------------------------------------------------------------------
# HTTP level: GET /api/buckets (slow, patched) vs. polling GET /health
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_buckets_offload_keeps_health_responsive(app_client, monkeypatch):
    """While list_buckets_for_role is "in flight" (blocking, patched to sleep),
    /health on the SAME event loop must still respond promptly — not only
    after the slow call finishes.

    Uses httpx.AsyncClient over ASGITransport (NOT starlette's TestClient)
    talking DIRECTLY to the ASGI app, so both requests are scheduled as
    coroutines on the one asyncio event loop this test runs on — exactly the
    scenario R001 is about. ASGITransport never drives the lifespan protocol
    (see httpx.ASGITransport.handle_async_request), so main.app's MCP
    session-manager lifespan is never entered here — irrelevant for these two
    plain HTTP routes and avoids FastMCP's real, hard "session_manager.run()
    only once per process" restriction that other tests already rely on.

    On UNFIXED code (list_buckets_for_role called directly, no
    run_in_threadpool), the synchronous time.sleep(SLOW_SECONDS) below runs
    ON the event loop thread. Getting this test to actually catch that took
    two corrections over naive attempts, both confirmed empirically against
    unfixed code before landing on this version:

    1. The slow request must be the coroutine THIS TEST awaits INLINE (not
       one merely scheduled via create_task), with /health polled from a
       BACKGROUND task. The reverse ordering passed even on unfixed code: an
       inline /health await's own coroutine chain never needs a genuine
       event-loop round-trip to finish (everything is in-process, nothing it
       awaits is ever "not yet ready"), so it ran to completion before a
       separately-scheduled slow task ever got its first turn at all,
       regardless of whether that task blocked.

    2. The assertion must be on the GAP between consecutive successful
       /health polls, not on how fast the FIRST poll landed. This app's
       middleware stack (main.py's four `@app.middleware("http")` functions,
       each a Starlette BaseHTTPMiddleware under the hood) inserts genuine
       async checkpoints on EVERY request, including before either route
       reaches its handler body — so the very first /health poll can
       legitimately complete quickly even on unfixed code, purely from that
       middleware interleaving, before the slow request's coroutine ever
       reaches its actual blocking line. Once it does reach that line,
       though, it holds the thread for the whole sleep — which shows up not
       in "was the first poll fast" but as one large GAP in the poll cadence
       while every other poll keeps ticking every ~10ms.
    """
    import another_s3_manager.main as main

    def _slow_list_buckets(role, user_dict):
        time.sleep(SLOW_SECONDS)
        return ["bucket-a"]

    monkeypatch.setattr(main, "list_buckets_for_role", _slow_list_buckets)

    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        login_resp = await client.post("/api/login", data={"username": "admin", "password": "admin123"})
        assert login_resp.status_code == 200

        t0 = time.perf_counter()
        poll_elapsed: list[float] = []
        stop = asyncio.Event()

        async def poll_health() -> None:
            while not stop.is_set():
                resp = await client.get("/health")
                assert resp.status_code == 200
                poll_elapsed.append(time.perf_counter() - t0)
                await asyncio.sleep(0.01)

        # Background poller, scheduled but not yet run. It only gets to
        # actually execute once the coroutine below yields the event loop.
        poller_task = asyncio.create_task(poll_health())

        # The slow request, awaited INLINE (not create_task'd) — see the
        # docstring above for why this ordering is what makes the test
        # trustworthy.
        slow_resp = await client.get("/api/buckets")

        stop.set()
        await poller_task

    assert slow_resp.status_code == 200
    assert slow_resp.json() == ["bucket-a"]
    # Need enough samples to have at least one meaningful gap. On unfixed
    # code this loop typically only completes ONE poll total (a fast one
    # slipped in via a pre-handler middleware checkpoint) before the whole
    # thread is captured for the rest of SLOW_SECONDS — so this floor alone
    # already tends to fail unfixed code, and the gap check below closes the
    # remaining gap in case a poll or two slip in either side of the block.
    assert len(poll_elapsed) >= 3, (
        f"only {len(poll_elapsed)} /health poll(s) completed across the whole "
        f"{SLOW_SECONDS}s window list_buckets_for_role was in flight — the event loop "
        "appears to have been blocked for most of it."
    )
    gaps = [b - a for a, b in zip(poll_elapsed, poll_elapsed[1:])]
    max_gap = max(gaps)
    # The proof: no gap between two consecutive successful /health polls may
    # approach SLOW_SECONDS. On unfixed code, whichever poll is due while
    # list_buckets_for_role's synchronous sleep actually runs cannot even
    # START until that sleep returns — the ~10ms poll cadence has one huge
    # gap sized almost exactly SLOW_SECONDS. On fixed code, the cadence stays
    # ~10ms throughout because the blocking call ran in a worker thread.
    assert max_gap < SLOW_SECONDS / 2, (
        f"largest gap between consecutive /health polls was {max_gap:.3f}s while "
        f"list_buckets_for_role was in flight ({SLOW_SECONDS}s sleep) — the event loop "
        "appears to have been blocked."
    )


# ---------------------------------------------------------------------------
# MCP level: bucket_summary tool (slow, patched) vs. a ticker coroutine.
# bucket_summary is the tool that motivated this fix (up to ~50 sequential
# S3 calls under mcp_summary_max_keys).
# ---------------------------------------------------------------------------


@pytest.fixture
def alice_offload():
    """Insert alice with the 'Default' role; return (user_id, plaintext_token)."""
    with session_scope() as session:
        user = User(username="alice_offload", password_hash="x", is_admin=False)
        session.add(user)
        session.flush()
        role = UserRole(user_id=user.id, role_name="Default")
        session.add(role)
        session.flush()
        uid = user.id

    _, plaintext = svc.create_token(uid, "offload-test", is_read_only=False, max_read_bytes=10_485_760)
    return uid, plaintext


class _FakeRequest:
    def __init__(self, headers: dict):
        self.headers = headers


def _fake_request(plaintext: str) -> _FakeRequest:
    return _FakeRequest({"authorization": f"Bearer {plaintext}"})


@pytest.fixture
def tool_registry():
    from another_s3_manager.mcp_server import mcp

    return {tool.name: tool.fn for tool in mcp._tool_manager._tools.values()}


async def _call(tool_registry, name, request, **kwargs):
    token = _current_request.set(request)
    try:
        return await tool_registry[name](**kwargs)
    finally:
        _current_request.reset(token)


_FAKE_SUMMARY = {
    "bucket": "b",
    "path": "",
    "complete": True,
    "scanned_objects": 3,
    "scanned_bytes": 30,
    "scanned_bytes_human": "30 B",
    "total_objects": 3,
    "total_bytes": 30,
    "total_bytes_human": "30 B",
    "scan_stopped_at": None,
    "root_objects": 3,
    "prefixes": [],
    "prefix_count": 0,
    "prefix_list_complete": True,
    "prefixes_truncated": False,
    "extensions": [{"ext": "txt", "objects": 3, "bytes": 30}],
    "extension_count": 1,
    "extensions_truncated": False,
    "largest_objects": [],
    "oldest_modified": None,
    "newest_modified": None,
}


@pytest.mark.asyncio
async def test_bucket_summary_offload_does_not_stall_event_loop(alice_offload, tool_registry):
    """While bucket_summary's underlying S3 walk is "in flight" (blocking,
    patched to sleep), a plain asyncio coroutine ticking on the SAME event
    loop must record its first tick almost immediately — not only after the
    slow call has already returned.

    No HTTP layer needed here — both coroutines are scheduled directly on
    this test's event loop via asyncio.gather, which is exactly what would
    happen when one MCP session's bucket_summary call and another session's
    (or the web UI's) request share the same process event loop.

    The ticker measures elapsed time from a SHARED t0 captured before
    asyncio.gather is even called — not from a `time.perf_counter()` read
    inside the ticker's own coroutine body. That distinction matters: if the
    ticker's own "start" were captured lazily on its first line, an unfixed
    call that monopolizes the thread for SLOW_SECONDS before the ticker ever
    gets to run would still let the ticker tick a bunch of times afterward
    within its own (now late-starting) window — passing the test for the
    wrong reason. Anchoring to the external t0 instead makes "the first tick
    arrived late" visible and catches exactly that failure mode.

    On UNFIXED code (summarize_bucket_for_role called directly, no
    run_in_threadpool), the tool coroutine has nothing else to await before
    reaching the blocking sleep, so it monopolizes the thread from the
    moment it is scheduled — the ticker's first append() cannot happen until
    the sleep is over, and this test then fails.
    """
    _, plaintext = alice_offload

    def _slow_summarize(*args, **kwargs):
        time.sleep(SLOW_SECONDS)
        return dict(_FAKE_SUMMARY)

    t0 = time.perf_counter()
    ticks: list[float] = []
    stop = asyncio.Event()

    async def ticker() -> None:
        while not stop.is_set():
            ticks.append(time.perf_counter() - t0)
            await asyncio.sleep(0.01)

    async def run_summary():
        try:
            return await _call(tool_registry, "bucket_summary", _fake_request(plaintext), role="Default", bucket="b")
        finally:
            stop.set()

    with patch("another_s3_manager.s3_client.summarize_bucket_for_role", side_effect=_slow_summarize):
        result, _ = await asyncio.gather(run_summary(), ticker())

    assert result["scanned_objects"] == 3
    assert ticks, "the ticker never got a chance to run at all"

    # The proof: the FIRST tick must land in a small fraction of SLOW_SECONDS
    # (t0-relative), even though the "S3 call" was still sleeping — only
    # possible if that call was off the event loop.
    assert ticks[0] < SLOW_SECONDS / 2, (
        f"first tick landed at {ticks[0]:.3f}s into a {SLOW_SECONDS}s slow S3 call — "
        "the event loop appears to have been blocked instead of letting the ticker run "
        "concurrently."
    )
