import pytest

from tests.test_main import login


@pytest.mark.parametrize("suffix", ["folders", "move", "move/preflight"])
def test_body_limit(app_client, suffix):
    _, headers = login(app_client)
    response = app_client.post(
        "/api/buckets/guard-bucket/" + suffix + "?role=Default", content=b"x" * (256 * 1024 + 1), headers=headers
    )
    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "BODY_TOO_LARGE"


@pytest.mark.asyncio
async def test_chunked_actual_bytes(monkeypatch, app_client):
    from another_s3_manager import main

    monkeypatch.setattr(main, "has_valid_session", lambda request: True)
    messages = iter(
        [
            {"type": "http.request", "body": b"x" * (128 * 1024), "more_body": True},
            {"type": "http.request", "body": b"y" * (128 * 1024 + 1), "more_body": False},
        ]
    )
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/jobs/secret-id/cleanup",
        "headers": [(b"content-length", b"1")],
    }

    async def receive():
        return next(messages)

    sent = []

    async def send(message):
        sent.append(message)

    async def app(*args):
        pytest.fail("oversized body reached app")

    await main._MoveBodyGuard(app)(scope, receive, send)
    assert sent[0]["status"] == 413
    assert scope["guard_path_template"] == "/api/jobs/{job_id}/cleanup"


def test_early_errors_use_bounded_metric_labels(app_client):
    from another_s3_manager.metrics import REGISTRY

    _, headers = login(app_client)
    template = "/api/buckets/{bucket_name}/folders"
    labels = {"method": "POST", "path_template": template, "status_code": "413"}
    before = REGISTRY.get_sample_value("as3m_http_requests_total", labels) or 0
    for bucket in ["first-bucket", "second-bucket"]:
        assert (
            app_client.post("/api/buckets/" + bucket + "/folders", content=b"x" * 262145, headers=headers).status_code
            == 413
        )
    assert REGISTRY.get_sample_value("as3m_http_requests_total", labels) == before + 2
