import uuid

import pytest

from another_s3_manager import move_jobs as moves
from tests.test_main import login


@pytest.fixture
def session(app_client, moto_s3):
    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="folder-routes")
    yield app_client, moto_s3, headers
    for job in list(moves.registry.jobs.values()):
        if job.future:
            job.future.result(timeout=10)
    moves.registry.jobs.clear()
    moves.registry.preflights.clear()


def test_create_folder(session):
    client, s3, headers = session
    response = client.post(
        "/api/buckets/folder-routes/folders?role=Default", json={"path": "новая 📁"}, headers=headers
    )
    assert response.status_code == 201
    assert response.json() == {"path": "новая 📁/"}
    assert s3.head_object(Bucket="folder-routes", Key="новая 📁/")["ContentLength"] == 0


@pytest.mark.parametrize(
    "path,kind,new_name",
    [
        ("source/a..b #+% 📁 ", "file", None),
        ("source/dir", "folder", None),
        ("source/file", "file", "changed"),
        ("source/dir", "folder", "changed"),
    ],
)
def test_move_happy_paths(session, path, kind, new_name):
    client, s3, headers = session
    suffix = "/nested/# +%😀 " if kind == "folder" else ""
    s3.put_object(Bucket="folder-routes", Key=path + suffix, Body=b"content", ContentType="text/plain")
    item = {"path": path, "kind": kind}
    if new_name:
        item["new_name"] = new_name
    body = {"items": [item], "destination": "dest"}
    preflight = client.post("/api/buckets/folder-routes/move/preflight?role=Default", json=body, headers=headers)
    assert preflight.status_code == 200
    assert preflight.json()["bytes"] == 7
    body["operation_id"] = str(uuid.uuid4())
    response = client.post("/api/buckets/folder-routes/move?role=Default", json=body, headers=headers)
    assert response.status_code == 202
    job_id = response.json()["job_id"]
    moves.registry.jobs[job_id].future.result(timeout=10)
    result = client.get("/api/jobs/" + job_id, headers=headers)
    assert result.status_code == 200
    assert result.json()["state"] == "done"
    dest = "dest/" + (new_name or path.rsplit("/", 1)[-1]) + suffix
    assert s3.get_object(Bucket="folder-routes", Key=dest)["Body"].read() == b"content"


@pytest.mark.parametrize("query,status", [("", 400), ("?role=", 400), ("?role=unknown", 400)])
def test_required_role_without_s3(session, monkeypatch, query, status):
    client, _, headers = session
    monkeypatch.setattr(moves.s3_client, "get_s3_client", lambda *a: pytest.fail("unexpected S3"))
    response = client.post("/api/buckets/folder-routes/folders" + query, json={"path": "new"}, headers=headers)
    assert response.status_code == status


@pytest.mark.parametrize("gate", ["env", "config"])
def test_deletion_gate_allows_new_folder(session, monkeypatch, gate):
    client, s3, headers = session
    if gate == "env":
        monkeypatch.setenv("DISABLE_DELETION", "true")
    else:
        cfg = moves.config.load_config()
        moves.config.save_config({**cfg, "disable_deletion": True})
    assert (
        client.post(
            "/api/buckets/folder-routes/folders?role=Default", json={"path": "new"}, headers=headers
        ).status_code
        == 201
    )
    response = client.post(
        "/api/buckets/folder-routes/move?role=Default",
        json={"items": [{"path": "file", "kind": "file"}], "destination": "dest", "operation_id": str(uuid.uuid4())},
        headers=headers,
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "DELETION_DISABLED"


def test_role_not_allowed_no_storage(session, monkeypatch):
    client, _, _ = session
    from another_s3_manager import auth, users

    users.create_user("restricted", auth.hash_password("password123"), allowed_roles=[], must_change_password=False)
    _, headers = login(client, "restricted", "password123")
    monkeypatch.setattr(moves.s3_client, "get_s3_client", lambda *args: pytest.fail("unexpected S3"))
    response = client.post("/api/buckets/folder-routes/folders?role=Default", json={"path": "new"}, headers=headers)
    assert response.status_code == 403


def test_cookie_and_csrf_required(session):
    client, _, headers = session
    assert client.post("/api/buckets/folder-routes/folders?role=Default", json={"path": "new"}).status_code == 403
    client.cookies.clear()
    assert (
        client.post(
            "/api/buckets/folder-routes/folders?role=Default", json={"path": "new"}, headers=headers
        ).status_code
        == 401
    )


def test_safe_storage_error(session, monkeypatch):
    from botocore.exceptions import ClientError

    client, _, headers = session

    def fail(*args):
        raise ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "arn:aws:iam::123456789012:role/private token=SECRET foreign/key https://secret/?X-Amz-Signature=123",
                }
            },
            "PutObject",
        )

    monkeypatch.setattr(moves.s3_client, "create_folder_for_role", fail)
    response = client.post("/api/buckets/folder-routes/folders?role=Default", json={"path": "new"}, headers=headers)
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "AccessDenied"
    assert response.json()["detail"]["key"] is None
    for secret in ["arn:", "123456789012", "SECRET", "foreign/key", "X-Amz"]:
        assert secret not in response.text


def test_folder_collision_and_owner_route_isolation(session):
    client, s3, headers = session
    s3.put_object(Bucket="folder-routes", Key="existing", Body=b"x")
    response = client.post(
        "/api/buckets/folder-routes/folders?role=Default", json={"path": "existing"}, headers=headers
    )
    assert response.status_code == 409
    s3.put_object(Bucket="folder-routes", Key="source", Body=b"x")
    response = client.post(
        "/api/buckets/folder-routes/move?role=Default",
        json={"items": [{"path": "source", "kind": "file"}], "destination": "dest", "operation_id": str(uuid.uuid4())},
        headers=headers,
    )
    job_id = response.json()["job_id"]
    moves.registry.jobs[job_id].future.result(timeout=10)
    from another_s3_manager import auth, users

    users.create_user("other", auth.hash_password("password123"), allowed_roles=["Default"], must_change_password=False)
    _, other_headers = login(client, "other", "password123")
    assert client.get("/api/jobs/" + job_id).status_code == 404
    assert client.post("/api/jobs/" + job_id + "/cleanup", headers=other_headers).status_code == 404


def test_invalid_folder_name_has_safe_specific_code(session):
    client, _, headers = session
    response = client.post(
        "/api/buckets/folder-routes/folders?role=Default", json={"path": "source/bad "}, headers=headers
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "INVALID_NAME"


def test_user_dictionary_is_not_returned(session):
    client, _, headers = session
    response = client.get("/api/me")
    assert "id" not in response.json()
    assert "password_hash" not in response.json()
    response = client.get("/api/admin/users")
    assert isinstance(response.json()["users"][0]["id"], int)
    assert "password_hash" not in response.json()["users"][0]


def test_unsupported_nested_key_and_destination_length_are_400(session):
    client, s3, headers = session
    s3.put_object(Bucket="folder-routes", Key="source/../unsupported", Body=b"x")
    response = client.post(
        "/api/buckets/folder-routes/move/preflight?role=Default",
        json={"items": [{"path": "source", "kind": "folder"}], "destination": "dest"},
        headers=headers,
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "INVALID_KEY"
    s3.put_object(Bucket="folder-routes", Key="file", Body=b"x")
    response = client.post(
        "/api/buckets/folder-routes/move/preflight?role=Default",
        json={"items": [{"path": "file", "kind": "file"}], "destination": "a" * 1024},
        headers=headers,
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "KEY_TOO_LONG"


def test_move_limit_config_is_preserved_and_validated(session):
    client, _, headers = session
    cfg = moves.config.load_config()
    cfg["move_max_objects"] = 17
    moves.config.save_config(cfg)
    body = {"roles": cfg["roles"]}
    assert client.post("/api/config", json=body, headers=headers).status_code == 200
    assert moves.config.load_config(force_reload=True)["move_max_objects"] == 17
    assert client.get("/api/config").json()["move_max_objects"] == 17
    response = client.post("/api/config", json={**body, "move_max_objects": 0}, headers=headers)
    assert response.status_code == 400


def test_recreated_owner_cannot_read_or_cleanup_job(session):
    from another_s3_manager import auth, users

    client, s3, _ = session
    password_hash = auth.hash_password("password123")
    owner = users.create_user("owner", password_hash, allowed_roles=["Default"], must_change_password=False)
    _, headers = login(client, "owner", "password123")
    s3.put_object(Bucket="folder-routes", Key="source", Body=b"x")
    response = client.post(
        "/api/buckets/folder-routes/move?role=Default",
        json={"items": [{"path": "source", "kind": "file"}], "destination": "dest", "operation_id": str(uuid.uuid4())},
        headers=headers,
    )
    assert response.status_code == 202
    job_id = response.json()["job_id"]
    moves.registry.jobs[job_id].future.result(timeout=10)
    users.delete_user("owner")
    replacement = users.create_user("owner", password_hash, allowed_roles=["Default"], must_change_password=False)
    assert replacement["id"] == owner["id"]
    assert replacement["created_at"] != owner["created_at"]
    _, headers = login(client, "owner", "password123")
    assert client.get("/api/jobs/" + job_id).status_code == 404
    assert client.post("/api/jobs/" + job_id + "/cleanup", headers=headers).status_code == 404


@pytest.mark.asyncio
async def test_polling_snapshot_does_not_block_event_loop(session, monkeypatch):
    import asyncio
    import threading

    from another_s3_manager import main, users

    _, s3, _ = session
    owner = users.load_users()["users"][0]
    s3.put_object(Bucket="folder-routes", Key="source", Body=b"x")
    job = moves.registry.start(
        owner,
        "Default",
        "folder-routes",
        moves.MoveRequest(items=[{"path": "source", "kind": "file"}], destination="dest"),
        str(uuid.uuid4()),
    )
    job.future.result(timeout=10)
    entered, loop_progress = threading.Event(), threading.Event()
    snapshot = job.snapshot

    def waiting_snapshot(offset):
        entered.set()
        assert loop_progress.wait(2), "polling blocked the event loop"
        return snapshot(offset)

    async def advance_loop():
        assert await asyncio.to_thread(entered.wait, 5)
        loop_progress.set()

    monkeypatch.setattr(job, "snapshot", waiting_snapshot)
    heartbeat = asyncio.create_task(advance_loop())
    try:
        result = await main.get_move_job(job.id, failures_offset=0, current_user=owner)
        assert result["state"] == "done"
    finally:
        loop_progress.set()
        await heartbeat


@pytest.mark.parametrize("delete_started", [False, True])
def test_job_snapshot_exposes_delete_started(session, delete_started):
    client, s3, headers = session
    s3.put_object(Bucket="folder-routes", Key="source", Body=b"x")
    response = client.post(
        "/api/buckets/folder-routes/move?role=Default",
        json={"items": [{"path": "source", "kind": "file"}], "destination": "dest", "operation_id": str(uuid.uuid4())},
        headers=headers,
    )
    assert response.status_code == 202
    job_id = response.json()["job_id"]
    job = moves.registry.jobs[job_id]
    job.future.result(timeout=10)
    with job.lock:
        job.state = "cancelled_access"
        job.delete_started = delete_started
    result = client.get("/api/jobs/" + job_id, headers=headers)
    assert result.status_code == 200
    assert result.json()["state"] == "cancelled_access"
    assert result.json()["delete_started"] is delete_started
