import importlib
import json
import os
from typing import Any, Dict

import pytest

# Ensure required environment variables exist for modules that import on load
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")


def _default_config() -> Dict[str, Any]:
    return {
        "roles": [{"name": "Default", "type": "default", "description": "Use default AWS credentials"}],
        "items_per_page": 200,
        "enable_lazy_loading": True,
        "max_file_size": 100 * 1024 * 1024,
        "disable_deletion": False,
    }


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch, tmp_path):
    """
    Prepare isolated environment for each test:
    - Temporary config, users, bans files
    - Environment variables required by the app
    - Reset module-level caches
    """
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(_default_config()))

    data_dir = tmp_path / "data"
    data_dir.mkdir()

    users_path = data_dir / "users.json"
    users_path.write_text(json.dumps({"users": []}))

    bans_path = data_dir / "bans.json"
    bans_path.write_text(json.dumps({}))

    monkeypatch.setenv("S3_FILE_MANAGER_CONFIG", str(config_path))
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("ADMIN_PASSWORD", "admin123")
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)

    # Reload modules that cache file paths or config to ensure isolation
    import another_s3_manager.config as config_module
    import another_s3_manager.constants as constants
    import another_s3_manager.database as database_module
    import another_s3_manager.s3_client as s3_client_module
    import another_s3_manager.users as users_module

    importlib.reload(constants)
    importlib.reload(database_module)
    importlib.reload(config_module)
    importlib.reload(users_module)
    importlib.reload(s3_client_module)

    # Ensure caches are cleared
    config_module._config_cache = {}
    config_module._config_mtime = 0
    s3_client_module._s3_clients_cache.clear()

    # Initialize SQLite schema for the isolated DATA_DIR
    database_module.reset_engine_for_tests()
    from another_s3_manager.models import Base

    Base.metadata.create_all(database_module.get_engine())

    yield

    # Dispose engine so the next test gets a fresh one
    database_module.reset_engine_for_tests()
    # Cleanup of files is handled by tmp_path fixture automatically


@pytest.fixture
def app_client(monkeypatch):
    """
    Provide a FastAPI TestClient with a fresh instance of the app.
    """
    from fastapi.testclient import TestClient

    import another_s3_manager.main as main

    # Reload main to ensure it picks up the isolated environment
    importlib.reload(main)

    client = TestClient(main.app)
    return client


@pytest.fixture
def fake_s3_client():
    """
    Provide a simple fake S3 client for unit tests that interact with boto3.
    """

    class FakePaginator:
        def __init__(self, pages):
            self._pages = pages

        def paginate(self, **kwargs):
            for page in self._pages:
                yield page

    class FakeS3Client:
        def __init__(self):
            self.objects = {}
            self.uploads = []
            self.deleted = []
            self._paginator_pages = []

        def set_paginator_pages(self, pages):
            self._paginator_pages = pages

        def get_paginator(self, name):
            return FakePaginator(self._paginator_pages)

        def put_object(self, Bucket, Key, Body, ContentType=None):
            self.uploads.append({"Bucket": Bucket, "Key": Key, "Body": Body, "ContentType": ContentType})
            self.objects[Key] = Body

        def get_object(self, Bucket, Key):
            if Key not in self.objects:
                from botocore.exceptions import ClientError

                raise ClientError(
                    {"Error": {"Code": "NoSuchKey", "Message": "Key not found"}},
                    "GetObject",
                )
            return {
                "Body": BodyWrapper(self.objects[Key]),
                "ContentType": "application/octet-stream",
            }

        def delete_object(self, Bucket, Key):
            self.deleted.append({"Bucket": Bucket, "Key": Key})
            self.objects.pop(Key, None)

        def delete_objects(self, Bucket, Delete):
            for obj in Delete.get("Objects", []):
                key = obj.get("Key")
                self.deleted.append({"Bucket": Bucket, "Key": key})
                self.objects.pop(key, None)

    class BodyWrapper:
        def __init__(self, data: bytes):
            self._data = data

        def read(self):
            return self._data

    return FakeS3Client()


@pytest.fixture
def mock_boto3_client(mocker, fake_s3_client):
    """
    Mock boto3.client to return a fake S3 client.
    """
    return mocker.patch("boto3.client", return_value=fake_s3_client)


@pytest.fixture
def db_session(monkeypatch, tmp_path):
    """Fresh in-memory SQLite engine + tables. Patches the app's engine to use it."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))

    import importlib

    from another_s3_manager import constants, database

    importlib.reload(constants)
    importlib.reload(database)
    database.reset_engine_for_tests()

    from sqlalchemy import event

    from another_s3_manager.models import Base

    engine = database.get_engine()

    @event.listens_for(engine, "connect")
    def _enable_fk(dbapi_conn, _):
        dbapi_conn.execute("PRAGMA foreign_keys = ON")

    Base.metadata.create_all(engine)

    # Yield a session bound to the same engine
    with database.session_scope() as session:
        yield session

    database.reset_engine_for_tests()
