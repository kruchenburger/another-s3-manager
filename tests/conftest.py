import importlib
import json
import os
from typing import Any, Dict

import pytest

# Ensure required environment variables exist for modules that import on load
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
# TestClient talks to "http://testserver" which is not HTTPS — Set-Cookie with the
# Secure flag is dropped by the cookie jar, breaking every cookie-auth test.
# Mirror the local-dev convention: tests run over plain HTTP, so disable Secure.
os.environ.setdefault("COOKIE_SECURE", "false")


def _default_config() -> Dict[str, Any]:
    return {
        "roles": [{"name": "Default", "type": "default", "description": "Use default AWS credentials"}],
        "enable_lazy_loading": True,
        "max_file_size": 100 * 1024 * 1024,
        "disable_deletion": False,
    }


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch, tmp_path):
    """
    Prepare isolated environment for each test:
    - Temporary config file and SQLite-backed data directory
    - Environment variables required by the app
    - Reset module-level caches
    """
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(_default_config()))

    data_dir = tmp_path / "data"
    data_dir.mkdir()

    monkeypatch.setenv("S3_FILE_MANAGER_CONFIG", str(config_path))
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("ADMIN_PASSWORD", "admin123")
    # A developer or CI runner with ADMIN_PASSWORD_FORCE set in their real environment would
    # otherwise silently change the behavior of every test in the suite (several tests already
    # delenv this by hand -- this makes the whole suite hermetic, not just the ones that noticed).
    monkeypatch.delenv("ADMIN_PASSWORD_FORCE", raising=False)
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
def alice_with_token():
    """Insert a user 'alice_proto' with the 'Default' role and return (user_id, plaintext_token).

    Shared across test_mcp_tools.py and test_mcp_protocol.py.  Requires the
    isolated_environment fixture to have already set up the SQLite database.
    """
    from another_s3_manager import api_tokens as svc
    from another_s3_manager.database import session_scope
    from another_s3_manager.models import User, UserRole

    with session_scope() as session:
        user = User(username="alice_proto", password_hash="x", is_admin=False)
        session.add(user)
        session.flush()
        role = UserRole(user_id=user.id, role_name="Default")
        session.add(role)
        session.flush()
        uid = user.id

    _, plaintext = svc.create_token(uid, "proto-test", is_read_only=False, max_read_bytes=10_485_760)
    return uid, plaintext


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
def valid_user_dict():
    """Plain user dict suitable for stubbing load_users in auth tests."""
    from another_s3_manager.auth import hash_password

    return {
        "username": "testuser",
        "password_hash": hash_password("testpass"),
        "is_admin": False,
        "theme": "auto",
    }


@pytest.fixture
def valid_jwt_token(valid_user_dict):
    """Signed JWT for the valid_user_dict identity, with a CSRF claim."""
    from another_s3_manager.auth import create_access_token, generate_csrf_token

    return create_access_token(data={"sub": valid_user_dict["username"], "csrf_token": generate_csrf_token()})


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


@pytest.fixture
def moto_s3():
    """In-memory S3 backend via moto. Yields a boto3 client bound to the mock backend
    so tests can pre-create buckets/objects. The mock_aws context manager intercepts
    boto3.client('s3', ...) calls globally, so s3_client._for_role helpers also hit
    the mock backend without extra wiring."""
    import boto3
    from moto import mock_aws

    # Force test credentials so boto3 doesn't try to read ~/.aws or env profiles
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
    os.environ.setdefault("AWS_SESSION_TOKEN", "testing")

    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        yield client
