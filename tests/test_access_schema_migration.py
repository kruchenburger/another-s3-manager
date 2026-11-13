import ast
import os
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

from another_s3_manager import access
from another_s3_manager.database import get_engine


def test_schema_supports_applied_mapping_mode():
    columns = {c["name"] for c in inspect(get_engine()).get_columns("users")}
    assert {"auth_generation", "session_epoch", "mapping_mode_applied", "is_disabled"} <= columns


def test_login_ledger_schema_stores_only_hash_and_timestamps():
    assert {c["name"] for c in inspect(get_engine()).get_columns("oidc_login_transactions")} == {
        "state_hash",
        "expires_at",
        "consumed_at",
    }


def populated_database(tmp_path, monkeypatch):
    data = tmp_path / "schema-data"
    data.mkdir()
    monkeypatch.setenv("DATA_DIR", str(data))
    cfg = Config("alembic.ini")
    cfg.set_main_option("script_location", "migrations")
    command.upgrade(cfg, "35173f08b83b")
    path = data / "another_s3_manager.db"
    engine = create_engine(f"sqlite:///{path}")
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (id,username,password_hash,is_admin,theme,default_role,must_change_password,password_set_via,created_at,updated_at) VALUES (1,'alice','hash',1,'dark','Default',0,'cli','2020-01-01','2020-01-02'), (2,'bob','other',0,'auto',NULL,1,'env','2020-02-01','2020-02-02')"
            )
        )
        conn.execute(text("INSERT INTO user_roles(user_id,role_name) VALUES (1,'Default'),(2,'reader')"))
        conn.execute(
            text(
                "INSERT INTO bans(user_id,banned_until,banned_at,reason,created_at) VALUES (2,100,1,'test','2020-02-01')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO api_tokens(user_id,token_hash,name,created_at,is_read_only,max_read_bytes) VALUES (1,'hash','test','2020-01-01',1,1024)"
            )
        )
    return cfg, engine, path


def test_populated_access_round_trip_preserves_children_and_invalidates_old_generation(tmp_path, monkeypatch):
    cfg, engine, path = populated_database(tmp_path, monkeypatch)
    tables = ("users", "user_roles", "bans", "api_tokens")
    with engine.connect() as conn:
        before = {name: conn.execute(text(f"SELECT * FROM {name} ORDER BY id")).mappings().all() for name in tables}
    ids = []
    for revision_file in Path("migrations/versions").glob("*.py"):
        tree = ast.parse(revision_file.read_text())
        for node in tree.body:
            name = (
                node.target.id
                if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
                else (
                    node.targets[0].id
                    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                    else None
                )
            )
            if name == "revision":
                ids.append(ast.literal_eval(node.value))
    assert len(ids) == len(set(ids))
    scripts = ScriptDirectory.from_config(cfg)
    assert scripts.get_heads() == ["c131a001"]
    revisions = [r.revision for r in scripts.walk_revisions()]
    assert len(revisions) == len(set(revisions))
    command.upgrade(cfg, "c131a001")
    from another_s3_manager import users
    from another_s3_manager.database import reset_engine_for_tests

    reset_engine_for_tests()
    old = users.get_user_by_id(1)
    cookie = access.issue_session(access.Principal(old), method="pwd", lifetime_minutes=180)
    with engine.begin() as conn:
        generations = conn.execute(text("SELECT auth_generation FROM users ORDER BY id")).scalars().all()
        assert len(set(generations)) == 2 and all(len(g) == 43 for g in generations)
        conn.execute(
            text(
                "INSERT INTO user_identities(user_id,issuer,subject,created_at) VALUES (1,'issuer','subject','2020-01-01')"
            )
        )
        conn.execute(
            text("INSERT INTO oidc_login_transactions(state_hash,expires_at) VALUES (:hash,'2099-01-01')"),
            {"hash": "a" * 64},
        )
        assert conn.execute(text("PRAGMA foreign_key_check")).all() == []
    command.downgrade(cfg, "35173f08b83b")
    with engine.connect() as conn:
        for name in tables:
            assert conn.execute(text(f"SELECT * FROM {name} ORDER BY id")).mappings().all() == before[name]
        assert conn.execute(text("PRAGMA foreign_key_check")).all() == []
    command.upgrade(cfg, "c131a001")
    reset_engine_for_tests()
    assert users.get_user_by_id(1)["auth_generation"] != old["auth_generation"]
    with pytest.raises(access.AuthenticationError) as error:
        access.authenticate_session(cookie)
    assert error.value.code == "ACCOUNT_REPLACED"
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM user_identities")).scalar_one() == 0
        assert conn.execute(text("SELECT count(*) FROM oidc_login_transactions")).scalar_one() == 0
        assert conn.execute(text("PRAGMA foreign_key_check")).all() == []
    engine.dispose()


def test_n_minus_one_insert_gets_one_generation():
    from another_s3_manager import users
    from another_s3_manager.database import get_engine

    with get_engine().begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users(id,username,password_hash,is_admin,theme,must_change_password,created_at,updated_at) VALUES (71,'legacy','hash',0,'auto',0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"
            )
        )
        assert conn.execute(text("SELECT auth_generation FROM users WHERE id=71")).scalar_one() is None
    start = Barrier(2)

    def read():
        start.wait(timeout=10)
        return access.principal_for(71).user["auth_generation"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = pool.submit(read), pool.submit(read)
        generations = [a.result(timeout=15), b.result(timeout=15)]
    assert len(generations[0]) == 43 and generations[0] == generations[1]
    assert users.get_user_by_id(71)["auth_generation"] == generations[0]


def test_mapping_mode_constraint_and_identity_uniqueness():
    from another_s3_manager import users
    from another_s3_manager.database import session_scope
    from another_s3_manager.models import User

    owner = users.create_user("alice", "hash")
    for mode in ("sync", "initial", None):
        with session_scope() as session:
            session.get(User, owner["id"]).mapping_mode_applied = mode
    with pytest.raises(IntegrityError), session_scope() as session:
        session.get(User, owner["id"]).mapping_mode_applied = "invalid"
    with session_scope() as session:
        access.insert_identity(session, user_id=owner["id"], issuer="issuer", subject="subject")
    for subject in ("subject", "different"):
        with pytest.raises(IntegrityError), session_scope() as session:
            access.insert_identity(session, user_id=owner["id"], issuer="issuer", subject=subject)
    assert access.find_identity("issuer", "subject")["user_id"] == owner["id"]
    users.delete_user("alice")
    assert access.find_identity("issuer", "subject") is None


def test_n_minus_one_actual_startup_on_upgraded_database(tmp_path, monkeypatch, record_property):
    image = os.environ.get("ASM_N_MINUS_ONE_IMAGE")
    if not image:
        pytest.skip("Required remote actual N-1 startup evidence pending: ASM_N_MINUS_ONE_IMAGE is unset")
    if os.environ.get("CI", "").lower() != "true":
        pytest.skip("Image startup experiment runs only in the manager's remote CI job")
    cfg, engine, original = populated_database(tmp_path, monkeypatch)
    command.upgrade(cfg, "c131a001")
    engine.dispose()
    disposable = tmp_path / "previous-image-data"
    disposable.mkdir()
    # Online backup includes WAL state; never copy an active SQLite file alone.
    with sqlite3.connect(original) as source, sqlite3.connect(disposable / "another_s3_manager.db") as target:
        source.backup(target)
    script = "from another_s3_manager.main import run_startup_tasks; run_startup_tasks()"
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp",
            "--user",
            "0",
            "--entrypoint",
            "python",
            "-v",
            f"{disposable.resolve()}:/experiment",
            "-e",
            "DATA_DIR=/experiment",
            "-e",
            "S3_FILE_MANAGER_CONFIG=/experiment/config.json",
            "-e",
            "JWT_SECRET_KEY=isolated-startup-experiment-only",
            "-e",
            "SQLITE_JOURNAL_MODE=delete",
            image,
            "-c",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    diagnostics = result.stdout + result.stderr
    unknown = "c131a001" in diagnostics and (
        "Can't locate revision" in diagnostics or "No such revision" in diagnostics
    )
    record_property("previous_image_startup_exit", result.returncode)
    record_property("unknown_c131a001", unknown)
    if unknown:
        record_property("startup_diagnostic", "Cannot resolve c131a001 in the previous image")
    # Do not publish raw container output: future startup versions may log config.
    assert result.returncode != 0, "Previous startup unexpectedly succeeded; re-review compatibility/recovery contracts"
    assert unknown, "Previous startup failed without the expected c131a001 resolution diagnostic"
