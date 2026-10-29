"""Bounded, process-local copy-before-delete jobs for a single bucket and role."""

import hashlib
import json
import os
import secrets
import threading
import time
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

from boto3.s3.transfer import TransferConfig
from botocore.exceptions import ClientError
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from another_s3_manager import config, s3_client, users
from another_s3_manager.errors import MoveError, safe_move_error, safe_storage_logging
from another_s3_manager.metrics import move_jobs_total, s3_objects_total, safe_role_label
from another_s3_manager.move_reservations import acquire, release, reserve
from another_s3_manager.utils import (
    build_destination_key,
    is_same_or_descendant,
    validate_new_name,
    validate_source_key,
)

MULTIPART_THRESHOLD = 5 * 1024**3
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="move-job")


class MoveItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    path: str
    kind: Literal["file", "folder"]
    new_name: str | None = None

    @field_validator("path")
    @classmethod
    def exact_key(cls, value):
        return validate_source_key(value)

    @field_validator("new_name")
    @classmethod
    def new_name_valid(cls, value):
        return validate_new_name(value) if value is not None else None


class MoveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    items: tuple[MoveItem, ...] | list[MoveItem] = Field(min_length=1, max_length=1000)
    destination: str

    @field_validator("destination")
    @classmethod
    def destination_valid(cls, value):
        return validate_source_key(value, allow_root=True)

    @model_validator(mode="after")
    def names_only_for_single(self):
        if len(self.items) > 1 and any(item.new_name is not None for item in self.items):
            raise ValueError("INVALID_NAME")
        object.__setattr__(self, "items", tuple(self.items))
        return self


def require_access(user: dict, role: str | None, bucket: str, *, deleting=False) -> None:
    if not role or not role.strip():
        raise MoveError("ROLE_REQUIRED")
    if len(role.encode("utf-8")) > 1024:
        raise MoveError("INVALID_REQUEST")
    cfg = config.load_config(force_reload=True)
    if not any(r.get("name") == role for r in cfg.get("roles", [])):
        raise MoveError("ROLE_NOT_FOUND")
    try:
        s3_client.validate_role_access(role, user)
        s3_client._validate_bucket_access(role, bucket, user)
    except PermissionError:
        raise MoveError("ACCESS_DENIED", 403) from None
    if deleting and (os.getenv("DISABLE_DELETION", "false").lower() == "true" or cfg.get("disable_deletion", False)):
        raise MoveError("DELETION_DISABLED", 403)


def s3_unit(role, operation, callback):
    token = safe_storage_logging.set(True)
    try:
        return s3_client.execute_with_s3_retry(role, operation, callback)
    finally:
        safe_storage_logging.reset(token)


def head(client, bucket, key):
    try:
        return client.head_object(Bucket=bucket, Key=key)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") in {"404", "NoSuchKey", "NotFound"}:
            return None
        raise


def name_exists(client, bucket, key):
    # A key and a directory with the same name collide in either direction.
    base = key[:-1] if key.endswith("/") else key
    return head(client, bucket, base) is not None or bool(
        client.list_objects_v2(Bucket=bucket, Prefix=base + "/", MaxKeys=1).get("Contents")
    )


def roots_for(request: MoveRequest) -> tuple[tuple[str, str, str], ...]:
    roots = []
    for item in request.items:
        target = build_destination_key(request.destination, item.path, item.kind, item.new_name)
        source = item.path + ("/" if item.kind == "folder" else "")
        if target == source:
            raise MoveError("SAME_LOCATION")
        if item.kind == "folder" and is_same_or_descendant(request.destination, item.path):
            raise MoveError("DESCENDANT")
        roots.append((source, target, item.kind))
    for i, (source, target, kind) in enumerate(roots):
        for j, (other_source, other_target, other_kind) in enumerate(roots):
            if i != j and (
                source == other_source
                or (kind == "folder" and other_source.startswith(source))
                or target.rstrip("/") == other_target.rstrip("/")
                or (kind == "folder" and other_target.startswith(target))
            ):
                raise MoveError("PLAN_CONFLICT", 409)
            if target == other_source or (other_kind == "folder" and target.startswith(other_source)):
                raise MoveError("PLAN_CONFLICT", 409)
    return tuple(roots)


def reservation_paths(role, bucket, request):
    paths = [(role, bucket, key) for source, target, _ in roots_for(request) for key in (source, target)]
    # Parent markers are writes too; reserve those parents while the move runs.
    for item in request.items:
        parent = item.path.rpartition("/")[0]
        if parent:
            paths.append((role, bucket, parent + "/"))
    return paths


@dataclass(frozen=True)
class Entry:
    source: str
    destination: str
    etag: str
    size: int
    last_modified: object


@dataclass(frozen=True)
class Plan:
    entries: tuple[Entry, ...]
    roots: tuple[tuple[str, str, str], ...]
    parents: tuple[str, ...]

    def summary(self):
        return {
            "objects": len(self.entries),
            "bytes": sum(e.size for e in self.entries),
            "largest": max((e.size for e in self.entries), default=0),
            "conflicts": [],
            "blocked_reason": None,
        }


def enumerate_sources(role, bucket, roots, *, allow_missing=False):
    limit = config.resolve_move_max_objects()

    def enumerate_all(client):
        found = {}
        for source, target, kind in roots:
            if kind == "folder":
                pages = client.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=source)

                def page_objects(pages):
                    for page in pages:
                        if page.get("IsTruncated") and not page.get("NextContinuationToken"):
                            raise MoveError("LISTING_INCOMPLETE", 502)
                        yield from page.get("Contents", [])

                objects = page_objects(pages)
            else:
                metadata = head(client, bucket, source)
                if metadata is None:
                    if allow_missing:
                        continue
                    raise MoveError("NoSuchKey", 404, key=source)
                objects = iter(
                    [
                        {
                            "Key": source,
                            "ETag": metadata["ETag"],
                            "Size": metadata["ContentLength"],
                            "LastModified": metadata.get("LastModified"),
                        }
                    ]
                )
            had_object = False
            for obj in objects:
                had_object = True
                key = validate_source_key(obj["Key"])
                dest = validate_source_key(target + key[len(source) :])
                found[key] = Entry(key, dest, obj["ETag"], obj["Size"], obj.get("LastModified"))
                if len(found) > limit:
                    raise MoveError("TOO_MANY_OBJECTS", objects=len(found))
            if not had_object and not allow_missing:
                raise MoveError("NoSuchKey", 404, key=source)
        return tuple(found.values())

    return s3_unit(role, "list", enumerate_all)


def build_plan(user, role, bucket, request):
    require_access(user, role, bucket, deleting=True)
    roots = roots_for(request)
    entries = enumerate_sources(role, bucket, roots)
    sources = {e.source for e in entries}
    destinations = set()
    for entry in entries:
        if entry.destination in sources or entry.destination in destinations:
            raise MoveError("PLAN_CONFLICT", 409)
        destinations.add(entry.destination)
    for destination in destinations:
        parts = destination.split("/")
        for index in range(1, len(parts)):
            if "/".join(parts[:index]) in destinations:
                raise MoveError("PLAN_CONFLICT", 409)
    for _, target, _ in roots:
        if s3_unit(role, "head", lambda client: name_exists(client, bucket, target)):
            raise MoveError("CONFLICT", 409)
    parents = tuple(sorted({item.path.rpartition("/")[0] for item in request.items if "/" in item.path}))
    for parent in parents:
        validate_source_key(parent + "/")
    return Plan(entries, roots, parents)


def copy_entry(role, bucket, entry):
    if s3_unit(role, "head", lambda client: head(client, bucket, entry.destination)) is not None:
        raise MoveError("DESTINATION_APPEARED", 409, "copy", entry.source)

    def copy_one(client):
        extra = {}
        if entry.size > MULTIPART_THRESHOLD:
            metadata = client.head_object(Bucket=bucket, Key=entry.source)
            extra = {
                key: metadata[key]
                for key in (
                    "ContentType",
                    "ContentEncoding",
                    "ContentDisposition",
                    "ContentLanguage",
                    "CacheControl",
                    "Expires",
                    "Metadata",
                )
                if key in metadata
            }
            if metadata.get("StorageClass", "STANDARD") != "STANDARD":
                extra["StorageClass"] = metadata["StorageClass"]
        client.copy(
            {"Bucket": bucket, "Key": entry.source},
            bucket,
            entry.destination,
            ExtraArgs=extra,
            # s3transfer uses >=; the exact 5 GiB boundary still fits CopyObject.
            Config=TransferConfig(
                multipart_threshold=MULTIPART_THRESHOLD + (entry.size == MULTIPART_THRESHOLD), use_threads=False
            ),
        )
        result = client.head_object(Bucket=bucket, Key=entry.destination)
        return result["ETag"]

    etag = s3_unit(role, "put", copy_one)
    s3_objects_total.labels(role=safe_role_label(role), bucket=bucket, operation="copy").inc()
    return etag


def owner_identity(user):
    created_at = user["created_at"]
    if created_at is not None:
        # SQLite reloads UTC timestamps without the timezone attached at creation.
        timestamp = datetime.fromisoformat(created_at)
        created_at = timestamp.replace(tzinfo=timestamp.tzinfo or UTC).astimezone(UTC).isoformat()
    return (user["id"], user["username"], created_at)


@dataclass
class Job:
    id: str
    owner: tuple[int, str, str | None]
    role: str
    bucket: str
    operation_id: str
    request_hash: str
    plan: Plan | None = None
    state: str = "running"
    phase: str = "planning"
    done: int = 0
    bytes_done: int = 0
    removed: int = 0
    copied: dict[str, str] = field(default_factory=dict)
    failures: list[dict] = field(default_factory=list)
    failures_total: int = 0
    finished_at: float | None = None
    delete_started: bool = False
    future: Future | None = None
    ready: threading.Event = field(default_factory=threading.Event, repr=False)
    planning_error: MoveError | None = None
    lock: object = field(default_factory=threading.RLock, repr=False)
    cleanup_lock: object = field(default_factory=threading.Lock, repr=False)

    def fail(self, error, phase, key=None):
        failure = safe_move_error(error, phase, key).detail()
        with self.lock:
            self.failures_total += 1
            if len(self.failures) < 1000:
                self.failures.append(failure)

    def snapshot(self, offset=0):
        with self.lock:
            total = self.plan.summary() if self.plan else {"objects": 0, "bytes": 0}
            return {
                "job_id": self.id,
                "state": self.state,
                "delete_started": self.delete_started,
                "phase": self.phase,
                "done": self.done,
                "total": total["objects"],
                "bytes_done": self.bytes_done,
                "bytes_total": total["bytes"],
                "removed": self.removed,
                "failures": list(self.failures[offset : offset + 100]),
                "failures_total": self.failures_total,
                "failures_stored": len(self.failures),
                "failures_offset": offset,
                "next_failures_offset": offset + 100 if offset + 100 < len(self.failures) else None,
                "result": {"moved": self.removed},
            }


def recheck(job):
    user = users.get_user_by_id(job.owner[0])
    if user is None or owner_identity(user) != job.owner:
        raise MoveError("ACCESS_DENIED", 403)
    require_access(user, job.role, job.bucket, deleting=True)


def delete_batch(job, keys):
    recheck(job)
    result = s3_unit(
        job.role,
        "delete",
        lambda client: client.delete_objects(
            Bucket=job.bucket, Delete={"Objects": [{"Key": key} for key in keys], "Quiet": False}
        ),
    )
    errors = {error["Key"]: error.get("Code", "STORAGE_ERROR") for error in result.get("Errors", [])}
    deleted = {item["Key"] for item in result.get("Deleted", [])}
    for key in keys:
        if key in errors or key not in deleted:
            job.fail(MoveError(errors.get(key, "STORAGE_ERROR"), 502, job.phase, key), job.phase, key)
    succeeded = deleted.intersection(keys).difference(errors)
    s3_objects_total.labels(role=safe_role_label(job.role), bucket=job.bucket, operation="delete").inc(len(succeeded))
    return succeeded


def run_job(job):
    try:
        job.phase = "copy"
        with ThreadPoolExecutor(max_workers=8, thread_name_prefix="move-copy") as pool:
            for index in range(0, len(job.plan.entries), 100):
                try:
                    recheck(job)
                except MoveError as error:
                    job.fail(error, job.phase)
                    job.state = "cancelled_access"
                    return
                batch = job.plan.entries[index : index + 100]
                futures = {pool.submit(copy_entry, job.role, job.bucket, entry): entry for entry in batch}
                failed = False
                for future in as_completed(futures):
                    entry = futures[future]
                    try:
                        etag = future.result()
                        with job.lock:
                            job.copied[entry.destination] = etag
                            job.done += 1
                            job.bytes_done += entry.size
                    except Exception as error:
                        failed = True
                        job.fail(error, "copy", entry.source)
                if failed:
                    job.state = "failed_copy"
                    return
        recheck(job)
        job.phase = "verify"
        current = {
            entry.source: entry for entry in enumerate_sources(job.role, job.bucket, job.plan.roots, allow_missing=True)
        }
        planned = {entry.source: entry for entry in job.plan.entries}
        unchanged = []
        for key, entry in planned.items():
            now = current.get(key)
            if now is None or (now.etag, now.size) != (entry.etag, entry.size):
                job.fail(MoveError("SOURCE_CHANGED", 409, "verify", key), "verify")
            else:
                unchanged.append(key)
        for key in current.keys() - planned.keys():
            job.fail(MoveError("NEW_IN_SOURCE", 409, "verify", key), "verify")
        recheck(job)
        job.phase = "delete"
        delete_failures_before = job.failures_total
        for index in range(0, len(unchanged), 1000):
            recheck(job)
            job.delete_started = True
            job.removed += len(delete_batch(job, unchanged[index : index + 1000]))
        if job.failures_total > delete_failures_before:
            job.state = "failed_delete"
            return
        for parent in job.plan.parents:
            recheck(job)
            try:
                empty = not s3_unit(
                    job.role,
                    "list",
                    lambda client: client.list_objects_v2(Bucket=job.bucket, Prefix=parent + "/", MaxKeys=1),
                ).get("Contents")
                if empty:
                    s3_unit(
                        job.role, "put", lambda client: client.put_object(Bucket=job.bucket, Key=parent + "/", Body=b"")
                    )
            except Exception:
                job.fail(MoveError("parent_marker_failed", 502, "marker", parent + "/"), "marker")
        job.state = "done_with_warnings" if job.failures_total else "done"
    except MoveError as error:
        job.fail(error, job.phase)
        job.state = (
            "cancelled_access"
            if error.code in {"ACCESS_DENIED", "ROLE_NOT_FOUND", "DELETION_DISABLED"}
            else ("failed_delete" if job.delete_started else "failed_copy")
        )
    except Exception as error:
        job.fail(error, job.phase)
        job.state = "failed_delete" if job.delete_started else "failed_copy"
    finally:
        with job.lock:
            job.finished_at = time.monotonic()
        move_jobs_total.labels(outcome=job.state).inc()
        release(job.id)


class MoveRegistry:
    def __init__(self):
        self.lock = threading.RLock()
        self.jobs: dict[str, Job] = {}
        self.preflights: dict[tuple[int, str, str | None], deque] = {}

    def _run(self, job):
        run_job(job)
        with self.lock:
            self.prune()

    def prune(self):
        now = time.monotonic()
        finished = sorted((j for j in self.jobs.values() if j.finished_at is not None), key=lambda j: j.finished_at)
        for index, job in enumerate(finished):
            if now - job.finished_at >= 3600 or index < len(finished) - 200:
                self.jobs.pop(job.id, None)
        for owner in list(self.preflights):
            if not self.preflights[owner] or now - self.preflights[owner][-1] >= 60:
                del self.preflights[owner]

    def preflight(self, user, role, bucket, request):
        require_access(user, role, bucket, deleting=True)
        with self.lock:
            self.prune()
            times = self.preflights.setdefault(owner_identity(user), deque())
            now = time.monotonic()
            while times and now - times[0] >= 60:
                times.popleft()
            if len(times) >= 10:
                raise MoveError("PREFLIGHT_LIMIT", 429)
            times.append(now)
        with reserve(secrets.token_urlsafe(), reservation_paths(role, bucket, request)):
            return build_plan(user, role, bucket, request).summary()

    def start(self, user, role, bucket, request, operation_id):
        require_access(user, role, bucket, deleting=True)
        digest = hashlib.sha256(
            json.dumps([role, bucket, request.model_dump()], sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()
        existing = None
        with self.lock:
            self.prune()
            for job in self.jobs.values():
                if (job.owner, job.operation_id) == (owner_identity(user), operation_id):
                    if job.request_hash != digest:
                        raise MoveError("OPERATION_CONFLICT", 409)
                    existing = job
                    break
            if existing is None:
                running = [j for j in self.jobs.values() if j.state == "running"]
                if len(running) >= 4 or sum(j.owner == owner_identity(user) for j in running) >= 2:
                    raise MoveError("TOO_MANY_JOBS", 429)
                job = Job(secrets.token_urlsafe(), owner_identity(user), role, bucket, operation_id, digest)
                acquire(job.id, reservation_paths(role, bucket, request))
                self.jobs[job.id] = job
        if existing is not None:
            existing.ready.wait()
            if existing.planning_error:
                raise existing.planning_error
            return existing
        try:
            job.plan = build_plan(user, role, bucket, request)
            job.future = _executor.submit(self._run, job)
            return job
        except Exception as error:
            job.planning_error = safe_move_error(error, "planning")
            with self.lock:
                self.jobs.pop(job.id, None)
            release(job.id)
            raise
        finally:
            job.ready.set()

    def get(self, job_id, user):
        with self.lock:
            self.prune()
            job = self.jobs.get(job_id)
            if job is None or job.owner != owner_identity(user):
                raise MoveError("NOT_FOUND", 404)
        require_access(user, job.role, job.bucket)
        return job

    def cleanup(self, job_id, user):
        job = self.get(job_id, user)
        recheck(job)
        if not job.cleanup_lock.acquire(blocking=False):
            raise MoveError("BUSY", 409)
        try:
            with job.lock:
                if job.state == "running":
                    raise MoveError("BUSY", 409)
                if job.delete_started:
                    raise MoveError("CLEANUP_UNSAFE", 409)
                copied = list(job.copied.items())
            token = secrets.token_urlsafe()
            with reserve(token, [(job.role, job.bucket, key) for key, _ in copied]):
                failures = []
                removed = 0
                for key, etag in copied:
                    recheck(job)
                    try:
                        metadata = s3_unit(job.role, "head", lambda client: head(client, job.bucket, key))
                        if metadata is None:
                            with job.lock:
                                del job.copied[key]
                            continue
                        if metadata["ETag"] != etag:
                            raise MoveError("CLEANUP_CHANGED", 409, "cleanup", key)
                        result = s3_unit(
                            job.role,
                            "delete",
                            lambda client: client.delete_objects(
                                Bucket=job.bucket, Delete={"Objects": [{"Key": key}], "Quiet": False}
                            ),
                        )
                        if result.get("Errors") or key not in {x["Key"] for x in result.get("Deleted", [])}:
                            raise MoveError("STORAGE_ERROR", 502, "cleanup", key)
                        with job.lock:
                            del job.copied[key]
                        removed += 1
                        s3_objects_total.labels(
                            role=safe_role_label(job.role), bucket=job.bucket, operation="delete"
                        ).inc()
                    except Exception as error:
                        if len(failures) < 1000:
                            failures.append(safe_move_error(error, "cleanup", key).detail())
                return {"removed": removed, "failures": failures}
        finally:
            job.cleanup_lock.release()


registry = MoveRegistry()
