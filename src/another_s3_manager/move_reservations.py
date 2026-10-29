"""Process-local reservations shared by moves and existing write helpers."""

import inspect
import secrets
import threading
from contextlib import contextmanager
from functools import wraps

from another_s3_manager.errors import MoveError

_lock = threading.RLock()
_active: dict[str, tuple[tuple[str, str, str], ...]] = {}


def overlaps(left: str, right: str) -> bool:
    # Also reserve the file/folder name counterpart; x and x/ must not collide.
    left, right = left.rstrip("/"), right.rstrip("/")
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def acquire(owner: str, paths: list[tuple[str, str, str]]) -> None:
    with _lock:
        for token, existing in _active.items():
            if token == owner:
                raise MoveError("BUSY", 409)
            for role, bucket, path in paths:
                for old_role, old_bucket, old_path in existing:
                    # Roles may be aliases for the same bucket. Conservatively coordinate
                    # matching bucket names even across separate compatible endpoints.
                    if bucket == old_bucket and overlaps(path, old_path):
                        raise MoveError("BUSY", 409)
        _active[owner] = tuple(paths)


def release(owner: str) -> None:
    with _lock:
        _active.pop(owner, None)


@contextmanager
def reserve(owner: str, paths: list[tuple[str, str, str]]):
    acquire(owner, paths)
    try:
        yield
    finally:
        release(owner)


def guarded_write(*, copy: bool = False):
    """Hold a reservation across the complete existing synchronous S3 helper."""

    def decorate(function):
        signature = inspect.signature(function)

        @wraps(function)
        def wrapped(*args, **kwargs):
            from another_s3_manager.s3_client import _validate_bucket_access, validate_role_access

            values = signature.bind(*args, **kwargs).arguments
            role = values["role"]
            user = values["user_dict"]
            validate_role_access(role, user)
            if copy:
                paths = [
                    (role, values["source_bucket"], values["source_path"]),
                    (role, values["dest_bucket"], values["dest_path"]),
                ]
            else:
                paths = [(role, values["bucket"], values["path"])]
            for _, bucket, _ in paths:
                _validate_bucket_access(role, bucket, user)
            with reserve(secrets.token_urlsafe(), paths):
                return function(*args, **kwargs)

        return wrapped

    return decorate
