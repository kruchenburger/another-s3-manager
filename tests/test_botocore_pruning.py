"""ASM-67: the image keeps only some botocore service models. Prove the clients ASM needs
still build from exactly that subset, and that the Dockerfile's keep-list matches."""

import re
import shutil
from pathlib import Path

import boto3
import botocore
import botocore.config
import botocore.exceptions
import botocore.loaders
import botocore.session
import pytest

REPO = Path(__file__).resolve().parent.parent
KEEP = {"s3", "sts", "sso", "sso-oidc"}


def _dockerfile_keep() -> set[str]:
    text = (REPO / "Dockerfile").read_text(encoding="utf-8")
    match = re.search(r'^ARG BOTOCORE_KEEP="([^"]+)"', text, re.MULTILINE)
    assert match, "Dockerfile must declare ARG BOTOCORE_KEEP"
    return set(match.group(1).split())


def test_dockerfile_keep_list_matches_test():
    assert _dockerfile_keep() == KEEP


@pytest.fixture
def pruned_session(tmp_path):
    """A botocore session whose loader sees only the pruned data directory, like the image."""
    src = Path(botocore.__file__).parent / "data"
    dst = tmp_path / "botocore-data"
    dst.mkdir()
    for entry in src.iterdir():
        # Top-level files (endpoints.json, partitions.json, _retry.json, ...) stay in the image.
        if entry.is_file():
            shutil.copy2(entry, dst / entry.name)
        elif entry.name in KEEP:
            shutil.copytree(entry, dst / entry.name)
    session = botocore.session.get_session()
    session.register_component(
        "data_loader", botocore.loaders.Loader(extra_search_paths=[], include_default_search_paths=False)
    )
    session.get_component("data_loader").search_paths.append(str(dst))
    return session


@pytest.mark.parametrize("service", sorted(KEEP))
def test_needed_clients_build_from_pruned_data(pruned_session, service):
    client = pruned_session.create_client(
        service, region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="y"
    )
    assert client.meta.service_model.service_name == service


def test_s3_client_through_boto3_with_custom_endpoint(pruned_session):
    # The S3-compatible path (MinIO, R2): custom endpoint + path addressing.
    session = boto3.Session(botocore_session=pruned_session)
    client = session.client(
        "s3",
        endpoint_url="http://minio:9000",
        aws_access_key_id="x",
        aws_secret_access_key="y",
        config=botocore.config.Config(s3={"addressing_style": "path"}),
    )
    assert client.meta.endpoint_url == "http://minio:9000"


def test_assume_role_operation_exists_in_pruned_sts(pruned_session):
    sts = pruned_session.create_client("sts", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="y")
    assert "AssumeRole" in sts.meta.service_model.operation_names


def test_dropped_service_is_really_missing(pruned_session):
    # Sanity check that the fixture models the image (otherwise the tests above prove nothing).
    with pytest.raises(botocore.exceptions.UnknownServiceError):
        pruned_session.create_client("ec2", region_name="us-east-1")
