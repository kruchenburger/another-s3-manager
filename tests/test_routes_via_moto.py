"""Reference patterns for testing routes against an in-memory S3 backend."""


def test_moto_fixture_smoke(moto_s3):
    """Verify mock_aws intercepts boto3 globally so helpers see fake S3."""
    moto_s3.create_bucket(Bucket="smoke-bucket")

    from another_s3_manager.s3_client import list_buckets_for_role

    buckets = list_buckets_for_role(
        None,
        {"username": "admin", "is_admin": True, "allowed_roles": []},
    )
    assert "smoke-bucket" in buckets
