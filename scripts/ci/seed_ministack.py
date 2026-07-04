#!/usr/bin/env python3
"""Idempotent ministack seed for E2E. Provisions S3 buckets, an IAM user with a
bucket-scoped policy, and an assumable role; prints the four app role configs and
optionally writes a full config.json (--config-out). Run against a running
ministack (default http://localhost:4566)."""

import argparse
import configparser
import json
import os
import sys

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

ALLOWED = "ministack-allowed"
FORBIDDEN = "ministack-forbidden"
USER = "restricted"
PROFILE = "ministack-profile"
ROLE = "ministack-s3-role"
ACCOUNT = "000000000000"  # pinned via MINISTACK_ACCOUNT_ID in the compose/CI env


def client(svc, endpoint, ak="test", sk="test"):
    return boto3.client(
        svc,
        endpoint_url=endpoint,
        region_name="us-east-1",
        aws_access_key_id=ak,
        aws_secret_access_key=sk,
        config=Config(retries={"max_attempts": 0}, signature_version="s3v4"),
    )


def _ignore_exists(fn, *args, **kwargs):
    """Run fn; swallow the 'already exists' family so re-seeding is a no-op."""
    try:
        return fn(*args, **kwargs)
    except ClientError as e:
        if e.response["Error"]["Code"] in {
            "BucketAlreadyOwnedByYou",
            "BucketAlreadyExists",
            "EntityAlreadyExists",
        }:
            return None
        raise


def seed(endpoint):
    s3 = client("s3", endpoint)
    iam = client("iam", endpoint)
    sts = client("sts", endpoint)

    acct = sts.get_caller_identity()["Account"]
    if acct != ACCOUNT:
        sys.exit(f"ministack account is {acct}, expected {ACCOUNT} (set MINISTACK_ACCOUNT_ID={ACCOUNT})")

    _ignore_exists(s3.create_bucket, Bucket=ALLOWED)
    _ignore_exists(s3.create_bucket, Bucket=FORBIDDEN)
    s3.put_object(Bucket=ALLOWED, Key="hello.txt", Body=b"seeded by seed_ministack.py")

    # Restricted user: may list bucket names + do anything in ALLOWED, nothing in
    # FORBIDDEN. NOTE: this emulator accepts IAM policies but does NOT enforce them
    # on S3, so the policy documents the intended scope but is not a security
    # boundary here; the ministack-creds role exercises the direct-credentials path.
    _ignore_exists(iam.create_user, UserName=USER)
    iam.put_user_policy(
        UserName=USER,
        PolicyName="scoped",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["s3:ListAllMyBuckets"], "Resource": "*"},
                    {
                        "Effect": "Allow",
                        "Action": ["s3:*"],
                        "Resource": [f"arn:aws:s3:::{ALLOWED}", f"arn:aws:s3:::{ALLOWED}/*"],
                    },
                ],
            }
        ),
    )
    # Fresh access key each run (idempotent: delete existing first).
    for k in iam.list_access_keys(UserName=USER).get("AccessKeyMetadata", []):
        iam.delete_access_key(UserName=USER, AccessKeyId=k["AccessKeyId"])
    key = iam.create_access_key(UserName=USER)["AccessKey"]

    # Assumable role with full S3 + a permissive trust policy.
    _ignore_exists(
        iam.create_role,
        RoleName=ROLE,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}],
            }
        ),
    )
    iam.put_role_policy(
        RoleName=ROLE,
        PolicyName="s3all",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        ),
    )

    return key


def roles(endpoint_for_app, key):
    return [
        {
            "name": "ministack-assume",
            "type": "assume_role",
            "role_arn": f"arn:aws:iam::{ACCOUNT}:role/{ROLE}",
            "endpoint_url": endpoint_for_app,
            "allowed_buckets": [ALLOWED],
        },
        {
            "name": "ministack-creds",
            "type": "credentials",
            "access_key_id": key["AccessKeyId"],
            "secret_access_key": key["SecretAccessKey"],
            "endpoint_url": endpoint_for_app,
            # FORBIDDEN is listed (app-allowed) but no test browses it: with IAM
            # unenforced there is no deny to assert, so it is unused-by-design.
            "allowed_buckets": [ALLOWED, FORBIDDEN],
        },
        {
            "name": "ministack-profile",
            "type": "profile",
            "profile_name": PROFILE,
            "endpoint_url": endpoint_for_app,
            "allowed_buckets": [ALLOWED],
        },
        {
            "name": "ministack-default",
            "type": "default",
            "endpoint_url": endpoint_for_app,
            "allowed_buckets": [ALLOWED],
        },
    ]


def write_aws_credentials_file(path, key):
    """Write the restricted user's key as a named profile for the profile role.

    The backend's `profile` role type does boto3.Session(profile_name=...), which
    reads AWS_SHARED_CREDENTIALS_FILE. CI points that env at this file.
    """
    cp = configparser.ConfigParser()
    cp[PROFILE] = {
        "aws_access_key_id": key["AccessKeyId"],
        "aws_secret_access_key": key["SecretAccessKey"],
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        cp.write(f)


def write_config(path, role_list):
    cfg = {
        "roles": role_list,
        "max_client_load": 50,
        "enable_lazy_loading": True,
        "max_file_size": 104857600,
        "disable_deletion": False,
        "auto_inline_extensions": [],
        "password_min_length": 8,
        "password_min_uppercase": 1,
        "password_min_lowercase": 1,
        "password_min_digits": 1,
        "password_min_special": 0,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", default="http://localhost:4566", help="ministack endpoint this script talks to")
    ap.add_argument("--app-endpoint", default=None, help="endpoint_url the app uses (defaults to --endpoint)")
    ap.add_argument(
        "--config-out", default=None, help="write a full config.json here (CI). Omit to only print the roles."
    )
    ap.add_argument(
        "--aws-credentials-out",
        default=None,
        help="write the profile's AWS shared-credentials file here (CI sets AWS_SHARED_CREDENTIALS_FILE to it).",
    )
    args = ap.parse_args()

    key = seed(args.endpoint)
    role_list = roles(args.app_endpoint or args.endpoint, key)

    if args.aws_credentials_out:
        write_aws_credentials_file(args.aws_credentials_out, key)
        print(f"# wrote {args.aws_credentials_out} (profile [{PROFILE}])")

    print("# ministack roles (paste into data/config.json 'roles' for local dev):")
    print(json.dumps(role_list, indent=2))
    if args.config_out:
        write_config(args.config_out, role_list)
        print(f"# wrote {args.config_out}")


if __name__ == "__main__":
    main()
