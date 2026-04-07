"""Throw-away smoke test for S3 access against the Nginx logs bucket.

Connects to the configured S3-compatible endpoint (e.g. OpenStack Swift's
S3 interface) using the same boto3 client config as the production
collector, lists a few objects, fetches the most recent one, gunzips it
and prints the first few JSON log lines.

Assumes the following env vars are already set in the shell:

    S3_BUCKET, S3_PREFIX (optional), S3_ENDPOINT_URL,
    AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION (optional)

Usage:
    python test_s3_access.py
"""

import gzip
import io
import os
import sys

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

S3_BUCKET = os.environ['S3_BUCKET']
S3_PREFIX = os.environ.get('S3_PREFIX', '')
S3_ENDPOINT_URL = os.environ.get('S3_ENDPOINT_URL') or None
S3_ACCESS_KEY = os.environ['S3_ACCESS_KEY']
S3_SECRET_KEY = os.environ['S3_SECRET_KEY']
S3_REGION = os.environ.get('S3_REGION', 'us-east-1')

MAX_LIST = 10
MAX_LINES = 3


def make_client():
    config = Config(
        signature_version='s3v4',
        s3={'addressing_style': 'path'},
    )
    return boto3.client(
        's3',
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
        endpoint_url=S3_ENDPOINT_URL,
        region_name=S3_REGION,
        config=config,
    )


def main():
    print(f"Endpoint: {S3_ENDPOINT_URL or '(default AWS)'}")
    print(f"Bucket:   {S3_BUCKET}")
    print(f"Prefix:   {S3_PREFIX or '(none)'}")
    print()

    s3 = make_client()

    print(f"[1] Listing up to {MAX_LIST} objects...")
    try:
        response = s3.list_objects_v2(
            Bucket=S3_BUCKET,
            Prefix=S3_PREFIX,
            MaxKeys=MAX_LIST,
        )
    except (BotoCoreError, ClientError) as e:
        print(f"  FAIL: list_objects_v2 raised: {e}")
        sys.exit(1)

    contents = response.get('Contents', [])
    if not contents:
        print("  No objects found in bucket/prefix.")
        sys.exit(0)

    for obj in contents:
        print(f"  {obj['LastModified']}  {obj['Size']:>10}  {obj['Key']}")

    latest = max(contents, key=lambda o: o['Key'])
    print(f"\n[2] Fetching latest key: {latest['Key']}")
    try:
        body = s3.get_object(
            Bucket=S3_BUCKET, Key=latest['Key'])['Body'].read()
    except (BotoCoreError, ClientError) as e:
        print(f"  FAIL: get_object raised: {e}")
        sys.exit(1)
    print(f"  Downloaded {len(body)} bytes (compressed)")

    print(f"\n[3] Decompressing and printing first {MAX_LINES} lines:")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as gz:
            for i, line in enumerate(gz):
                if i >= MAX_LINES:
                    break
                print(f"  {line.decode('utf-8', errors='replace').rstrip()}")
    except OSError as e:
        print(f"  FAIL: gzip decode raised: {e}")
        sys.exit(1)

    print("\nPASS: S3 access works")


if __name__ == '__main__':
    main()
