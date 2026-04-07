"""Collect workflow invocation data from Nginx logs stored in S3.

Lists gzipped JSON Nginx log objects in an S3 bucket, processes any
objects whose key sorts after the last-seen key (recorded between
runs), and for each workflow invocation request line:

- Decodes the StoredWorkflow ID using Galaxy's IdEncodingHelper algorithm
- Queries the Galaxy database for workflow name and source_metadata
- Resolves a canonical workflow identity (TRS tool ID if available)
- Sends the data point to InfluxDB via the HTTP write API

Designed to run hourly as a cron job. Object keys are assumed to begin
with a sortable timestamp prefix so that lexicographic ordering matches
upload order.

Usage:
    collect_workflow_invocations.py
"""

import codecs
import gzip
import io
import json
import logging
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from Crypto.Cipher import Blowfish
from dotenv import load_dotenv
from sqlalchemy import create_engine, text

load_dotenv(Path(__file__).parent / '.env')

LOG_FORMAT = '%(levelname)s: %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)

GALAXY_ID_SECRET = os.environ['GALAXY_ID_SECRET']
GALAXY_DATABASE_URL = os.environ['GALAXY_DATABASE_URL']
INFLUX_URL = os.environ['INFLUX_URL']
INFLUX_DB = os.environ['INFLUX_DB']
INFLUX_TOKEN = os.environ['INFLUX_TOKEN']
S3_BUCKET = os.environ['S3_BUCKET']
S3_PREFIX = os.environ.get('S3_PREFIX', '')
S3_ENDPOINT_URL = os.environ.get('S3_ENDPOINT_URL') or None
S3_ACCESS_KEY = os.environ['S3_ACCESS_KEY']
S3_SECRET_KEY = os.environ['S3_SECRET_KEY']
S3_REGION = os.environ.get('S3_REGION', 'us-east-1')

MEASUREMENT_NAME = 'workflow_invocation'
STATE_FILE = Path(__file__).parent / '.collect_state'

INVOCATION_PATTERN = re.compile(
    r'^POST /api/workflows/([a-f0-9]+)/invocations'
)
DOMAIN_PATTERN = re.compile(
    r'https?://([^/"\s]+)'
)

WORKFLOW_QUERY = text("""
    SELECT sw.id, sw.name, sw.user_id, w.uuid, w.source_metadata
    FROM stored_workflow sw
    JOIN workflow w ON w.id = sw.latest_workflow_id
    WHERE sw.id = :id
""")


def decode_galaxy_id(encoded_id: str, id_cipher) -> int:
    """Decode a Galaxy hex-encoded ID to an integer database ID.

    Replicates Galaxy's IdEncodingHelper.decode_id algorithm:
    hex decode -> Blowfish ECB decrypt -> strip padding -> int.
    """
    raw = codecs.decode(encoded_id, 'hex')
    decrypted = id_cipher.decrypt(raw)
    return int(decrypted.decode('utf-8').lstrip('!'))


def parse_json_log_line(line: str) -> dict | None:
    """Extract workflow invocation data from a JSON-formatted Nginx log line.

    Each line is a JSON object with a `parsed` sub-object containing
    `request`, `timestamp`, and `referer` fields. Returns a dict with
    `encoded_id`, `datetime`, and `domain` keys, or None if the line
    is not a workflow invocation request.
    """
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        logger.warning("Skipping malformed JSON line")
        return None

    parsed = record.get('parsed') or {}
    request = parsed.get('request', '')

    inv_match = INVOCATION_PATTERN.match(request)
    if not inv_match:
        return None

    timestamp = parsed.get('timestamp')
    if not timestamp:
        logger.warning("No timestamp in invocation line: %s", request)
        return None
    try:
        dt = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError as e:
        logger.warning("Invalid timestamp '%s': %s", timestamp, e)
        return None

    referer = parsed.get('referer', '') or ''
    domain_match = DOMAIN_PATTERN.search(referer)
    domain = domain_match.group(1) if domain_match else 'unknown'

    return {
        'encoded_id': inv_match.group(1),
        'datetime': dt,
        'domain': domain,
    }


def resolve_canonical_id(source_metadata) -> tuple[str, str, str]:
    """Resolve canonical workflow identity from source_metadata.

    Returns (canonical_id, trs_server, trs_version_id).
    """
    if not source_metadata:
        return '', '', ''

    if isinstance(source_metadata, str):
        source_metadata = json.loads(source_metadata)

    trs_tool_id = source_metadata.get('trs_tool_id', '')
    trs_server = source_metadata.get('trs_server', '')
    trs_version_id = source_metadata.get('trs_version_id', '')

    if trs_tool_id:
        canonical_id = (
            f"{trs_server}:{trs_tool_id}" if trs_server
            else trs_tool_id
        )
        return canonical_id, trs_server, trs_version_id

    url = source_metadata.get('url', '')
    if url:
        return url, '', ''

    return '', '', ''


def escape_tag_value(value: str) -> str:
    """Escape special characters in an InfluxDB line protocol tag value."""
    return (
        value
        .replace('\\', '\\\\')
        .replace(' ', '\\ ')
        .replace(',', '\\,')
        .replace('=', '\\=')
    )


def escape_field_string(value: str) -> str:
    """Escape special characters in an InfluxDB line protocol string field."""
    return value.replace('\\', '\\\\').replace('"', '\\"')


def format_line_protocol(
    measurement: str,
    tags: dict,
    fields: dict,
    timestamp: datetime,
) -> str:
    """Format a data point as an InfluxDB line protocol string."""
    tag_str = ','.join(
        f"{k}={escape_tag_value(str(v))}"
        for k, v in tags.items()
    )
    field_parts = []
    for k, v in fields.items():
        if isinstance(v, float):
            field_parts.append(f"{k}={v}")
        elif isinstance(v, int):
            field_parts.append(f"{k}={v}i")
        else:
            field_parts.append(f'{k}="{escape_field_string(str(v))}"')
    field_str = ','.join(field_parts)
    ts = int(timestamp.timestamp())
    return f"{measurement},{tag_str} {field_str} {ts}"


def read_last_key() -> str:
    """Return the last processed S3 object key, or '' if none."""
    try:
        return STATE_FILE.read_text().strip()
    except FileNotFoundError:
        return ''


def save_last_key(key: str):
    """Persist the last processed S3 object key for the next run."""
    STATE_FILE.write_text(f"{key}\n")


def make_s3_client():
    """Create a boto3 S3 client from environment configuration.

    Configured to be compatible with non-AWS S3 services such as
    OpenStack Swift's S3 interface: forces path-style addressing
    (Swift does not support virtual-hosted-style buckets) and
    signature v4.
    """
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


def list_new_objects(s3_client, last_key: str) -> list[str]:
    """List object keys lexicographically greater than last_key.

    Uses S3's StartAfter parameter so the bucket is only paged for new
    objects. Returns keys in sorted (upload) order.
    """
    keys = []
    paginator = s3_client.get_paginator('list_objects_v2')
    list_kwargs = {'Bucket': S3_BUCKET, 'Prefix': S3_PREFIX}
    if last_key:
        list_kwargs['StartAfter'] = last_key
    for page in paginator.paginate(**list_kwargs):
        for obj in page.get('Contents', []):
            keys.append(obj['Key'])
    keys.sort()
    return keys


def fetch_object_lines(s3_client, key: str):
    """Yield decoded log lines from a gzipped JSON-lines S3 object."""
    response = s3_client.get_object(Bucket=S3_BUCKET, Key=key)
    body = response['Body'].read()
    with gzip.GzipFile(fileobj=io.BytesIO(body)) as gz:
        for raw in gz:
            yield raw.decode('utf-8', errors='replace')


def write_to_influxdb(lines: list[str]):
    """Write line protocol data points to InfluxDB via the HTTP write API."""
    payload = '\n'.join(lines).encode('utf-8')
    url = f"{INFLUX_URL}/write?db={INFLUX_DB}"
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            'Authorization': f'Token {INFLUX_TOKEN}',
            'Content-Type': 'application/octet-stream',
        },
        method='POST',
    )
    try:
        with urllib.request.urlopen(req) as response:
            logger.info(
                "Wrote %d data points to InfluxDB (HTTP %d)",
                len(lines), response.status,
            )
    except urllib.error.URLError as e:
        logger.error("Failed to write to InfluxDB: %s", e)
        sys.exit(1)


def process_line(line: str, conn, id_cipher) -> str | None:
    """Convert a single log line into an InfluxDB line protocol record.

    Returns the formatted line protocol string, or None if the line is
    not an invocation or could not be resolved.
    """
    parsed = parse_json_log_line(line)
    if not parsed:
        return None

    try:
        workflow_id = decode_galaxy_id(parsed['encoded_id'], id_cipher)
    except (ValueError, TypeError) as e:
        logger.warning(
            "Failed to decode ID '%s': %s",
            parsed['encoded_id'], e,
        )
        return None

    result = conn.execute(
        WORKFLOW_QUERY,
        {'id': workflow_id},
    ).fetchone()

    if not result:
        logger.warning(
            "StoredWorkflow %d not found in database",
            workflow_id,
        )
        return None

    _, name, user_id, uuid, source_metadata = result
    canonical_id, trs_server, trs_version_id = (
        resolve_canonical_id(source_metadata)
    )

    return format_line_protocol(
        measurement=MEASUREMENT_NAME,
        tags={
            'domain': parsed['domain'],
            'workflow_name': name,
            'canonical_id': canonical_id or name,
            'trs_server': trs_server,
        },
        fields={
            'count': 1.0,
            'workflow_id': workflow_id,
            'user_id': user_id,
            'trs_version_id': trs_version_id,
        },
        timestamp=parsed['datetime'],
    )


def main():
    id_cipher = Blowfish.new(
        GALAXY_ID_SECRET.encode('utf-8'),
        mode=Blowfish.MODE_ECB,
    )
    engine = create_engine(GALAXY_DATABASE_URL)
    s3_client = make_s3_client()

    last_key = read_last_key()
    try:
        new_keys = list_new_objects(s3_client, last_key)
    except (BotoCoreError, ClientError) as e:
        logger.error("Failed to list S3 objects: %s", e)
        sys.exit(1)

    if not new_keys:
        logger.info("No new S3 objects to process")
        return

    logger.info("Processing %d new S3 object(s)", len(new_keys))
    data_points = []
    latest_key = last_key

    with engine.connect() as conn:
        for key in new_keys:
            try:
                for line in fetch_object_lines(s3_client, key):
                    record = process_line(line, conn, id_cipher)
                    if record:
                        data_points.append(record)
            except (BotoCoreError, ClientError, OSError) as e:
                logger.error("Failed to read s3://%s/%s: %s",
                             S3_BUCKET, key, e)
                break
            latest_key = key

    if data_points:
        write_to_influxdb(data_points)

    if latest_key != last_key:
        save_last_key(latest_key)


if __name__ == '__main__':
    main()
