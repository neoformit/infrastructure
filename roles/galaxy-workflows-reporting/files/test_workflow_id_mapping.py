"""Test workflow ID decoding, DB lookup, and canonical ID resolution.

Run on the Galaxy server with access to the Galaxy database.

Requires a .env file (or environment variables) with:
    GALAXY_ID_SECRET       - Galaxy's id_secret for encoding/decoding IDs
    GALAXY_DATABASE_URL    - SQLAlchemy connection string for Galaxy's database

Usage:
    python test_workflow_id_mapping.py
    python test_workflow_id_mapping.py -v          # verbose output
"""

import codecs
import json
import os
import unittest
from datetime import datetime

from Crypto.Cipher import Blowfish
from dotenv import load_dotenv
from sqlalchemy import create_engine, text

load_dotenv()

GALAXY_ID_SECRET = os.environ.get('GALAXY_ID_SECRET', '')
GALAXY_DATABASE_URL = os.environ.get('GALAXY_DATABASE_URL', '')

# --- Functions under test (duplicated from the deployed script) ---

INVOCATION_PATTERN_STR = (
    r'POST /api/workflows/([a-f0-9]+)/invocations'
)
DATETIME_PATTERN_STR = (
    r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})'
)
DATETIME_FORMAT = '%d/%b/%Y:%H:%M:%S'
DOMAIN_PATTERN_STR = r'https?://([^/"\s]+)'

import re  # noqa: E402

INVOCATION_PATTERN = re.compile(INVOCATION_PATTERN_STR)
DATETIME_PATTERN = re.compile(DATETIME_PATTERN_STR)
DOMAIN_PATTERN = re.compile(DOMAIN_PATTERN_STR)

WORKFLOW_QUERY = text("""
    SELECT sw.id, sw.name, sw.user_id, w.uuid, w.source_metadata
    FROM stored_workflow sw
    JOIN workflow w ON w.id = sw.latest_workflow_id
    WHERE sw.id = :id
""")

SAMPLE_WORKFLOW_QUERY = text("""
    SELECT sw.id, sw.name, sw.user_id, w.uuid, w.source_metadata
    FROM stored_workflow sw
    JOIN workflow w ON w.id = sw.latest_workflow_id
    WHERE sw.deleted = false
    LIMIT 1
""")

SAMPLE_TRS_WORKFLOW_QUERY = text("""
    SELECT sw.id, sw.name, sw.user_id, w.uuid, w.source_metadata
    FROM stored_workflow sw
    JOIN workflow w ON w.id = sw.latest_workflow_id
    WHERE sw.deleted = false
        AND w.source_metadata IS NOT NULL
        AND w.source_metadata::text LIKE '%trs_tool_id%'
    LIMIT 1
""")


def encode_galaxy_id(decoded_id: int, id_cipher) -> str:
    """Encode a database integer ID to Galaxy's hex-encoded format.

    Replicates Galaxy's IdEncodingHelper.encode_id algorithm:
    int -> pad with '!' to 8 bytes -> Blowfish ECB encrypt -> hex encode.
    """
    id_str = str(decoded_id)
    padded = id_str.rjust(8, '!')
    encrypted = id_cipher.encrypt(padded.encode('utf-8'))
    return codecs.encode(encrypted, 'hex').decode('utf-8')


def decode_galaxy_id(encoded_id: str, id_cipher) -> int:
    """Decode a Galaxy hex-encoded ID to an integer database ID."""
    raw = codecs.decode(encoded_id, 'hex')
    decrypted = id_cipher.decrypt(raw)
    return int(decrypted.decode('utf-8').lstrip('!'))


def parse_log_line(line: str) -> dict | None:
    """Extract workflow invocation data from an Nginx log line."""
    inv_match = INVOCATION_PATTERN.search(line)
    if not inv_match:
        return None

    dt_match = DATETIME_PATTERN.search(line)
    if not dt_match:
        return None
    dt = datetime.strptime(dt_match.group(1), DATETIME_FORMAT)

    domain_match = DOMAIN_PATTERN.search(line)
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
        return ('', '', '')

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
        return (canonical_id, trs_server, trs_version_id)

    url = source_metadata.get('url', '')
    if url:
        return (url, '', '')

    return ('', '', '')


# --- Unit tests (no DB or secrets required) ---


class TestParseLogLine(unittest.TestCase):
    """Test nginx log line parsing."""

    SAMPLE_LINE = (
        '192.168.1.1 - - [27/Feb/2026:10:30:45 +0000] '
        '"POST /api/workflows/abcdef1234567890/invocations HTTP/1.1" '
        '200 215 '
        '"https://genome.usegalaxy.org.au/workflows/run?id=e4d20320d61c4f83"'
    )

    def test_extracts_encoded_id(self):
        result = parse_log_line(self.SAMPLE_LINE)
        self.assertIsNotNone(result)
        self.assertEqual(result['encoded_id'], 'abcdef1234567890')

    def test_extracts_datetime(self):
        result = parse_log_line(self.SAMPLE_LINE)
        self.assertIsNotNone(result)
        expected = datetime(2026, 2, 27, 10, 30, 45)
        self.assertEqual(result['datetime'], expected)

    def test_extracts_domain(self):
        result = parse_log_line(self.SAMPLE_LINE)
        self.assertIsNotNone(result)
        self.assertEqual(result['domain'], 'genome.usegalaxy.org.au')

    def test_returns_none_for_non_invocation(self):
        line = (
            '192.168.1.1 - - [27/Feb/2026:10:30:45 +0000] '
            '"GET /api/histories HTTP/1.1" 200 100 "-"'
        )
        self.assertIsNone(parse_log_line(line))

    def test_returns_none_for_get_workflow(self):
        line = (
            '192.168.1.1 - - [27/Feb/2026:10:30:45 +0000] '
            '"GET /api/workflows/abcdef1234567890 HTTP/1.1" '
            '200 100 "-"'
        )
        self.assertIsNone(parse_log_line(line))

    def test_unknown_domain_when_no_referer(self):
        line = (
            '192.168.1.1 - - [27/Feb/2026:10:30:45 +0000] '
            '"POST /api/workflows/abcdef1234567890/invocations HTTP/1.1" '
            '200 215 "-"'
        )
        result = parse_log_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result['domain'], 'unknown')


class TestResolveCanonicalId(unittest.TestCase):
    """Test canonical workflow identity resolution."""

    def test_trs_metadata(self):
        metadata = {
            'trs_tool_id': '#workflow/github.com/iwc-workflows/example',
            'trs_server': 'dockstore',
            'trs_version_id': 'v1.0',
        }
        canonical_id, trs_server, version = resolve_canonical_id(metadata)
        self.assertEqual(
            canonical_id,
            'dockstore:#workflow/github.com/iwc-workflows/example',
        )
        self.assertEqual(trs_server, 'dockstore')
        self.assertEqual(version, 'v1.0')

    def test_trs_metadata_as_json_string(self):
        metadata = json.dumps({
            'trs_tool_id': '#workflow/example',
            'trs_server': 'workflowhub',
            'trs_version_id': 'v2.0',
        })
        canonical_id, trs_server, version = resolve_canonical_id(metadata)
        self.assertEqual(canonical_id, 'workflowhub:#workflow/example')
        self.assertEqual(trs_server, 'workflowhub')
        self.assertEqual(version, 'v2.0')

    def test_trs_without_server(self):
        metadata = {
            'trs_tool_id': '#workflow/example',
        }
        canonical_id, trs_server, version = resolve_canonical_id(metadata)
        self.assertEqual(canonical_id, '#workflow/example')
        self.assertEqual(trs_server, '')

    def test_url_import(self):
        metadata = {
            'url': 'https://example.com/workflow.ga',
        }
        canonical_id, trs_server, version = resolve_canonical_id(metadata)
        self.assertEqual(canonical_id, 'https://example.com/workflow.ga')
        self.assertEqual(trs_server, '')
        self.assertEqual(version, '')

    def test_null_metadata(self):
        canonical_id, trs_server, version = resolve_canonical_id(None)
        self.assertEqual(canonical_id, '')
        self.assertEqual(trs_server, '')
        self.assertEqual(version, '')

    def test_empty_dict(self):
        canonical_id, trs_server, version = resolve_canonical_id({})
        self.assertEqual(canonical_id, '')

    def test_trs_takes_precedence_over_url(self):
        metadata = {
            'trs_tool_id': '#workflow/example',
            'trs_server': 'dockstore',
            'url': 'https://example.com/workflow.ga',
        }
        canonical_id, _, _ = resolve_canonical_id(metadata)
        self.assertIn('dockstore', canonical_id)


# --- Integration tests (require DB access and GALAXY_ID_SECRET) ---


def _skip_unless_configured(func):
    """Skip test if GALAXY_ID_SECRET or GALAXY_DATABASE_URL not set."""
    def wrapper(self):
        if not GALAXY_ID_SECRET:
            self.skipTest("GALAXY_ID_SECRET not set")
        if not GALAXY_DATABASE_URL:
            self.skipTest("GALAXY_DATABASE_URL not set")
        return func(self)
    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper


class TestIdEncodingRoundTrip(unittest.TestCase):
    """Test Galaxy ID encoding/decoding round-trip."""

    @_skip_unless_configured
    def test_round_trip_small_id(self):
        cipher = Blowfish.new(
            GALAXY_ID_SECRET.encode('utf-8'),
            mode=Blowfish.MODE_ECB,
        )
        original_id = 42
        encoded = encode_galaxy_id(original_id, cipher)
        decoded = decode_galaxy_id(encoded, cipher)
        self.assertEqual(decoded, original_id)

    @_skip_unless_configured
    def test_round_trip_large_id(self):
        cipher = Blowfish.new(
            GALAXY_ID_SECRET.encode('utf-8'),
            mode=Blowfish.MODE_ECB,
        )
        original_id = 9999999
        encoded = encode_galaxy_id(original_id, cipher)
        decoded = decode_galaxy_id(encoded, cipher)
        self.assertEqual(decoded, original_id)

    @_skip_unless_configured
    def test_encoded_id_is_hex_string(self):
        cipher = Blowfish.new(
            GALAXY_ID_SECRET.encode('utf-8'),
            mode=Blowfish.MODE_ECB,
        )
        encoded = encode_galaxy_id(1, cipher)
        self.assertRegex(encoded, r'^[a-f0-9]+$')
        self.assertEqual(len(encoded), 16)


class TestDatabaseLookup(unittest.TestCase):
    """Test workflow lookup against the live Galaxy database."""

    @_skip_unless_configured
    def test_lookup_existing_workflow(self):
        """Fetch a real workflow and verify decode -> DB lookup works."""
        engine = create_engine(GALAXY_DATABASE_URL)
        cipher = Blowfish.new(
            GALAXY_ID_SECRET.encode('utf-8'),
            mode=Blowfish.MODE_ECB,
        )

        with engine.connect() as conn:
            sample = conn.execute(SAMPLE_WORKFLOW_QUERY).fetchone()
            if not sample:
                self.skipTest("No workflows found in database")

            sw_id, name, user_id, uuid, source_metadata = sample
            self.assertIsInstance(sw_id, int)
            self.assertIsInstance(name, str)
            self.assertTrue(len(name) > 0, "Workflow name is empty")

            # Encode the ID and decode it back
            encoded = encode_galaxy_id(sw_id, cipher)
            decoded = decode_galaxy_id(encoded, cipher)
            self.assertEqual(decoded, sw_id)

            # Look up via decoded ID (simulating the real pipeline)
            result = conn.execute(
                WORKFLOW_QUERY,
                {'id': decoded},
            ).fetchone()
            self.assertIsNotNone(result)
            self.assertEqual(result[0], sw_id)
            self.assertEqual(result[1], name)

            print(f"\n  Verified workflow: id={sw_id}, name='{name}'")
            if source_metadata:
                canonical_id, trs_server, version = (
                    resolve_canonical_id(source_metadata)
                )
                print(f"  canonical_id: {canonical_id}")
                print(f"  trs_server: {trs_server}")
                print(f"  trs_version_id: {version}")

    @_skip_unless_configured
    def test_lookup_trs_workflow(self):
        """Find a TRS-imported workflow and verify canonical ID resolution."""
        engine = create_engine(GALAXY_DATABASE_URL)

        with engine.connect() as conn:
            sample = conn.execute(SAMPLE_TRS_WORKFLOW_QUERY).fetchone()
            if not sample:
                self.skipTest(
                    "No TRS-imported workflows found in database")

            sw_id, name, user_id, uuid, source_metadata = sample
            canonical_id, trs_server, version = (
                resolve_canonical_id(source_metadata)
            )

            self.assertTrue(
                len(canonical_id) > 0,
                "canonical_id should not be empty for TRS workflow",
            )
            self.assertTrue(
                len(trs_server) > 0,
                "trs_server should not be empty for TRS workflow",
            )

            print(f"\n  TRS workflow: id={sw_id}, name='{name}'")
            print(f"  canonical_id: {canonical_id}")
            print(f"  trs_server: {trs_server}")
            print(f"  trs_version_id: {version}")

    @_skip_unless_configured
    def test_full_pipeline_with_synthetic_log_line(self):
        """Simulate the full pipeline: log line -> decode -> DB -> resolve."""
        engine = create_engine(GALAXY_DATABASE_URL)
        cipher = Blowfish.new(
            GALAXY_ID_SECRET.encode('utf-8'),
            mode=Blowfish.MODE_ECB,
        )

        with engine.connect() as conn:
            sample = conn.execute(SAMPLE_WORKFLOW_QUERY).fetchone()
            if not sample:
                self.skipTest("No workflows found in database")

            sw_id = sample[0]
            encoded = encode_galaxy_id(sw_id, cipher)

            # Build a synthetic nginx log line
            log_line = (
                '192.168.1.1 - - [27/Feb/2026:10:30:45 +0000] '
                f'"POST /api/workflows/{encoded}/invocations HTTP/1.1" '
                '200 215 '
                '"https://genome.usegalaxy.org.au/workflows/run?id=abc"'
            )

            parsed = parse_log_line(log_line)
            self.assertIsNotNone(parsed)
            self.assertEqual(parsed['encoded_id'], encoded)
            self.assertEqual(
                parsed['domain'], 'genome.usegalaxy.org.au')

            decoded = decode_galaxy_id(parsed['encoded_id'], cipher)
            self.assertEqual(decoded, sw_id)

            result = conn.execute(
                WORKFLOW_QUERY,
                {'id': decoded},
            ).fetchone()
            self.assertIsNotNone(result)

            _, name, user_id, uuid, source_metadata = result
            canonical_id, trs_server, version = (
                resolve_canonical_id(source_metadata)
            )

            print("\n  Full pipeline OK:")
            print(f"    encoded: {encoded}")
            print(f"    decoded: {decoded}")
            print(f"    name: {name}")
            print(f"    canonical_id: {canonical_id or '(local)'}")
            print(f"    domain: {parsed['domain']}")


if __name__ == '__main__':
    unittest.main()
