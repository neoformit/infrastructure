"""Unit tests for collect_workflow_invocations.

Run from the workflows_reporting directory:

    python -m unittest test_collect_workflow_invocations.py
"""

import gzip
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

# Module-level env vars must be present before importing the script.
os.environ.setdefault('GALAXY_ID_SECRET', 'testsecr')
os.environ.setdefault('GALAXY_DATABASE_URL', 'sqlite:///:memory:')
os.environ.setdefault('INFLUX_URL', 'http://influx.test:8086')
os.environ.setdefault('INFLUX_DB', 'testdb')
os.environ.setdefault('INFLUX_TOKEN', 'token:abc')
os.environ.setdefault('S3_BUCKET', 'test-bucket')
os.environ.setdefault('S3_PREFIX', 'logs/')
os.environ.setdefault('S3_ACCESS_KEY', 'AKIATEST')
os.environ.setdefault('S3_SECRET_KEY', 'secret')
os.environ.setdefault('S3_REGION', 'us-east-1')

from Crypto.Cipher import Blowfish  # noqa: E402

import collect_workflow_invocations as ci  # noqa: E402


def encode_galaxy_id(obj_id: int, secret: str) -> str:
    """Encode an integer ID the same way Galaxy's IdEncodingHelper does.

    Pads the stringified id on the left with `!` to a multiple of 8
    bytes, encrypts with Blowfish ECB, and hex-encodes the result.
    """
    cipher = Blowfish.new(secret.encode('utf-8'), mode=Blowfish.MODE_ECB)
    s = str(obj_id)
    pad = (8 - len(s) % 8) % 8
    padded = ('!' * pad) + s
    return cipher.encrypt(padded.encode('utf-8')).hex()


# ---------------------------------------------------------------------
# decode_galaxy_id
# ---------------------------------------------------------------------

class DecodeGalaxyIdTests(unittest.TestCase):
    def setUp(self):
        self.cipher = Blowfish.new(
            ci.GALAXY_ID_SECRET.encode('utf-8'),
            mode=Blowfish.MODE_ECB,
        )

    def test_round_trip(self):
        for original in (1, 42, 12345, 99999999):
            encoded = encode_galaxy_id(original, ci.GALAXY_ID_SECRET)
            self.assertEqual(
                ci.decode_galaxy_id(encoded, self.cipher), original)

    def test_invalid_hex_raises(self):
        with self.assertRaises(ValueError):
            ci.decode_galaxy_id('zzzz', self.cipher)


# ---------------------------------------------------------------------
# parse_json_log_line
# ---------------------------------------------------------------------

def make_log_line(request, timestamp='2026-04-07T00:01:02Z',
                  referer='https://galaxy.example.org/workflows/run'):
    return json.dumps({
        'parsed': {
            'request': request,
            'timestamp': timestamp,
            'referer': referer,
        },
    })


class ParseJsonLogLineTests(unittest.TestCase):
    def test_valid_invocation(self):
        line = make_log_line(
            'POST /api/workflows/abc123def456/invocations HTTP/1.1')
        result = ci.parse_json_log_line(line)
        self.assertEqual(result['encoded_id'], 'abc123def456')
        self.assertEqual(result['domain'], 'galaxy.example.org')
        self.assertEqual(
            result['datetime'], datetime(2026, 4, 7, 0, 1, 2))

    def test_non_invocation_request_returns_none(self):
        line = make_log_line('GET /api/version HTTP/1.1')
        self.assertIsNone(ci.parse_json_log_line(line))

    def test_malformed_json_returns_none(self):
        self.assertIsNone(ci.parse_json_log_line('not json{'))

    def test_missing_parsed_returns_none(self):
        self.assertIsNone(ci.parse_json_log_line(json.dumps({})))

    def test_missing_timestamp_returns_none(self):
        line = json.dumps({
            'parsed': {
                'request': 'POST /api/workflows/abc/invocations HTTP/1.1',
                'referer': '',
            },
        })
        self.assertIsNone(ci.parse_json_log_line(line))

    def test_invalid_timestamp_returns_none(self):
        line = make_log_line(
            'POST /api/workflows/abc/invocations HTTP/1.1',
            timestamp='not-a-time',
        )
        self.assertIsNone(ci.parse_json_log_line(line))

    def test_unknown_domain_when_referer_missing(self):
        line = make_log_line(
            'POST /api/workflows/abc/invocations HTTP/1.1',
            referer='',
        )
        result = ci.parse_json_log_line(line)
        self.assertEqual(result['domain'], 'unknown')


# ---------------------------------------------------------------------
# resolve_canonical_id
# ---------------------------------------------------------------------

class ResolveCanonicalIdTests(unittest.TestCase):
    def test_empty_metadata(self):
        self.assertEqual(ci.resolve_canonical_id(None), ('', '', ''))
        self.assertEqual(ci.resolve_canonical_id({}), ('', '', ''))

    def test_string_metadata_parsed_as_json(self):
        meta = json.dumps({'trs_tool_id': 'foo', 'trs_server': 'dockstore',
                           'trs_version_id': 'v1'})
        self.assertEqual(
            ci.resolve_canonical_id(meta),
            ('dockstore:foo', 'dockstore', 'v1'),
        )

    def test_trs_without_server(self):
        self.assertEqual(
            ci.resolve_canonical_id({'trs_tool_id': 'foo'}),
            ('foo', '', ''),
        )

    def test_url_fallback(self):
        self.assertEqual(
            ci.resolve_canonical_id({'url': 'https://example.org/wf.ga'}),
            ('https://example.org/wf.ga', '', ''),
        )

    def test_no_useful_metadata(self):
        self.assertEqual(
            ci.resolve_canonical_id({'other_field': 'x'}),
            ('', '', ''),
        )


# ---------------------------------------------------------------------
# escape_tag_value / escape_field_string
# ---------------------------------------------------------------------

class EscapeHelpersTests(unittest.TestCase):
    def test_escape_tag_value(self):
        self.assertEqual(
            ci.escape_tag_value('a b,c=d\\e'),
            'a\\ b\\,c\\=d\\\\e',
        )

    def test_escape_tag_value_plain(self):
        self.assertEqual(ci.escape_tag_value('plain'), 'plain')

    def test_escape_field_string(self):
        self.assertEqual(
            ci.escape_field_string('hello "world"\\test'),
            'hello \\"world\\"\\\\test',
        )


# ---------------------------------------------------------------------
# format_line_protocol
# ---------------------------------------------------------------------

class FormatLineProtocolTests(unittest.TestCase):
    def test_mixed_field_types(self):
        ts = datetime(2026, 4, 7, 0, 0, 0, tzinfo=timezone.utc)
        line = ci.format_line_protocol(
            measurement='m',
            tags={'host': 'a b'},
            fields={'f_float': 1.5, 'f_int': 7, 'f_str': 'x'},
            timestamp=ts,
        )
        expected_ts = int(ts.timestamp())
        self.assertEqual(
            line,
            f'm,host=a\\ b f_float=1.5,f_int=7i,f_str="x" {expected_ts}',
        )


# ---------------------------------------------------------------------
# read_last_key / save_last_key
# ---------------------------------------------------------------------

class StateFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state_path = Path(self.tmp.name) / '.collect_state'
        self._patch = mock.patch.object(ci, 'STATE_FILE', self.state_path)
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def test_read_when_missing_returns_empty(self):
        self.assertEqual(ci.read_last_key(), '')

    def test_round_trip(self):
        ci.save_last_key('logs/2026-04-07-foo.log')
        self.assertEqual(ci.read_last_key(), 'logs/2026-04-07-foo.log')


# ---------------------------------------------------------------------
# make_s3_client
# ---------------------------------------------------------------------

class MakeS3ClientTests(unittest.TestCase):
    def test_passes_swift_compatible_config(self):
        with mock.patch.object(ci.boto3, 'client') as boto_client:
            ci.make_s3_client()
            boto_client.assert_called_once()
            kwargs = boto_client.call_args.kwargs
            self.assertEqual(boto_client.call_args.args, ('s3',))
            self.assertEqual(kwargs['aws_access_key_id'], ci.S3_ACCESS_KEY)
            self.assertEqual(
                kwargs['aws_secret_access_key'], ci.S3_SECRET_KEY)
            self.assertEqual(kwargs['region_name'], ci.S3_REGION)
            config = kwargs['config']
            self.assertEqual(config.signature_version, 's3v4')
            self.assertEqual(
                config.s3.get('addressing_style'), 'path')


# ---------------------------------------------------------------------
# list_new_objects
# ---------------------------------------------------------------------

class ListNewObjectsTests(unittest.TestCase):
    def _make_client(self, pages):
        paginator = mock.Mock()
        paginator.paginate.return_value = iter(pages)
        client = mock.Mock()
        client.get_paginator.return_value = paginator
        return client, paginator

    def test_no_last_key_omits_start_after(self):
        pages = [{'Contents': [{'Key': 'logs/b.log'},
                               {'Key': 'logs/a.log'}]}]
        client, paginator = self._make_client(pages)
        keys = ci.list_new_objects(client, '')
        self.assertEqual(keys, ['logs/a.log', 'logs/b.log'])
        paginator.paginate.assert_called_once_with(
            Bucket=ci.S3_BUCKET, Prefix=ci.S3_PREFIX)

    def test_with_last_key_passes_start_after(self):
        pages = [{'Contents': [{'Key': 'logs/c.log'}]}]
        client, paginator = self._make_client(pages)
        keys = ci.list_new_objects(client, 'logs/b.log')
        self.assertEqual(keys, ['logs/c.log'])
        paginator.paginate.assert_called_once_with(
            Bucket=ci.S3_BUCKET, Prefix=ci.S3_PREFIX,
            StartAfter='logs/b.log')

    def test_empty_pages(self):
        client, _ = self._make_client([{}])
        self.assertEqual(ci.list_new_objects(client, ''), [])


# ---------------------------------------------------------------------
# fetch_object_lines
# ---------------------------------------------------------------------

class FetchObjectLinesTests(unittest.TestCase):
    def test_yields_decompressed_lines(self):
        raw = b'line one\nline two\n'
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode='wb') as gz:
            gz.write(raw)
        body = mock.Mock()
        body.read.return_value = buf.getvalue()
        client = mock.Mock()
        client.get_object.return_value = {'Body': body}

        lines = list(ci.fetch_object_lines(client, 'logs/x.log'))
        self.assertEqual(lines, ['line one\n', 'line two\n'])
        client.get_object.assert_called_once_with(
            Bucket=ci.S3_BUCKET, Key='logs/x.log')


# ---------------------------------------------------------------------
# write_to_influxdb
# ---------------------------------------------------------------------

class WriteToInfluxdbTests(unittest.TestCase):
    def test_posts_payload(self):
        fake_resp = mock.MagicMock()
        fake_resp.__enter__.return_value.status = 204
        with mock.patch.object(
                ci.urllib.request, 'urlopen', return_value=fake_resp) as up:
            ci.write_to_influxdb(['m,t=1 v=1 1000', 'm,t=1 v=2 2000'])
        up.assert_called_once()
        req = up.call_args.args[0]
        self.assertEqual(req.data, b'm,t=1 v=1 1000\nm,t=1 v=2 2000')
        self.assertEqual(
            req.full_url, f'{ci.INFLUX_URL}/write?db={ci.INFLUX_DB}')
        self.assertEqual(
            req.headers['Authorization'], f'Token {ci.INFLUX_TOKEN}')

    def test_url_error_exits(self):
        with mock.patch.object(
                ci.urllib.request, 'urlopen',
                side_effect=ci.urllib.error.URLError('boom')):
            with self.assertRaises(SystemExit):
                ci.write_to_influxdb(['m,t=1 v=1 1000'])


# ---------------------------------------------------------------------
# process_line
# ---------------------------------------------------------------------

class ProcessLineTests(unittest.TestCase):
    def setUp(self):
        self.cipher = Blowfish.new(
            ci.GALAXY_ID_SECRET.encode('utf-8'),
            mode=Blowfish.MODE_ECB,
        )
        self.workflow_id = 4242
        self.encoded = encode_galaxy_id(
            self.workflow_id, ci.GALAXY_ID_SECRET)
        self.line = make_log_line(
            f'POST /api/workflows/{self.encoded}/invocations HTTP/1.1')

    def _make_conn(self, row):
        result = mock.Mock()
        result.fetchone.return_value = row
        conn = mock.Mock()
        conn.execute.return_value = result
        return conn

    def test_happy_path(self):
        conn = self._make_conn(
            (self.workflow_id, 'My WF', 7, 'uuid-x',
             {'trs_tool_id': 'foo', 'trs_server': 'ds', 'trs_version_id': '1'})
        )
        out = ci.process_line(self.line, conn, self.cipher)
        self.assertIsNotNone(out)
        self.assertIn('workflow_name=My\\ WF', out)
        self.assertIn('canonical_id=ds:foo', out)
        self.assertIn('trs_server=ds', out)
        self.assertIn('workflow_id=4242i', out)
        self.assertIn('user_id=7i', out)

    def test_returns_none_for_non_invocation(self):
        line = make_log_line('GET / HTTP/1.1')
        conn = self._make_conn(None)
        self.assertIsNone(ci.process_line(line, conn, self.cipher))
        conn.execute.assert_not_called()

    def test_returns_none_when_db_miss(self):
        conn = self._make_conn(None)
        self.assertIsNone(ci.process_line(self.line, conn, self.cipher))

    def test_returns_none_on_decode_failure(self):
        bad_line = make_log_line(
            'POST /api/workflows/deadbeef/invocations HTTP/1.1')
        conn = self._make_conn(None)
        # 'deadbeef' is valid hex but won't decrypt to a valid integer.
        self.assertIsNone(ci.process_line(bad_line, conn, self.cipher))


# ---------------------------------------------------------------------
# main
# ---------------------------------------------------------------------

class MainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        state_path = Path(self.tmp.name) / '.collect_state'
        self._patches = [
            mock.patch.object(ci, 'STATE_FILE', state_path),
            mock.patch.object(ci, 'make_s3_client', return_value=mock.Mock()),
            mock.patch.object(ci, 'create_engine'),
            mock.patch.object(ci, 'write_to_influxdb'),
            mock.patch.object(ci, 'fetch_object_lines'),
            mock.patch.object(ci, 'list_new_objects'),
            mock.patch.object(ci, 'process_line'),
        ]
        self.mocks = {p.attribute: p.start() for p in self._patches}
        for p in self._patches:
            self.addCleanup(p.stop)
        self.state_path = state_path

    def test_no_new_keys_does_nothing(self):
        self.mocks['list_new_objects'].return_value = []
        ci.main()
        self.mocks['write_to_influxdb'].assert_not_called()
        self.assertFalse(self.state_path.exists())

    def test_processes_keys_writes_influx_and_saves_state(self):
        self.mocks['list_new_objects'].return_value = ['logs/a', 'logs/b']
        self.mocks['fetch_object_lines'].return_value = iter(['line\n'])
        self.mocks['process_line'].return_value = 'm,t=1 v=1 1000'
        ci.main()
        self.mocks['write_to_influxdb'].assert_called_once()
        # Saved state advances to last processed key
        self.assertEqual(self.state_path.read_text().strip(), 'logs/b')

    def test_list_failure_exits(self):
        self.mocks['list_new_objects'].side_effect = ci.BotoCoreError()
        with self.assertRaises(SystemExit):
            ci.main()
        self.mocks['write_to_influxdb'].assert_not_called()

    def test_fetch_failure_breaks_loop_but_advances_state(self):
        self.mocks['list_new_objects'].return_value = ['logs/a', 'logs/b']
        # First call yields one line; second raises.
        self.mocks['fetch_object_lines'].side_effect = [
            iter(['line\n']),
            ci.BotoCoreError(),
        ]
        self.mocks['process_line'].return_value = 'm,t=1 v=1 1000'
        ci.main()
        # 'a' processed successfully; 'b' failed before completion.
        self.assertEqual(self.state_path.read_text().strip(), 'logs/a')


if __name__ == '__main__':
    unittest.main()
