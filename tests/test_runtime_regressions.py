"""Synthetic regression tests for the first bound-config integration failures.

No live credentials, CLI binaries, GitHub calls or AWS services are used.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.lrcs.runtime import Runtime, StageError, load_config


class BoundConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'disabled.json'
        self.path.write_text('{"deployment_enabled": false}')
        commit = '0123456789abcdef0123456789abcdef01234567'
        policy = {
            'schema_version': '1.0', 'policy_id': 'synthetic',
            'github_cli_version': '2.101.0',
            'oidc_issuer': 'https://token.actions.githubusercontent.com',
            'deny_self_hosted_runners': True,
            'allowed_tuples': [{
                'source_repository': 'synthetic-owner/synthetic-repo',
                'certificate_identity': 'https://github.com/synthetic-owner/synthetic-repo/.github/workflows/release.yml@refs/heads/current',
                'signer_digest': commit, 'source_digest': commit,
                'source_ref': 'refs/heads/current',
                'predicate_type': 'https://slsa.dev/provenance/v1',
            }],
        }
        self.config = {
            'schema_version': '1.0', 'deployment_enabled': True,
            'g4_approved': True, 'region': 'eu-central-1',
            'project_prefix': 'lrcs-20260928', 'account_id': '123456789012',
            'buckets': {
                'artifacts': 'lrcs-20260928-123456789012-eu-central-1-artifacts',
                'signed': 'lrcs-20260928-123456789012-eu-central-1-signed',
            },
            'roles': {
                'build': 'arn:aws:iam::123456789012:role/lrcs-20260928-build-sign',
                'fixtures': 'arn:aws:iam::123456789012:role/lrcs-20260928-fixture-sign',
                'deploy': 'arn:aws:iam::123456789012:role/lrcs-20260928-deploy',
            },
            'policies': {'synthetic': policy},
        }

    def load(self, config):
        with patch.dict(os.environ, {'LRCS_BOUND_CONFIG': json.dumps(config)}, clear=True):
            return load_config(self.path)

    def test_real_role_arn_separator_accepts_complete_bound_config(self):
        self.assertEqual(self.load(self.config), self.config)

    def test_old_colon_separator_and_other_account_are_rejected(self):
        for key in self.config['roles']:
            for replacement in (':role:', ':role/other-'):
                config = copy.deepcopy(self.config)
                config['roles'][key] = config['roles'][key].replace(':role/', replacement)
                with self.subTest(role=key, replacement=replacement):
                    with self.assertRaises(StageError):
                        self.load(config)
        config = copy.deepcopy(self.config)
        config['roles']['deploy'] = config['roles']['deploy'].replace('123456789012', '210987654321')
        with self.assertRaises(StageError):
            self.load(config)


class Clock:
    def __init__(self):
        self.seconds = 1000.0

    def monotonic(self):
        return self.seconds

    def monotonic_ns(self):
        return int(self.seconds * 1_000_000_000)

    def sleep(self, seconds):
        self.seconds += seconds


class SigningDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.clock = Clock()
        self.r = Runtime.__new__(Runtime)
        self.r.d = Path(self.tmp.name)
        self.r.path = self.r.d / 'state.json'
        self.r.artifact = self.r.d / 'final.zip'
        self.r.artifact.write_bytes(b'synthetic unsigned ZIP')
        self.r.s = {
            'needs_signing': True, 'build': {'synthetic': True},
            'workload': 'producer', 'attempt_id': 'synthetic-attempt',
            'inputs': {'fixture_mode': 'valid'},
            'stage_events': [],
            'clock': {'monotonic_ns': self.clock.monotonic_ns()},
        }
        self.r.c = {
            'region': 'eu-central-1',
            'buckets': {'artifacts': 'synthetic-source', 'signed': 'synthetic-signed'},
            'profiles': {'allowed': {'name': 'synthetic_profile', 'version': 'abc123def4'}},
        }
        self.operations = []
        self.polls = 0
        self.head_duration = 10
        self.download_duration = 3
        self.source = None

    def run_cli(self, argv, **kwargs):
        operation = argv[2]
        self.operations.append((operation, kwargs['timeout']))
        if operation == 'get-signing-profile':
            self.clock.seconds += 20
            response = {'profileVersion': 'abc123def4', 'status': 'Active'}
        elif operation == 'put-object':
            self.clock.seconds += 20
            response = {'VersionId': 'source-version'}
        elif operation == 'start-signing-job':
            self.clock.seconds += 20
            self.source = json.loads(argv[argv.index('--source') + 1])
            response = {'jobId': 'synthetic-job'}
        elif operation == 'describe-signing-job':
            self.clock.seconds += 25
            self.polls += 1
            response = {
                'status': 'Succeeded' if self.polls == 4 else 'InProgress',
                'profileName': 'synthetic_profile', 'profileVersion': 'abc123def4',
                'source': self.source,
                'signedObject': {'s3': {'bucketName': 'synthetic-signed',
                                       'key': 'signed/fixtures/synthetic-attempt/output.zip'}},
            }
        elif operation == 'head-object':
            self.clock.seconds += self.head_duration
            response = {'VersionId': 'signed-version'}
        elif operation == 'get-object':
            self.clock.seconds += self.download_duration
            # The positional output path immediately follows --version-id VALUE.
            Path(argv[argv.index('--version-id') + 2]).write_bytes(b'synthetic signed ZIP')
            response = {'VersionId': 'signed-version'}
        else:
            raise AssertionError('Unexpected cloud operation in synthetic test: ' + operation)
        return subprocess.CompletedProcess(argv, 0, json.dumps(response).encode(), b'')

    def sign(self):
        with patch('scripts.lrcs.runtime.time.monotonic', self.clock.monotonic), \
             patch('scripts.lrcs.runtime.time.monotonic_ns', self.clock.monotonic_ns), \
             patch('scripts.lrcs.runtime.time.sleep', self.clock.sleep), \
             patch('scripts.lrcs.runtime.subprocess.run', side_effect=self.run_cli):
            return self.r.sign()

    def test_last_download_gets_only_remaining_shared_budget(self):
        self.sign()
        self.assertEqual(self.operations[-1], ('get-object', 4.0))
        self.assertEqual(self.r.s['signing']['elapsed_seconds'], 179.0)
        self.assertEqual(self.r.artifact.read_bytes(), b'synthetic signed ZIP')
        self.assertEqual(len(self.r.s['stage_events']), len(self.operations))

    def test_deadline_exhausted_by_head_never_starts_download(self):
        self.head_duration = 14
        with self.assertRaises(StageError) as caught:
            self.sign()
        self.assertEqual(caught.exception.reason, 'timeout')
        self.assertNotIn('get-object', [op for op, _ in self.operations])
        self.assertNotIn('output', self.r.s['signing'])
        self.assertEqual(self.r.artifact.read_bytes(), b'synthetic unsigned ZIP')
        event = self.r.s['stage_events'][-1]
        record = json.loads((self.r.d / event['evidence']).read_text())
        self.assertTrue(record['deadline_exceeded_after_response'])

    def test_late_download_cannot_be_reported_as_signing_success(self):
        self.download_duration = 5
        with self.assertRaises(StageError) as caught:
            self.sign()
        self.assertEqual(caught.exception.reason, 'timeout')
        self.assertEqual(self.operations[-1], ('get-object', 4.0))
        self.assertNotIn('output', self.r.s['signing'])
        self.assertEqual(self.r.artifact.read_bytes(), b'synthetic unsigned ZIP')

    def test_expired_deadline_stops_before_cli_launch(self):
        with patch('scripts.lrcs.runtime.time.monotonic', self.clock.monotonic), \
             patch('scripts.lrcs.runtime.time.monotonic_ns', self.clock.monotonic_ns), \
             patch('scripts.lrcs.runtime.subprocess.run') as run:
            with self.assertRaises(StageError) as caught:
                self.r.aws('s3api', 'get-object', [], deadline=self.clock.seconds)
        self.assertEqual(caught.exception.reason, 'timeout')
        run.assert_not_called()
        self.assertEqual(self.r.s['stage_events'], [])

    def test_timeout_journals_exact_partial_bytes_before_raising(self):
        out, err = b'{"partial":"\xff', b'interrupted\r\n\xfe'
        timeout = subprocess.TimeoutExpired(['aws'], 3, output=out, stderr=err)
        with patch('scripts.lrcs.runtime.time.monotonic_ns', self.clock.monotonic_ns), \
             patch('scripts.lrcs.runtime.subprocess.run', side_effect=timeout):
            with self.assertRaises(StageError) as caught:
                self.r.aws('signer', 'describe-signing-job', ['--job-id', 'synthetic-job'], limit=3)
        self.assertEqual(caught.exception.reason, 'timeout')
        record = json.loads((self.r.d / 'aws-0000.json').read_text())
        self.assertTrue(record['timed_out'])
        self.assertIsNone(record['exit_code'])
        self.assertEqual(base64.b64decode(record['stdout_base64']), out)
        self.assertEqual(base64.b64decode(record['stderr_base64']), err)
        self.assertEqual(record['stdout_sha256'], hashlib.sha256(out).hexdigest())
        self.assertEqual(record['stderr_sha256'], hashlib.sha256(err).hexdigest())
        saved = json.loads(self.r.path.read_text())
        self.assertEqual(saved['stage_events'][0]['evidence'], 'aws-0000.json')
        self.assertTrue(saved['stage_events'][0]['timed_out'])


if __name__ == '__main__':
    unittest.main()
