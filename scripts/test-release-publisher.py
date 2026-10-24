"""Draft publication regression tests; no network, accounts or release writes."""
import copy
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('publisher', Path(__file__).with_name('publish-verified-release.py'))
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class PublicationTests(unittest.TestCase):
    def test_cli_metadata_is_decoded_as_utf8_on_windows_too(self):
        original = subprocess.check_output
        payload = '{"name":"سلام"}'.encode('utf-8').hex()

        def cli(args, **kwargs):
            return original([sys.executable, '-c',
                             'import sys;sys.stdout.buffer.write(bytes.fromhex("'+payload+'"))'], **kwargs)

        with patch.object(publisher.subprocess, 'check_output', side_effect=cli):
            self.assertEqual(publisher.gh('api', 'fixture', json_result=True), {'name': 'سلام'})

    def test_draft_discovery_includes_later_pages(self):
        draft = {'id': 42, 'tag_name': 'v2.6.2', 'draft': True}
        with patch.object(publisher, 'gh', return_value=[[{'tag_name': 'v1'}], [draft]]) as call:
            self.assertEqual(publisher.find_release('owner/repo', 'v2.6.2'), draft)
            self.assertIn('--paginate', call.call_args.args)
            self.assertNotIn('/tags/', call.call_args.args[1])

    def test_discovery_errors_do_not_become_missing_releases(self):
        with patch.object(publisher, 'gh', side_effect=subprocess.CalledProcessError(1, 'gh')):
            with self.assertRaises(subprocess.CalledProcessError):
                publisher.find_release('owner/repo', 'v2.6.2')

    def test_missing_release_is_created_as_a_draft_before_upload(self):
        with tempfile.TemporaryDirectory() as folder:
            assets = Path(folder)
            (assets/'artifact.zip').write_bytes(b'fixture')
            draft = {'id': 42, 'tag_name': 'v2.6.2', 'draft': True,
                     'target_commitish': 'a'*40, 'assets': [], 'html_url': 'https://example.invalid/release'}
            calls, exists = [], False

            def github(*args, **kwargs):
                nonlocal exists
                calls.append(args)
                if args[0] == 'api':
                    if args[1].endswith('/releases'): return [[copy.deepcopy(draft)]] if exists else [[]]
                    return copy.deepcopy(draft)
                if args[:2] == ('release', 'create'):
                    self.assertIn('--draft', args)
                    self.assertEqual(args[args.index('--target')+1], 'a'*40)
                    exists = True
                if args[:2] == ('release', 'upload'):
                    self.assertTrue(exists and draft['draft'])
                    draft['assets'] = [{'name': 'artifact.zip', 'state': 'uploaded',
                                        'digest': 'sha256:'+publisher.digest(b'fixture')}]
                if args[:2] == ('release', 'edit'): draft['draft'] = False
                return ''

            with patch.object(publisher, 'gh', side_effect=github):
                publisher.publish_assets('owner/repo', 'v2.6.2', 'a'*40, assets, assets/'notes')
            self.assertEqual(sum(c[:2] == ('release', 'create') for c in calls), 1)
            self.assertEqual(sum(c[:2] == ('release', 'upload') for c in calls), 1)

    def test_draft_publication_requires_complete_uploaded_hashes(self):
        for failure in [None, 'digest', 'missing', 'extra', 'state', 'commit', 'published']:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as folder:
                assets = Path(folder)
                (assets/'artifact.zip').write_bytes(b'fixture artifact, not an executable')
                draft = {'id': 42, 'tag_name': 'v2.6.2', 'draft': True, 'target_commitish': 'a'*40,
                         'html_url': 'https://example.invalid/release', 'assets': [
                             {'name': 'artifact.zip', 'state': 'uploaded',
                              'digest': 'sha256:'+publisher.digest((assets/'artifact.zip').read_bytes())}]}
                if failure == 'digest': draft['assets'][0]['digest'] = 'sha256:'+'0'*64
                if failure == 'missing': draft['assets'] = []
                if failure == 'extra': draft['assets'].append({'name': 'unreviewed', 'state': 'uploaded', 'digest': 'x'})
                if failure == 'state': draft['assets'][0]['state'] = 'starter'
                if failure == 'commit': draft['target_commitish'] = 'b'*40
                if failure == 'published': draft['draft'] = False
                calls = []

                def github(*args, **kwargs):
                    calls.append(args)
                    self.assertFalse(any('/tags/' in str(a) for a in args))
                    if args[0] == 'api':
                        if args[1].endswith('/releases'): return [[copy.deepcopy(draft)]]
                        self.assertTrue(args[1].endswith('/releases/42'))
                        return copy.deepcopy(draft)
                    if args[:2] == ('release', 'edit'): draft['draft'] = False
                    return ''

                with patch.object(publisher, 'gh', side_effect=github):
                    if failure:
                        with self.assertRaises(AssertionError):
                            publisher.publish_assets('owner/repo', 'v2.6.2', 'a'*40, assets, assets/'notes')
                        self.assertFalse(any(c[:2] == ('release', 'edit') for c in calls))
                    else:
                        publisher.publish_assets('owner/repo', 'v2.6.2', 'a'*40, assets, assets/'notes')
                        self.assertEqual(sum(c[:2] == ('release', 'edit') for c in calls), 1)


if __name__ == '__main__':
    unittest.main()
