"""Sigillum falsum, limites et viae fallaces reiciuntur."""
import contextlib
import copy
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from vestigium_integrity import core, seal
from vestigium_integrity.cli import main


class SealTests(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(32)
        self.manifest = {'schema': core.SCHEMA, 'algorithm': 'sha256', 'entries': [{'path': 'note.txt', 'type': 'file', 'size': 4, 'sha256': hashlib.sha256(b'note').hexdigest()}]}
        self.envelope = seal.create_seal(self.manifest, self.key)

    def test_authentic_roundtrip_and_standard_hmac_payload(self):
        self.assertEqual(seal.verify_seal(self.envelope, self.key), self.manifest)
        payload = {k: v for k, v in self.envelope.items() if k != 'tag'}
        expected = hmac.new(self.key, core.canonical_json(payload), hashlib.sha256).hexdigest()
        self.assertEqual(self.envelope['tag'], expected)
        self.assertEqual(seal.create_seal(self.manifest, self.key), self.envelope)

    def test_wrong_key_and_each_tampered_manifest_field(self):
        with self.assertRaises(seal.AuthenticationError):
            seal.verify_seal(self.envelope, os.urandom(32))
        for field, value in [('path', 'other.txt'), ('size', 99), ('sha256', '0' * 64)]:
            altered = copy.deepcopy(self.envelope)
            altered['manifest']['entries'][0][field] = value
            with self.subTest(field=field), self.assertRaises(seal.AuthenticationError):
                seal.verify_seal(altered, self.key)

    def test_strict_envelope_and_tag(self):
        for field, value in [('schema', 'other/v1'), ('algorithm', 'sha1'), ('tag', 'g' * 64), ('tag', []), ('extra', 'unexpected')]:
            altered = copy.deepcopy(self.envelope)
            altered[field] = value
            with self.assertRaises(core.ManifestError):
                seal.verify_seal(altered, self.key)
        altered = copy.deepcopy(self.envelope)
        altered['tag'] = '0' * 64
        with self.assertRaises(seal.AuthenticationError):
            seal.verify_seal(altered, self.key)

    def test_path_traversal_and_hierarchy_rejected_before_authentication(self):
        for path in ['../private', '/private', 'C:/private', 'a/../../b', 'a/child', 'x' * 4097]:
            altered = copy.deepcopy(self.envelope)
            altered['manifest']['entries'][0]['path'] = path
            with self.subTest(path=path), self.assertRaises(core.ManifestError):
                seal.verify_seal(altered, self.key)

    def test_key_bounds_and_public_permissions(self):
        for key in [b'', b'x' * 31, b'x' * 4097, 'x' * 32]:
            with self.assertRaises(core.IntegrityError):
                seal.create_seal(self.manifest, key)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'key'
            path.write_bytes(self.key)
            path.chmod(0o644)
            with self.assertRaises(core.IntegrityError):
                seal.load_key(path)
            path.chmod(0o600)
            self.assertEqual(seal.load_key(path), self.key)
            path.write_bytes(b'x' * 4097)
            with self.assertRaises(core.IntegrityError):
                seal.load_key(path)

    def test_special_files_symlinks_and_private_error_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'key'
            target.write_bytes(self.key)
            target.chmod(0o600)
            link = Path(folder) / 'private-link'
            link.symlink_to(target)
            pipe = Path(folder) / 'private-pipe'
            os.mkfifo(pipe)
            for path in [link, pipe, Path(folder) / 'private-missing']:
                with self.assertRaises(core.IntegrityError) as caught:
                    seal.load_key(path)
                self.assertNotIn(folder, str(caught.exception))
                self.assertNotIn('private-', str(caught.exception))

    def test_duplicate_json_nonfinite_nesting_and_byte_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'seal.json'
            for data in [b'{"tag":"a","tag":"b"}', b'{"tag":NaN}', b'[' * 2000 + b']' * 2000, b'\xff']:
                path.write_bytes(data)
                with self.assertRaises(core.IntegrityError):
                    seal.load_seal(path)
            path.write_bytes(core.canonical_json(self.envelope))
            with patch.object(seal, 'MAX_SEAL_BYTES', 8), self.assertRaises(core.IntegrityError):
                seal.load_seal(path)

    def test_manifest_item_size_and_target_bounds(self):
        with patch.object(core, 'MAX_ENTRIES', 0), self.assertRaises(core.ManifestError):
            core.validate_manifest(self.manifest)
        for size in [True, -1, 2**63]:
            value = copy.deepcopy(self.manifest)
            value['entries'][0]['size'] = size
            with self.assertRaises(core.ManifestError):
                core.validate_manifest(value)
        value = copy.deepcopy(self.manifest)
        value['entries'] = [{'path': 'link', 'type': 'symlink', 'target': 'x' * 65537}]
        with self.assertRaises(core.ManifestError):
            core.validate_manifest(value)

    def test_atomic_new_output_permissions_and_no_key_storage(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'seal.json'
            seal.write_seal(output, self.envelope)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            data = output.read_bytes()
            self.assertNotIn(self.key, data)
            self.assertNotIn(self.key.hex().encode(), data)
            with self.assertRaises(core.IntegrityError):
                seal.write_seal(output, self.envelope)
            self.assertEqual(output.read_bytes(), data)
            self.assertEqual(list(Path(folder).iterdir()), [output])

    def test_offline_diff_does_not_open_manifest_paths(self):
        after = copy.deepcopy(self.manifest)
        after['entries'][0]['sha256'] = '0' * 64
        after['entries'].append({'path': 'new', 'type': 'directory'})
        with patch('socket.socket', side_effect=AssertionError('network')), patch('builtins.open', side_effect=AssertionError('file')):
            result = seal.diff_manifests(self.manifest, after)
        self.assertEqual(result['status'], 'different')
        self.assertEqual(result['changes']['added'], ['new'])
        self.assertEqual(result['changes']['changed'][0]['reasons'], ['sha256'])
        self.assertEqual(result['changes']['changed'][0]['before']['sha256'], self.manifest['entries'][0]['sha256'])
        self.assertEqual(seal.diff_manifests(self.manifest, self.manifest)['status'], 'clean')
        self.assertEqual(seal.diff_manifests(after, self.manifest)['changes']['missing'], ['new'])

    def test_cli_end_to_end_exit_codes_and_privacy(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest, key, output = root / 'manifest.json', root / 'key', root / 'sealed.json'
            manifest.write_bytes(core.canonical_json(self.manifest))
            key.write_bytes(self.key)
            key.chmod(0o600)
            def run(*args):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = main([str(a) for a in args] + ['--json'])
                self.assertNotIn(folder, out.getvalue())
                self.assertNotIn(self.key.hex(), out.getvalue())
                return code, json.loads(out.getvalue())
            self.assertEqual(run('seal', manifest, '--key-file', key, '--output', output)[0], 0)
            code, report = run('verify-seal', output, '--key-file', key)
            self.assertEqual(code, 0)
            self.assertFalse(report['author_identity_verified'])
            self.assertFalse(report['filesystem_verified'])
            key.write_bytes(os.urandom(32))
            self.assertEqual(run('verify-seal', output, '--key-file', key)[0], 1)
            self.assertEqual(run('verify-seal', root / 'missing', '--key-file', key)[0], 2)
            self.assertEqual(run('diff', manifest, manifest)[0], 0)
            changed = copy.deepcopy(self.manifest)
            changed['entries'] = []
            second = root / 'after.json'
            second.write_bytes(core.canonical_json(changed))
            self.assertEqual(run('diff', manifest, second)[0], 1)

    def test_authenticated_directory_verification_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'source'
            source.mkdir()
            (source / 'note.txt').write_bytes(b'note')
            key, envelope = root / 'key', root / 'seal.json'
            key.write_bytes(self.key)
            key.chmod(0o600)
            seal.write_seal(envelope, self.envelope)
            def run():
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = main(['verify-seal', str(envelope), '--key-file', str(key), '--source', str(source), '--json'])
                return code, json.loads(out.getvalue())
            code, report = run()
            self.assertEqual(code, 0)
            self.assertTrue(report['filesystem_verified'])
            self.assertFalse(report['author_identity_verified'])
            (source / 'note.txt').write_bytes(b'edit')
            code, report = run()
            self.assertEqual(code, 1)
            self.assertFalse(report['filesystem_verified'])
            with patch('vestigium_integrity.cli.scan_directory', return_value=core.ScanResult([], [{'path': '.', 'code': 'unreadable', 'message': 'Unavailable'}])):
                code, report = run()
            self.assertEqual(code, 2)
            self.assertIsNone(report['changes'])
            key.write_bytes(os.urandom(32))
            with patch('vestigium_integrity.cli.scan_directory', side_effect=AssertionError('Unauthenticated manifest used')):
                self.assertEqual(run()[0], 1)


if __name__ == '__main__':
    unittest.main()
