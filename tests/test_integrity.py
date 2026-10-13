import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from vestigium_integrity import core
from vestigium_integrity.cli import main


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.source = self.base / "evidence"
        self.source.mkdir()
        (self.source / "note.txt").write_bytes(b"Initial observation.\n")
        (self.source / "archive").mkdir()
        (self.source / "archive" / "data.bin").write_bytes(b"\x00\xff\x01")
        (self.source / "empty").mkdir()
        self.manifest = self.base / "baseline.json"

    def call(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main([str(arg) for arg in args] + ["--json"])
        return code, json.loads(output.getvalue())

    def snapshot(self):
        code, report = self.call("snapshot", self.source, "--output", self.manifest)
        self.assertEqual(code, 0, report)
        self.assertEqual(report["status"], "ok")
        return core.load_manifest(self.manifest)

    def test_snapshot_verify_and_expected_digest(self):
        baseline = self.snapshot()
        file_entry = next(item for item in baseline["entries"] if item["path"] == "note.txt")
        self.assertEqual(file_entry["sha256"], hashlib.sha256(b"Initial observation.\n").hexdigest())
        self.assertEqual(file_entry["size"], 21)
        code, report = self.call("verify", self.source, self.manifest)
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "clean")
        self.assertEqual(report["summary"], {"files": 2, "directories": 2, "symlinks": 0, "bytes": 24})
        self.assertEqual(report["changes"], {"added": [], "missing": [], "changed": []})

    def test_detects_same_size_tamper_added_and_missing(self):
        self.snapshot()
        (self.source / "note.txt").write_bytes(b"Altered observation.\n")
        (self.source / "archive" / "data.bin").unlink()
        (self.source / "new.txt").write_bytes(b"Additional record.\n")
        code, report = self.call("verify", self.source, self.manifest)
        self.assertEqual(code, 1)
        self.assertEqual(report["status"], "different")
        self.assertTrue(report["complete"])
        self.assertEqual(report["changes"]["added"], ["new.txt"])
        self.assertEqual(report["changes"]["missing"], ["archive/data.bin"])
        self.assertEqual(report["changes"]["changed"][0]["path"], "note.txt")
        self.assertEqual(report["changes"]["changed"][0]["reasons"], ["sha256"])

    def test_detects_empty_directory_and_type_changes(self):
        self.snapshot()
        (self.source / "empty").rmdir()
        (self.source / "empty").write_bytes(b"Now a file.")
        (self.source / "new-empty").mkdir()
        code, report = self.call("verify", self.source, self.manifest)
        self.assertEqual(code, 1)
        self.assertEqual(report["changes"]["added"], ["new-empty"])
        self.assertEqual(report["changes"]["changed"], [{"path": "empty", "reasons": ["type"], "expected_type": "directory", "actual_type": "file"}])

    def test_output_is_deterministic_and_timestamp_independent(self):
        self.snapshot()
        first = self.manifest.read_bytes()
        timestamp = (self.source / "note.txt").stat().st_mtime_ns
        os.utime(self.source / "note.txt", ns=(timestamp, timestamp + 10_000_000))
        second = self.base / "second.json"
        code, report = self.call("snapshot", self.source, "--output", second)
        self.assertEqual(code, 0, report)
        self.assertEqual(first, second.read_bytes())
        self.assertEqual(first, core.canonical_json(json.loads(first)))
        code, report = self.call("verify", self.source, self.manifest)
        self.assertEqual(code, 0, report)

    def test_source_can_move_without_invalidating_relative_paths(self):
        self.snapshot()
        moved = self.base / "moved"
        self.source.rename(moved)
        code, report = self.call("verify", moved, self.manifest)
        self.assertEqual(code, 0, report)

    def test_output_inside_source_is_rejected_before_scan(self):
        destination = self.source / "manifest.json"
        with mock.patch.object(core, "_walk_directory") as walk:
            code, report = self.call("snapshot", self.source, "--output", destination)
        self.assertEqual(code, 2)
        self.assertFalse(destination.exists())
        self.assertFalse(report["complete"])
        walk.assert_not_called()

    def test_existing_output_is_never_overwritten(self):
        self.snapshot()
        original = self.manifest.read_bytes()
        (self.source / "note.txt").write_bytes(b"New contents.")
        code, report = self.call("snapshot", self.source, "--output", self.manifest)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "error")
        self.assertEqual(self.manifest.read_bytes(), original)

    def test_traversal_absolute_and_ambiguous_paths_are_rejected(self):
        invalid = ("../escape", "/absolute", "folder/../escape", "./note", "a//b", "a/", "C:/escape", "C:escape", "folder\\escape", "bad\x00name")
        for path in invalid:
            with self.subTest(path=path):
                payload = {"schema": core.SCHEMA, "algorithm": "sha256", "entries": [{"path": path, "type": "directory"}]}
                self.manifest.write_bytes(core.canonical_json(payload))
                code, report = self.call("verify", self.source, self.manifest)
                self.assertEqual(code, 2)
                self.assertEqual(report["status"], "error")
                self.assertFalse(report["complete"])

    def test_duplicate_paths_fields_and_missing_ancestors_are_rejected(self):
        baseline = self.snapshot()
        baseline["entries"].append(dict(baseline["entries"][0]))
        with self.assertRaises(core.ManifestError):
            core.validate_manifest(baseline)
        self.manifest.write_text('{"schema":"vestigium-integrity/v1","algorithm":"sha256","entries":[],"entries":[]}', encoding="utf-8")
        with self.assertRaises(core.ManifestError):
            core.load_manifest(self.manifest)
        with self.assertRaises(core.ManifestError):
            core.validate_manifest({"schema": core.SCHEMA, "algorithm": "sha256", "entries": [{"path": "absent/child", "type": "directory"}]})

    def test_invalid_schema_and_sizes_are_rejected(self):
        baseline = self.snapshot()
        cases = [None, [], {"schema": core.SCHEMA}, {**baseline, "algorithm": "md5"}, {**baseline, "unexpected": 1}]
        file_entry = next(item for item in baseline["entries"] if item["type"] == "file")
        for size in (-1, True, "1", 1.5):
            cases.append({"schema": core.SCHEMA, "algorithm": "sha256", "entries": [{**file_entry, "path": "file", "size": size}]})
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(core.ManifestError):
                core.validate_manifest(payload)

    def test_invalid_json_is_an_error_not_a_traceback(self):
        for data in (b"not json", b"\xff", b'{"entries":'):
            self.manifest.write_bytes(data)
            code, report = self.call("verify", self.source, self.manifest)
            self.assertEqual(code, 2)
            self.assertEqual(report["status"], "error")

    @unittest.skipUnless(hasattr(os, "symlink"), "Symbolic links are unavailable.")
    def test_symlinks_are_recorded_and_never_followed(self):
        outside = self.base / "outside"
        outside.mkdir()
        secret = outside / "unrelated.txt"
        secret.write_bytes(b"Outside the scan.")
        (self.source / "external-directory").symlink_to(outside, target_is_directory=True)
        (self.source / "external-file").symlink_to(secret)
        (self.source / "broken-link").symlink_to("missing-target")
        baseline = self.snapshot()
        paths = {item["path"] for item in baseline["entries"]}
        self.assertNotIn("external-directory/unrelated.txt", paths)
        self.assertEqual(sum(item["type"] == "symlink" for item in baseline["entries"]), 3)
        secret.write_bytes(b"Changed outside the scan.")
        code, report = self.call("verify", self.source, self.manifest)
        self.assertEqual(code, 0, report)
        (self.source / "external-file").unlink()
        (self.source / "external-file").symlink_to("other-target")
        code, report = self.call("verify", self.source, self.manifest)
        self.assertEqual(code, 1)
        self.assertEqual(report["changes"]["changed"][0]["reasons"], ["target"])

    def test_source_and_manifest_symlinks_are_rejected(self):
        self.snapshot()
        alias = self.base / "source-link"
        alias.symlink_to(self.source, target_is_directory=True)
        code, report = self.call("verify", alias, self.manifest)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "incomplete")
        reference_alias = self.base / "manifest-link"
        reference_alias.symlink_to(self.manifest)
        code, report = self.call("verify", self.source, reference_alias)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "error")

    def test_output_parent_symlink_into_source_is_rejected(self):
        alias = self.base / "source-link"
        alias.symlink_to(self.source, target_is_directory=True)
        code, report = self.call("snapshot", self.source, "--output", alias / "baseline.json")
        self.assertEqual(code, 2)
        self.assertFalse((self.source / "baseline.json").exists())

    def test_output_parent_symlink_loop_is_a_clear_error(self):
        alias = self.base / "loop"
        alias.symlink_to(alias)
        code, report = self.call("snapshot", self.source, "--output", alias / "baseline.json")
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "error")
        self.assertFalse(report["complete"])

    def test_file_mutated_during_hashing_makes_snapshot_incomplete(self):
        read = os.read
        mutated = False

        def mutating_read(descriptor, count):
            nonlocal mutated
            block = read(descriptor, count)
            if block and not mutated:
                mutated = True
                (self.source / "archive" / "data.bin").write_bytes(b"Changed during hashing.")
            return block

        with mock.patch.object(core.os, "read", side_effect=mutating_read):
            code, report = self.call("snapshot", self.source, "--output", self.manifest)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(self.manifest.exists())
        self.assertTrue(any(issue["code"] == "source_changed" for issue in report["issues"]))

    def test_directory_changed_during_scan_makes_snapshot_incomplete(self):
        hash_file = core._hash_file
        signature = core._signature

        def adding_file(parent_fd, name, expected):
            result = hash_file(parent_fd, name, expected)
            if name == "note.txt":
                (self.source / "added-during-scan.txt").write_bytes(b"Late arrival.")
            return result

        def coarse_directory_signature(info):
            if stat.S_ISDIR(info.st_mode):
                return info.st_dev, info.st_ino, info.st_mode
            return signature(info)

        with mock.patch.object(core, "_hash_file", side_effect=adding_file), mock.patch.object(core, "_signature", side_effect=coarse_directory_signature):
            code, report = self.call("snapshot", self.source, "--output", self.manifest)
        self.assertEqual(code, 2)
        self.assertFalse(self.manifest.exists())
        self.assertTrue(any(issue["code"] == "directory_changed" for issue in report["issues"]))

    def test_symlink_swap_during_file_open_is_rejected(self):
        outside = self.base / "outside.txt"
        outside.write_bytes(b"Must not be read.")
        open_file = os.open

        def swapping_open(path, flags, *args, **kwargs):
            if path == "note.txt":
                (self.source / "note.txt").unlink()
                (self.source / "note.txt").symlink_to(outside)
            return open_file(path, flags, *args, **kwargs)

        with mock.patch.object(core.os, "open", side_effect=swapping_open), mock.patch.object(core, "_require_platform"):
            code, report = self.call("snapshot", self.source, "--output", self.manifest)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(self.manifest.exists())

    def test_unreadable_file_makes_verification_incomplete(self):
        self.snapshot()
        original = core._hash_file

        def inaccessible(parent_fd, name, expected):
            if name == "note.txt":
                raise PermissionError("Permission denied.")
            return original(parent_fd, name, expected)

        with mock.patch.object(core, "_hash_file", side_effect=inaccessible):
            code, report = self.call("verify", self.source, self.manifest)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "incomplete")
        self.assertIsNone(report["changes"])
        self.assertFalse(report["complete"])
        self.assertTrue(any(issue["code"] == "read_error" for issue in report["issues"]))

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "Privileged process can bypass mode permissions.")
    def test_actual_unreadable_file_is_not_silently_skipped(self):
        file = self.source / "note.txt"
        file.chmod(0)
        try:
            code, report = self.call("snapshot", self.source, "--output", self.manifest)
        finally:
            file.chmod(0o600)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(self.manifest.exists())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "Named pipes are unavailable.")
    def test_special_file_is_an_error_without_blocking(self):
        os.mkfifo(self.source / "pipe")
        code, report = self.call("snapshot", self.source, "--output", self.manifest)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "incomplete")
        self.assertTrue(any(issue["code"] == "unsupported_type" for issue in report["issues"]))
        self.assertFalse(self.manifest.exists())

    def test_missing_source_is_an_error(self):
        code, report = self.call("snapshot", self.base / "absent", "--output", self.manifest)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "error")

    def test_human_output_escapes_untrusted_filenames(self):
        self.snapshot()
        (self.source / "new\nline.txt").write_bytes(b"Record.")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["verify", str(self.source), str(self.manifest)])
        self.assertEqual(code, 1)
        self.assertIn('"new\\nline.txt"', output.getvalue())
        self.assertNotIn('"new\nline.txt"', output.getvalue())


if __name__ == "__main__":
    unittest.main()
