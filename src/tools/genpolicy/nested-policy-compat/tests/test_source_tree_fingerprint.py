#!/usr/bin/env python3
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "source_tree_fingerprint.sh"
)


class SourceTreeFingerprintTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.repo = Path(self.tempdir.name)
        subprocess.run(["git", "init", "-q", self.repo], check=True)
        source = self.repo / "src" / "component"
        source.mkdir(parents=True)
        (source / "tracked.txt").write_text("one\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", self.repo, "add", "src/component/tracked.txt"],
            check=True,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def fingerprint(self):
        return subprocess.check_output(
            [SCRIPT, self.repo, "src/component"],
            text=True,
        ).strip()

    def test_tracked_change_changes_fingerprint(self):
        original = self.fingerprint()
        (self.repo / "src/component/tracked.txt").write_text(
            "two\n", encoding="utf-8"
        )
        self.assertNotEqual(original, self.fingerprint())

    def test_untracked_file_changes_fingerprint(self):
        original = self.fingerprint()
        (self.repo / "src/component/untracked.txt").write_text(
            "new\n", encoding="utf-8"
        )
        self.assertNotEqual(original, self.fingerprint())

    def test_tracked_deletion_changes_fingerprint(self):
        original = self.fingerprint()
        (self.repo / "src/component/tracked.txt").unlink()
        self.assertNotEqual(original, self.fingerprint())

    def test_mode_change_changes_fingerprint(self):
        source = self.repo / "src/component/tracked.txt"
        source.chmod(0o755)
        executable = self.fingerprint()
        source.chmod(0o644)
        self.assertNotEqual(executable, self.fingerprint())

    def test_non_executable_umask_bits_do_not_change_fingerprint(self):
        source = self.repo / "src/component/tracked.txt"
        source.chmod(0o644)
        standard = self.fingerprint()
        source.chmod(0o664)
        self.assertEqual(standard, self.fingerprint())

    def test_checkout_path_does_not_affect_fingerprint(self):
        alternate = subprocess.check_output(
            [SCRIPT, f"{self.repo}/.", "src/component"],
            text=True,
        ).strip()
        self.assertEqual(self.fingerprint(), alternate)


if __name__ == "__main__":
    unittest.main()
