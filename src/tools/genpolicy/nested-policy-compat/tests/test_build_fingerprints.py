#!/usr/bin/env python3
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPONENT_FINGERPRINT = ROOT / "scripts" / "component_input_fingerprint.sh"
IMAGE_FINGERPRINT = ROOT / "scripts" / "image_input_fingerprint.sh"


class BuildFingerprintTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary_directory.name)
        subprocess.run(["git", "init", "-q", self.repo], check=True)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def write(self, relative_path: str, content: str = "input\n"):
        path = self.repo / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def run_fingerprint(self, script: Path, *arguments: str):
        environment = os.environ.copy()
        return subprocess.check_output(
            [script, self.repo, *arguments],
            text=True,
            env=environment,
        ).strip()

    def test_agent_key_ignores_genpolicy_and_tracks_agent(self):
        self.write("Cargo.toml")
        self.write("Cargo.lock")
        self.write("src/agent/src/main.rs", "fn agent() {}\n")
        self.write("src/tools/genpolicy/src/main.rs", "fn genpolicy() {}\n")

        original = self.run_fingerprint(COMPONENT_FINGERPRINT, "agent")
        self.write("src/tools/genpolicy/src/main.rs", "fn changed_genpolicy() {}\n")
        self.assertEqual(
            original,
            self.run_fingerprint(COMPONENT_FINGERPRINT, "agent"),
        )

        self.write("src/agent/src/main.rs", "fn changed_agent() {}\n")
        self.assertNotEqual(
            original,
            self.run_fingerprint(COMPONENT_FINGERPRINT, "agent"),
        )

    def test_rootfs_key_tracks_component_archives(self):
        dependency = self.write("build/kata-static-agent.tar.zst", "agent-a\n")
        original = self.run_fingerprint(
            COMPONENT_FINGERPRINT,
            "rootfs-image-confidential",
            dependency,
        )
        dependency.write_text("agent-b\n", encoding="utf-8")
        self.assertNotEqual(
            original,
            self.run_fingerprint(
                COMPONENT_FINGERPRINT,
                "rootfs-image-confidential",
                dependency,
            ),
        )

    def test_static_image_key_ignores_genpolicy_source(self):
        for relative_path in (
            "src/tools/genpolicy/nested-policy-compat/appliance/config/input",
            "src/tools/genpolicy/nested-policy-compat/appliance/scripts/input",
            "src/tools/genpolicy/nested-policy-compat/config/input",
            "src/tools/genpolicy/nested-policy-compat/scripts/compat_report.py",
            "src/tools/genpolicy/nested-policy-compat/scripts/hvsock_capture.py",
            "src/tools/genpolicy/nested-policy-compat/scripts/image_input_fingerprint.sh",
        ):
            self.write(relative_path)
        profile = self.write(
            "src/tools/genpolicy/nested-policy-compat/appliance/profiles/test.env",
            "PROFILE_NAME=test\n",
        )
        self.write("src/tools/genpolicy/nested-policy-compat/Dockerfile")
        self.write(
            "src/tools/genpolicy/nested-policy-compat/scripts/entrypoint.sh"
        )
        self.write("src/tools/genpolicy/src/main.rs", "fn genpolicy() {}\n")

        original = self.run_fingerprint(
            IMAGE_FINGERPRINT,
            profile,
            "1.8.5",
        )
        self.write("src/tools/genpolicy/src/main.rs", "fn changed_genpolicy() {}\n")
        self.assertEqual(
            original,
            self.run_fingerprint(IMAGE_FINGERPRINT, profile, "1.8.5"),
        )

        self.write(
            "src/tools/genpolicy/nested-policy-compat/scripts/entrypoint.sh",
            "changed\n",
        )
        self.assertNotEqual(
            original,
            self.run_fingerprint(IMAGE_FINGERPRINT, profile, "1.8.5"),
        )

        self.assertNotEqual(
            original,
            self.run_fingerprint(IMAGE_FINGERPRINT, profile, "1.8.6"),
        )


if __name__ == "__main__":
    unittest.main()
