#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class ManifestTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.out = Path(temporary.name)
        self.verity = (
            "root_hash=" + "ab" * 32 + ",salt=" + "cd" * 32
            + ",data_blocks=51712,data_block_size=4096,hash_block_size=4096"
        )
        (self.out / "root_hash_.txt").write_text(self.verity)
        self.kernel = self.out / "inputs" / "bzImage"
        self.bootshim = self.out / "inputs" / "snp_bootshim"

    def generate(self, *args, check=True):
        return subprocess.run(
            [sys.executable, str(Path(__file__).with_name("igvm_manifest.py")),
             str(self.out / "root_hash_.txt"),
             "--kernel", str(self.kernel), "--bootshim", str(self.bootshim),
             "--manifest", str(self.out / "manifest.json"),
             "--resources", str(self.out / "resources.json"), *args],
            capture_output=True, text=True, check=check,
        )

    def test_production_and_debug_contract(self):
        for debug in (False, True):
            with self.subTest(debug=debug):
                self.generate("--svn", "7", *(["--debug"] if debug else []))
                config = json.loads((self.out / "manifest.json").read_text())["guest_configs"][0]
                self.assertEqual(config["guest_svn"], 7)
                self.assertFalse(config["isolation_type"]["snp"]["enable_debug"])
                self.assertEqual(config["isolation_type"]["snp"]["injection_type"], "normal")
                image = config["image"]["snp_linux_direct"]
                self.assertNotIn("launch_time_sizing", image)
                self.assertEqual(image["processor_count"], 1)
                self.assertEqual(image["memory_page_count"], 512 * 256)
                command = image["linux"]["command_line"]
                self.assertIn("nr_cpus=256", command)
                self.assertEqual(command.count("clearcpuid=rdpid"), 1)
                self.assertIn("ab" * 32, command)
                self.assertIn("cd" * 32, command)
                self.assertEqual("console=hvc0" in command, debug)
                self.assertEqual("agent.debug_console " in command, debug)
                self.assertEqual("quiet" in command.split(), not debug)
                resources = json.loads((self.out / "resources.json").read_text())["resources"]
                self.assertEqual(resources["linux_kernel"], str(self.kernel))
                self.assertEqual(resources["snp_bootshim"], str(self.bootshim))

    def test_invalid_svn(self):
        for value in ("-1", str(1 << 32)):
            self.assertNotEqual(self.generate("--svn", value, check=False).returncode, 0)

    def test_fixed_profile_arguments_rejected(self):
        self.assertNotEqual(self.generate("8", "2048", check=False).returncode, 0)

    def test_inputs_required(self):
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("igvm_manifest.py")), str(self.out / "root_hash_.txt")],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_invalid_verity_block_size(self):
        (self.out / "root_hash_.txt").write_text(self.verity.replace("data_block_size=4096", "data_block_size=512"))
        self.assertNotEqual(self.generate(check=False).returncode, 0)


if __name__ == "__main__":
    unittest.main()
