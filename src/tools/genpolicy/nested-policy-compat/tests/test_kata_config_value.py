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
    Path(__file__).resolve().parents[1] / "scripts" / "kata_config_value.sh"
)


class KataConfigValueTests(unittest.TestCase):
    def test_reads_quoted_value_from_selected_section(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "configuration.toml"
            config.write_text(
                """
[hypervisor.clh]
image = "/opt/kata/share/kata-containers/kata-containers.img" # selected

[runtime]
hypervisor_name = "clh"
""",
                encoding="utf-8",
            )
            value = subprocess.check_output(
                [SCRIPT, config, "hypervisor.clh", "image"],
                text=True,
            ).strip()
            self.assertEqual(
                value,
                "/opt/kata/share/kata-containers/kata-containers.img",
            )

    def test_rejects_missing_value(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "configuration.toml"
            config.write_text("[runtime]\n", encoding="utf-8")
            result = subprocess.run(
                [SCRIPT, config, "runtime", "hypervisor_name"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
