#!/usr/bin/env python3
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

import importlib.util
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "compat_report.py"
SPEC = importlib.util.spec_from_file_location("compat_report", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CompatibilityReportTest(unittest.TestCase):
    def arguments(self, root, ready=False):
        workload = root / "workload.yaml"
        workload.write_text("kind: Pod\n", encoding="utf-8")
        kata_config = root / "configuration.toml"
        kata_config.write_text("[hypervisor]\n", encoding="utf-8")
        capture_state = root / "state.json"
        capture_state.write_text('{"connections": 1}\n', encoding="utf-8")
        logs = root / "logs"
        logs.mkdir()
        return Namespace(
            base_exit_code=0,
            capture_state=capture_state,
            kata_config=kata_config,
            logs=logs,
            profile="test-profile",
            ready=ready,
            workload=workload,
        )

    def test_ready_is_compatible(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.arguments(Path(temporary), ready=True)
            self.assertEqual(MODULE.build_report(args)["result"], "compatible")

    def test_policy_denial_is_incompatible(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.arguments(root)
            (args.logs / "agent.log").write_text(
                "CreateContainer request denied by policy\n",
                encoding="utf-8",
            )
            report = MODULE.build_report(args)
            self.assertEqual(report["result"], "policy-incompatible")
            self.assertIn("denied", report["denial"]["text"])

    def test_other_failure_is_infrastructure(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.arguments(Path(temporary))
            self.assertEqual(
                MODULE.build_report(args)["result"],
                "infrastructure-failure",
            )


if __name__ == "__main__":
    unittest.main()
