# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

import base64
import gzip
import tempfile
import unittest
from pathlib import Path

import yaml

from annotate_workload import ANNOTATION, annotate


class AnnotateWorkloadTests(unittest.TestCase):
    def test_annotates_pod_and_deployment_templates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workload = root / "workload.yaml"
            policy = root / "policy.rego"
            output = root / "annotated.yaml"
            workload.write_text(
                """apiVersion: v1
kind: Pod
metadata:
  name: pod
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: deployment
spec:
  template:
    metadata: {}
    spec:
      containers: []
""",
                encoding="utf-8",
            )
            policy.write_text("package agent_policy\n", encoding="utf-8")

            annotate(workload, policy, output)

            documents = list(yaml.safe_load_all(output.read_text(encoding="utf-8")))
            values = [
                documents[0]["metadata"]["annotations"][ANNOTATION],
                documents[1]["spec"]["template"]["metadata"]["annotations"][ANNOTATION],
            ]
            self.assertEqual(values[0], values[1])
            initdata = gzip.decompress(base64.b64decode(values[0])).decode("utf-8")
            self.assertIn('"policy.rego"', initdata)
            self.assertIn("package agent_policy", initdata)

    def test_rejects_workload_without_pod_template(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workload = root / "workload.yaml"
            policy = root / "policy.rego"
            workload.write_text(
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: config\n",
                encoding="utf-8",
            )
            policy.write_text("package agent_policy\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "no supported Pod template"):
                annotate(workload, policy, root / "annotated.yaml")

    def test_adds_registry_ca_to_cdh_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workload = root / "workload.yaml"
            policy = root / "policy.rego"
            registry_ca = root / "registry.crt"
            output = root / "annotated.yaml"
            workload.write_text(
                "apiVersion: v1\nkind: Pod\nmetadata:\n  name: pod\n",
                encoding="utf-8",
            )
            policy.write_text("package agent_policy\n", encoding="utf-8")
            registry_ca.write_text(
                "-----BEGIN CERTIFICATE-----\ncertificate\n"
                "-----END CERTIFICATE-----\n",
                encoding="utf-8",
            )

            annotate(workload, policy, output, registry_ca)

            document = yaml.safe_load(output.read_text(encoding="utf-8"))
            value = document["metadata"]["annotations"][ANNOTATION]
            initdata = gzip.decompress(base64.b64decode(value)).decode("utf-8")
            self.assertIn('"cdh.toml"', initdata)
            self.assertIn('name = "offline_fs_kbc"', initdata)
            self.assertIn("extra_root_certificates", initdata)
            self.assertIn("-----BEGIN CERTIFICATE-----", initdata)


if __name__ == "__main__":
    unittest.main()
