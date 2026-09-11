#!/usr/bin/env python3
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path


SCRIPT = (
    Path(__file__).parents[1]
    / "appliance"
    / "scripts"
    / "reference_oci_image.py"
)
SPEC = importlib.util.spec_from_file_location("reference_oci_image", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
reference_oci_image = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reference_oci_image)


class ReferenceOciImageTests(unittest.TestCase):
    def test_docker_archive_is_rejected_with_clear_error(self):
        digest = f"sha256:{'1' * 64}"

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oci_archive = root / "oci.tar"
            with tarfile.open(oci_archive, "w") as archive:
                data = json.dumps(
                    {
                        "schemaVersion": 2,
                        "manifests": [{"digest": digest, "size": 1}],
                    }
                ).encode()
                info = tarfile.TarInfo("index.json")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))

            docker_archive = root / "docker.tar"
            with tarfile.open(docker_archive, "w") as archive:
                data = b"[]"
                info = tarfile.TarInfo("manifest.json")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))

            with self.assertRaisesRegex(
                ValueError, "is not an OCI image-layout archive: index.json not found"
            ):
                reference_oci_image.find_archive(
                    [oci_archive, docker_archive], digest
                )


if __name__ == "__main__":
    unittest.main()
