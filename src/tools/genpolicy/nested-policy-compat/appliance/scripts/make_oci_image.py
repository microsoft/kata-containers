#!/usr/bin/env python3
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import gzip
import hashlib
import json
import os
import platform
import tarfile
import tempfile
from pathlib import Path


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def add_tree(archive: tarfile.TarFile, rootfs: Path) -> None:
    for path in sorted(rootfs.rglob("*")):
        relative = path.relative_to(rootfs)
        info = archive.gettarinfo(str(path), arcname=str(relative))
        info.mtime = 0
        info.uid = 0
        info.gid = 0
        info.uname = ""
        info.gname = ""
        if info.isfile():
            with path.open("rb") as source:
                archive.addfile(info, source)
        else:
            archive.addfile(info)


def write_blob(layout: Path, data: bytes) -> tuple[str, int]:
    value_digest = digest(data)
    destination = layout / "blobs" / "sha256" / value_digest
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return value_digest, len(data)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--entrypoint", required=True)
    parser.add_argument("--user")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    entrypoint = json.loads(args.entrypoint)
    architecture = {
        "x86_64": "amd64",
        "aarch64": "arm64",
    }.get(platform.machine(), platform.machine())

    with tempfile.TemporaryDirectory() as temporary:
        temporary_path = Path(temporary)
        layer_path = temporary_path / "layer.tar"
        with tarfile.open(layer_path, "w", format=tarfile.PAX_FORMAT) as layer:
            add_tree(layer, args.rootfs)
        layer_data = layer_path.read_bytes()
        compressed_layer = gzip.compress(layer_data, mtime=0)
        layer_digest, layer_size = write_blob(temporary_path, compressed_layer)
        diff_id = digest(layer_data)

        image_config = {
            "Entrypoint": entrypoint,
            "Env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            ],
            "WorkingDir": "/",
        }
        if args.user is not None:
            image_config["User"] = args.user

        config = canonical_json(
            {
                "architecture": architecture,
                "config": image_config,
                "created": "1970-01-01T00:00:00Z",
                "history": [{"created": "1970-01-01T00:00:00Z"}],
                "os": "linux",
                "rootfs": {
                    "diff_ids": [f"sha256:{diff_id}"],
                    "type": "layers",
                },
            }
        )
        config_digest, config_size = write_blob(temporary_path, config)

        manifest = canonical_json(
            {
                "config": {
                    "digest": f"sha256:{config_digest}",
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "size": config_size,
                },
                "layers": [
                    {
                        "digest": f"sha256:{layer_digest}",
                        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                        "size": layer_size,
                    }
                ],
                "schemaVersion": 2,
            }
        )
        manifest_digest, manifest_size = write_blob(temporary_path, manifest)

        (temporary_path / "oci-layout").write_text(
            '{"imageLayoutVersion":"1.0.0"}\n', encoding="utf-8"
        )
        index = canonical_json(
            {
                "manifests": [
                    {
                        "annotations": {
                            "org.opencontainers.image.ref.name": args.reference
                        },
                        "digest": f"sha256:{manifest_digest}",
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "platform": {"architecture": architecture, "os": "linux"},
                        "size": manifest_size,
                    }
                ],
                "schemaVersion": 2,
            }
        )
        (temporary_path / "index.json").write_bytes(index)

        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(args.output, "w") as output:
            for name in ("oci-layout", "index.json", "blobs"):
                output.add(
                    temporary_path / name,
                    arcname=name,
                    recursive=True,
                    filter=lambda info: _normalize_tar_info(info),
                )


def _normalize_tar_info(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


if __name__ == "__main__":
    main()
