#!/usr/bin/env python3
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import copy
import io
import json
import re
import tarfile
from pathlib import Path


DIGEST_REFERENCE = re.compile(r"^.+@(sha256:[0-9a-f]{64})$")
REFERENCE_ANNOTATION = "org.opencontainers.image.ref.name"


def find_archive(archives: list[Path], digest: str) -> tuple[Path, dict]:
    indexes = []
    for archive in archives:
        with tarfile.open(archive) as layout:
            try:
                index_file = layout.extractfile("index.json")
            except KeyError as error:
                raise ValueError(
                    f"{archive} is not an OCI image-layout archive: index.json not found"
                ) from error
            if index_file is None:
                raise ValueError(
                    f"{archive} is not an OCI image-layout archive: index.json not found"
                )
            indexes.append((archive, json.load(index_file)))

    for archive, index in indexes:
        for descriptor in index.get("manifests", []):
            if descriptor.get("digest") == digest:
                return archive, descriptor
    raise ValueError(f"no OCI archive contains requested manifest digest {digest}")


def write_archive(source: Path, descriptor: dict, reference: str, output: Path) -> None:
    selected = copy.deepcopy(descriptor)
    selected.setdefault("annotations", {})[REFERENCE_ANNOTATION] = reference
    index = json.dumps(
        {"manifests": [selected], "schemaVersion": 2},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(source) as source_layout, tarfile.open(output, "w") as result:
        index_info = tarfile.TarInfo("index.json")
        index_info.size = len(index)
        index_info.mode = 0o644
        result.addfile(index_info, io.BytesIO(index))
        for member in source_layout.getmembers():
            if member.name == "index.json":
                continue
            result.addfile(member, source_layout.extractfile(member))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("archives", nargs="+", type=Path)
    args = parser.parse_args()

    match = DIGEST_REFERENCE.fullmatch(args.reference)
    if match is None:
        parser.error("--reference must be digest-qualified with sha256")
    try:
        source, descriptor = find_archive(args.archives, match.group(1))
    except ValueError as error:
        parser.error(str(error))
    write_archive(source, descriptor, args.reference, args.output)


if __name__ == "__main__":
    main()
