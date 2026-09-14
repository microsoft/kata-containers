#!/usr/bin/env python3
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import base64
import gzip
from pathlib import Path

import yaml


ANNOTATION = "io.katacontainers.config.hypervisor.cc_init_data"


def pod_metadata(document: dict) -> dict | None:
    kind = document.get("kind")
    if kind == "Pod":
        return document.setdefault("metadata", {})
    if kind in {"Deployment", "DaemonSet", "StatefulSet", "Job"}:
        return document.setdefault("spec", {}).setdefault("template", {}).setdefault(
            "metadata", {}
        )
    if kind == "CronJob":
        return (
            document.setdefault("spec", {})
            .setdefault("jobTemplate", {})
            .setdefault("spec", {})
            .setdefault("template", {})
            .setdefault("metadata", {})
        )
    return None


def annotate(
    workload: Path, policy: Path, output: Path, registry_ca: Path | None = None
) -> None:
    policy_text = policy.read_text(encoding="utf-8")
    initdata = (
        'version = "0.1.0"\n'
        'algorithm = "sha256"\n\n'
        "[data]\n"
        '"policy.rego" = \'\'\'\n'
        f"{policy_text}\n"
        "'''\n"
    )
    if registry_ca is not None:
        certificate = registry_ca.read_text(encoding="utf-8").strip()
        initdata += (
            '"cdh.toml" = \'\'\'\n'
            "[kbc]\n"
            'name = "offline_fs_kbc"\n'
            'url = ""\n\n'
            "[image]\n"
            'extra_root_certificates = ["""\n'
            f"{certificate}\n"
            '"""]\n'
            "'''\n"
        )
    value = base64.b64encode(
        gzip.compress(initdata.encode("utf-8"), mtime=0)
    ).decode("ascii")

    documents = list(yaml.safe_load_all(workload.read_text(encoding="utf-8")))
    annotated = 0
    for document in documents:
        if not isinstance(document, dict):
            continue
        metadata = pod_metadata(document)
        if metadata is None:
            continue
        metadata.setdefault("annotations", {})[ANNOTATION] = value
        annotated += 1
    if annotated == 0:
        raise ValueError("workload contains no supported Pod template")

    output.write_text(
        yaml.safe_dump_all(documents, sort_keys=False),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workload", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--registry-ca", type=Path)
    args = parser.parse_args()
    annotate(args.workload, args.policy, args.output, args.registry_ca)


if __name__ == "__main__":
    main()
