#!/usr/bin/env python3
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import hashlib
import json
import re
from pathlib import Path


DENIAL = re.compile(
    r"(policy.{0,80}(?:denied|deny|not allowed|refused)|"
    r"(?:denied|refused).{0,80}(?:request|policy)|"
    r"AllowRequestsFailingPolicy)",
    re.IGNORECASE,
)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def denial_excerpt(log_dir):
    for path in sorted(log_dir.rglob("*.log")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        match = DENIAL.search(text)
        if match:
            start = max(0, text.rfind("\n", 0, match.start()) + 1)
            end = text.find("\n", match.end())
            if end < 0:
                end = len(text)
            return {"file": str(path), "text": text[start:end][:2000]}
    return None


def build_report(args):
    capture_state = {}
    if args.capture_state.exists():
        capture_state = json.loads(args.capture_state.read_text(encoding="utf-8"))

    denial = denial_excerpt(args.logs)
    if args.ready:
        result = "compatible"
    elif denial:
        result = "policy-incompatible"
    else:
        result = "infrastructure-failure"

    return {
        "base_appliance_exit_code": args.base_exit_code,
        "capture": capture_state,
        "denial": denial,
        "kata_config": {
            "path": str(args.kata_config),
            "sha256": sha256(args.kata_config) if args.kata_config.is_file() else None,
        },
        "profile": args.profile,
        "result": result,
        "workload": {
            "path": str(args.workload),
            "sha256": sha256(args.workload),
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-exit-code", type=int, required=True)
    parser.add_argument("--capture-state", type=Path, required=True)
    parser.add_argument("--kata-config", type=Path, required=True)
    parser.add_argument("--logs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--ready", action="store_true")
    parser.add_argument("--workload", type=Path, required=True)
    args = parser.parse_args()

    args.output.write_text(
        json.dumps(build_report(args), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
