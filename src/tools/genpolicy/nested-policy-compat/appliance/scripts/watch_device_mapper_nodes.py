#!/usr/bin/env python3
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

import os
import stat
import time
from pathlib import Path


SYS_BLOCK = Path("/sys/block")
DEV_ROOT = Path("/dev")
DEV_MAPPER = DEV_ROOT / "mapper"


def ensure_node(path: Path, device: int) -> None:
    if os.path.lexists(path):
        return
    try:
        os.mknod(path, stat.S_IFBLK | 0o600, device)
    except FileExistsError:
        pass


def reconcile() -> None:
    DEV_MAPPER.mkdir(parents=True, exist_ok=True)
    active = set()
    for device in SYS_BLOCK.glob("dm-*"):
        try:
            name = (device / "dm" / "name").read_text(encoding="utf-8").strip()
            major, minor = (int(value) for value in (device / "dev").read_text().split(":"))
        except (OSError, ValueError):
            continue
        if not name.startswith("containerd-erofs-"):
            continue
        active.add(name)
        kernel_path = DEV_ROOT / device.name
        ensure_node(kernel_path, os.makedev(major, minor))
        path = DEV_MAPPER / name
        ensure_node(path, os.makedev(major, minor))
    for path in DEV_MAPPER.glob("containerd-erofs-*"):
        if path.name not in active:
            path.unlink(missing_ok=True)


def main() -> None:
    while True:
        reconcile()
        time.sleep(0.01)


if __name__ == "__main__":
    main()
