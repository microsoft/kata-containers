#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: Apache-2.0
"""Generate a launch-sized OpenVMM SNP igvmfilegen manifest bound to an osbuilder verity image."""

import argparse
import json
import pathlib

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("root_hash", type=pathlib.Path, help="osbuilder root_hash_<variant>.txt")
parser.add_argument("--kernel", type=pathlib.Path, required=True, help="guest bzImage")
parser.add_argument("--bootshim", type=pathlib.Path, required=True, help="OpenVMM snp_bootshim")
parser.add_argument("--manifest", type=pathlib.Path, required=True, help="output igvmfilegen manifest")
parser.add_argument("--resources", type=pathlib.Path, required=True, help="output igvmfilegen resources")
parser.add_argument("--svn", type=int, default=1)
parser.add_argument("--debug", action="store_true")
args = parser.parse_args()
if not 0 <= args.svn <= 0xFFFFFFFF:
    parser.error("SVN must fit in an unsigned 32-bit integer")
verity = dict(item.split("=", 1) for item in args.root_hash.read_text().strip().split(","))
data_blocks = int(verity["data_blocks"])
data_size = int(verity["data_block_size"])
hash_size = int(verity["hash_block_size"])
root_hash, salt = verity["root_hash"], verity["salt"]
if data_blocks <= 0 or data_size != 4096 or hash_size != 4096:
    raise ValueError("expected 4096-byte dm-verity blocks")
if len(bytes.fromhex(root_hash)) != 32 or len(bytes.fromhex(salt)) != 32:
    raise ValueError("expected SHA-256 root hash and 32-byte salt")
command_line = (
    f'dm-mod.create="dm-verity,,,ro,0 {data_blocks * data_size // 512} '
    f'verity 1 /dev/vda1 /dev/vda2 {data_size} {hash_size} {data_blocks} 0 '
    f'sha256 {root_hash} {salt}" '
    "root=/dev/dm-0 rootfstype=ext4 ro rootflags=data=ordered,errors=remount-ro "
    "panic=1 nr_cpus=256 systemd.unit=kata-containers.target "
    "systemd.mask=systemd-networkd.service systemd.mask=systemd-networkd.socket"
)
# MSHV SNP can advertise RDPID without TSC_AUX virtualization: the instruction
# reports CPU 0 despite a correct MSR value. Use Linux's GDT getcpu fallback
# until OpenVMM masks unsupported RDPID/RDTSCP; raw instructions remain exposed.
command_line += " clearcpuid=rdpid"
if args.debug:
    command_line += (
        " console=hvc0 systemd.log_target=console agent.log=debug"
        " agent.debug_console agent.debug_console_vport=1026"
    )
else:
    command_line += " quiet"
manifest = {
    "guest_arch": "x64",
    "guest_configs": [{
        "guest_svn": args.svn, "max_vtl": 0,
        "isolation_type": {"snp": {
            "shared_gpa_boundary_bits": None, "policy": 196608,
            "enable_debug": False, "injection_type": "normal", "secure_avic": "disabled",
        }},
        "image": {"snp_linux_direct": {
            "memory_page_count": 512 * 256,
            "c_bit_position": 51,
            "linux": {"use_initrd": False, "command_line": command_line},
        }},
    }],
}
resources = {"resources": {
    "linux_kernel": str(args.kernel.resolve()),
    "snp_bootshim": str(args.bootshim.resolve()),
}}
for path, contents in ((args.manifest, manifest), (args.resources, resources)):
    path.write_text(json.dumps(contents, indent=2) + "\n")
