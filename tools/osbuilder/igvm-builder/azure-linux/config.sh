#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

# this is where the kernel-uvm package installation places bzImage, see SPEC file
bzimage_bin="/usr/share/cloud-hypervisor/bzImage"

igvm_extract_folder="igvm-tooling"
clh_acpi_tables_dir="${igvm_extract_folder}/src/igvm/acpi/acpi-clh/"
igvmgen_py_file="${igvm_extract_folder}/src/igvm/igvmgen.py"

igvm_vars="-kernel ${bzimage_bin} -boot_mode x64 -vtl 0 -svme 1 -encrypted_page 1 -pvalidate_opt 1 -acpi ${clh_acpi_tables_dir}"

# root_hash=85b2e9101c51173834f911eaa22e24a41427c806f794585f2fa7a4d26f9470d5
# salt=9476eed0d13d80032e38905c849ea00417d64f62b5819d9bc1379e7f2bba6dbb


igvm_kernel_params_common="dm-mod.create=\"dm-verity,,,ro,0 ${data_sectors} verity 1 /dev/vda1 /dev/vda2 ${data_block_size} ${hash_block_size} ${data_blocks} 0 sha256 ${root_hash} ${salt}\" \
	root=/dev/dm-0 rootflags=data=ordered,errors=remount-ro ro rootfstype=ext4 panic=1 no_timer_check noreplace-smp systemd.unit=kata-containers.target systemd.mask=systemd-networkd.service \
	systemd.mask=systemd-networkd.socket agent.enable_signature_verification=false"
echo "FOOBY!!!"
echo "igvm_kernel_params_common: $igvm_kernel_params_common"

igvm_kernel_prod_params="${igvm_kernel_params_common} quiet"
igvm_kernel_debug_params="${igvm_kernel_params_common} console=hvc0 systemd.log_target=console agent.log=debug agent.debug_console agent.debug_console_vport=1026"
