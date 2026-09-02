# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

OPENVMM_DIR ?= $(HOME)/openvmm-snp-mshv-aci-igvm
OUT_DIR ?= $(CURDIR)/out
KERNEL ?=
KERNEL_SRC ?=
KERNEL_CONFIG ?= $(CURDIR)/kernel.config
KERNEL_BUILD_DIR ?= $(OUT_DIR)/kernel
BUSYBOX ?=
KATA_IMAGE ?=
ROOT_HASH_FILE ?= $(OUT_DIR)/root_hash_.txt
RUNTIME_CONFIG ?= $(CURDIR)/out/configuration-openvmm-snp-runtime-rs.toml
VP_COUNT ?= 2
MEMORY ?= 1G
AGENT_IGVM = $(OUT_DIR)/kata-aci-agent-dmverity-reserve-416b-$(VP_COUNT)vp.bin
AGENT_BINARY = $(abspath ../../../target/$(shell uname -m)-unknown-linux-gnu/release/kata-agent)
AGENT_SOURCE_DIR = $(abspath ../../../src/agent)
AGENT_POLICY ?= yes
AGENT_POLICY_FILE ?= $(abspath ../../../src/kata-opa/allow-all.rego)
STRICT_POLICY ?= no

OPENVMM ?= $(OPENVMM_DIR)/target/release/openvmm
IGVMFILEGEN ?= $(OPENVMM_DIR)/target/release/igvmfilegen

.PHONY: help
help:
	@echo "OpenVMM SNP IGVM bring-up targets:"
	@echo "  make kernel KERNEL_SRC=<linux-source>"
	@echo "  make guest-image"
	@echo "  make openvmm OPENVMM_DIR=<path>"
	@echo "  make shell-igvm KERNEL=<bzImage> BUSYBOX=<static-busybox>"
	@echo "  make shell-run"
	@echo "  make shell-disk-run KATA_IMAGE=<kata-containers.img>"
	@echo "  make agent-dmverity-igvm KERNEL=<bzImage> [VP_COUNT=2]"
	@echo "  make agent-dmverity-run KATA_IMAGE=<kata-containers.img> [VP_COUNT=2]"
	@echo "  make e2e-setup KATA_IMAGE=<image> [KERNEL=<bzImage>] [VP_COUNT=2]"
	@echo "  make e2e-test [VP_COUNT=2]"
	@echo "  make e2e-k8s-setup"
	@echo "  make e2e-k8s-test [VP_COUNT=2]"
	@echo "  make check"
	@echo "  make clean"

.PHONY: kernel
kernel:
	KERNEL_SRC="$(KERNEL_SRC)" \
	KERNEL_CONFIG="$(KERNEL_CONFIG)" \
	BUILD_DIR="$(KERNEL_BUILD_DIR)" \
	./build-kernel.sh

.PHONY: guest-image
guest-image:
	$(MAKE) -C "$(AGENT_SOURCE_DIR)" \
		AGENT_POLICY="$(AGENT_POLICY)" \
		BUILD_TYPE=release \
		LIBC=gnu \
		SECCOMP=yes \
		STRICT_POLICY="$(STRICT_POLICY)" \
		kata-agent kata-agent.service kata-containers.target
	sudo rm -f \
		"$(OUT_DIR)/.cbl-mariner_rootfs.done" \
		"$(OUT_DIR)/kata-containers.img" \
		"$(OUT_DIR)/root_hash_.txt"
	sudo -E env \
		PATH="$(PATH)" \
		$(MAKE) -C .. \
		ROOTFS_BUILD_DEST="$(OUT_DIR)" \
		DISTRO=cbl-mariner \
		AGENT_SOURCE_BIN="$(AGENT_BINARY)" \
		AGENT_POLICY="$(AGENT_POLICY)" \
		AGENT_POLICY_FILE="$(AGENT_POLICY_FILE)" \
		CONFIDENTIAL_GUEST=yes \
		rootfs
	sudo install -D -m 0644 \
		"$(AGENT_SOURCE_DIR)/kata-agent.service" \
		"$(OUT_DIR)/cbl-mariner_rootfs/usr/lib/systemd/system/kata-agent.service"
	sudo install -D -m 0644 \
		"$(AGENT_SOURCE_DIR)/kata-containers.target" \
		"$(OUT_DIR)/cbl-mariner_rootfs/usr/lib/systemd/system/kata-containers.target"
	sudo mkdir -p \
		"$(OUT_DIR)/cbl-mariner_rootfs/etc/systemd/system/kata-containers.target.wants"
	sudo ln -sf /usr/lib/systemd/system/kata-agent.service \
		"$(OUT_DIR)/cbl-mariner_rootfs/etc/systemd/system/kata-containers.target.wants/kata-agent.service"
	sudo -E env \
		PATH="$(PATH)" \
		$(MAKE) -C .. \
		ROOTFS_BUILD_DEST="$(OUT_DIR)" \
		IMAGES_BUILD_DEST="$(OUT_DIR)" \
		DISTRO=cbl-mariner \
		MEASURED_ROOTFS=yes \
		DM_VERITY_FORMAT=kernelinit \
		IMAGE_SIZE_ALIGNMENT_MB=2 \
		image
	sudo chown "$(shell id -u):$(shell id -g)" "$(OUT_DIR)"

.PHONY: openvmm
openvmm:
	cd "$(OPENVMM_DIR)" && \
		CARGO_INCREMENTAL=0 cargo build --release -p openvmm -p igvmfilegen

.PHONY: shell-igvm
shell-igvm:
	OPENVMM_DIR="$(OPENVMM_DIR)" \
	IGVMFILEGEN="$(IGVMFILEGEN)" \
	KERNEL="$(KERNEL)" \
	BUSYBOX="$(BUSYBOX)" \
	OUT_DIR="$(OUT_DIR)" \
	EXTRA_KERNEL_ARGS='memmap=4K$$0x416b000' \
	OUTPUT_NAME="kata-aci-shell-reserve-416b-1vp.bin" \
	./build.sh

.PHONY: agent-dmverity-igvm
agent-dmverity-igvm:
	OPENVMM_DIR="$(OPENVMM_DIR)" \
	IGVMFILEGEN="$(IGVMFILEGEN)" \
	KERNEL="$(KERNEL)" \
	OUT_DIR="$(OUT_DIR)" \
	BOOT_MODE="rootfs" \
	ROOT_HASH_FILE="$(ROOT_HASH_FILE)" \
	VP_COUNT="$(VP_COUNT)" \
	EXTRA_KERNEL_ARGS='memmap=4K$$0x416b000' \
	OUTPUT_NAME="$(notdir $(AGENT_IGVM))" \
	./build.sh

.PHONY: shell-run
shell-run:
	OPENVMM="$(OPENVMM)" \
	IGVM="$(OUT_DIR)/kata-aci-shell-reserve-416b-1vp.bin" \
	KATA_IMAGE="" \
	VP_COUNT=1 \
	MEMORY="$(MEMORY)" \
	./run.sh

.PHONY: shell-disk-run
shell-disk-run:
	@test -n "$(KATA_IMAGE)" || \
		{ echo "ERROR: set KATA_IMAGE to kata-containers.img" >&2; exit 1; }
	OPENVMM="$(OPENVMM)" \
	IGVM="$(OUT_DIR)/kata-aci-shell-reserve-416b-1vp.bin" \
	KATA_IMAGE="$(KATA_IMAGE)" \
	VP_COUNT=1 \
	MEMORY="$(MEMORY)" \
	./run.sh

.PHONY: agent-dmverity-run
agent-dmverity-run:
	@test -n "$(KATA_IMAGE)" || \
		{ echo "ERROR: set KATA_IMAGE to kata-containers.img" >&2; exit 1; }
	OPENVMM="$(OPENVMM)" \
	IGVM="$(AGENT_IGVM)" \
	KATA_IMAGE="$(KATA_IMAGE)" \
	VP_COUNT="$(VP_COUNT)" \
	MEMORY="$(MEMORY)" \
	./run.sh

.PHONY: e2e-setup
e2e-setup:
	OPENVMM_DIR="$(OPENVMM_DIR)" \
	KERNEL_SRC="$(KERNEL_SRC)" \
	KERNEL_CONFIG="$(KERNEL_CONFIG)" \
	KERNEL_BUILD_DIR="$(KERNEL_BUILD_DIR)" \
	KERNEL="$(KERNEL)" \
	KATA_IMAGE="$(KATA_IMAGE)" \
	ROOT_HASH_FILE="$(ROOT_HASH_FILE)" \
	VP_COUNT="$(VP_COUNT)" \
	OUT_DIR="$(OUT_DIR)" \
	RUNTIME_CONFIG="$(RUNTIME_CONFIG)" \
	./e2e-setup.sh

.PHONY: e2e-test
e2e-test:
	VP_COUNT="$(VP_COUNT)" \
	RUNTIME_CONFIG="$(RUNTIME_CONFIG)" \
	./e2e-test.sh

.PHONY: e2e-k8s-setup
e2e-k8s-setup:
	./e2e-k8s-setup.sh

.PHONY: e2e-k8s-test
e2e-k8s-test:
	VP_COUNT="$(VP_COUNT)" \
	./e2e-k8s-test.sh

.PHONY: check
check:
	bash -n build.sh build-kernel.sh run.sh e2e-setup.sh e2e-test.sh \
		e2e-k8s-setup.sh e2e-k8s-test.sh init
	jq empty manifest.json manifest-rootfs.json e2e-pod.json \
		e2e-container.json

.PHONY: clean
clean:
	rm -rf -- "$(OUT_DIR)"
