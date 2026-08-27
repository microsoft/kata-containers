OPENVMM_DIR ?= $(HOME)/openvmm-snp-mshv-aci-igvm
OUT_DIR ?= $(CURDIR)/out
KERNEL ?=
BUSYBOX ?=
KATA_IMAGE ?=
ROOT_HASH_FILE ?= $(CURDIR)/../root_hash_.txt
RUNTIME_CONFIG ?= $(CURDIR)/out/configuration-openvmm-snp-runtime-rs.toml
VP_COUNT ?= 2
AGENT_IGVM = $(OUT_DIR)/kata-aci-agent-dmverity-reserve-416b-$(VP_COUNT)vp.bin

OPENVMM ?= $(OPENVMM_DIR)/target/release/openvmm
IGVMFILEGEN ?= $(OPENVMM_DIR)/target/release/igvmfilegen

.PHONY: help
help:
	@echo "OpenVMM SNP IGVM bring-up targets:"
	@echo "  make kernel BASE_KERNEL=<tested-aci-bzImage>"
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
	BASE_KERNEL="$(BASE_KERNEL)" \
	BUILD_DIR="$(BUILD_DIR)" \
	./build-kernel.sh

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
	./run.sh

.PHONY: shell-disk-run
shell-disk-run:
	@test -n "$(KATA_IMAGE)" || \
		{ echo "ERROR: set KATA_IMAGE to kata-containers.img" >&2; exit 1; }
	OPENVMM="$(OPENVMM)" \
	IGVM="$(OUT_DIR)/kata-aci-shell-reserve-416b-1vp.bin" \
	KATA_IMAGE="$(KATA_IMAGE)" \
	./run.sh

.PHONY: agent-dmverity-run
agent-dmverity-run:
	@test -n "$(KATA_IMAGE)" || \
		{ echo "ERROR: set KATA_IMAGE to kata-containers.img" >&2; exit 1; }
	OPENVMM="$(OPENVMM)" \
	IGVM="$(AGENT_IGVM)" \
	KATA_IMAGE="$(KATA_IMAGE)" \
	./run.sh

.PHONY: e2e-setup
e2e-setup:
	OPENVMM_DIR="$(OPENVMM_DIR)" \
	KERNEL="$(KERNEL)" \
	KATA_IMAGE="$(KATA_IMAGE)" \
	ROOT_HASH_FILE="$(ROOT_HASH_FILE)" \
	IGVM="$(AGENT_IGVM)" \
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
