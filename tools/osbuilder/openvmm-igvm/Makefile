OPENVMM_DIR ?= $(HOME)/openvmm-snp-mshv-aci-igvm
OUT_DIR ?= $(CURDIR)/out
KERNEL ?=
BUSYBOX ?=
KATA_IMAGE ?=
ROOT_HASH_FILE ?= $(CURDIR)/../root_hash_.txt

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
	@echo "  make agent-dmverity-igvm KERNEL=<bzImage>"
	@echo "  make agent-dmverity-run KATA_IMAGE=<kata-containers.img>"
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
	EXTRA_KERNEL_ARGS='memmap=4K$$0x416b000' \
	OUTPUT_NAME="kata-aci-agent-dmverity-reserve-416b-1vp.bin" \
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
	IGVM="$(OUT_DIR)/kata-aci-agent-dmverity-reserve-416b-1vp.bin" \
	KATA_IMAGE="$(KATA_IMAGE)" \
	./run.sh

.PHONY: check
check:
	bash -n build.sh build-kernel.sh run.sh init
	jq empty manifest.json manifest-rootfs.json

.PHONY: clean
clean:
	rm -rf -- "$(OUT_DIR)"
