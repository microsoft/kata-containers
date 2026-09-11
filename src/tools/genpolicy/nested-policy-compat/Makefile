# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

SHELL := /bin/bash

REPO_ROOT := $(abspath ../../../..)
PROFILE ?= k8s-1.36-containerd-2.3-erofs-dmverity
IMAGE ?= nested-policy-compat:$(PROFILE)
CONTAINER_ENGINE ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
KATA_ROOT ?= /opt/kata
KATA_CONFIG ?= $(KATA_ROOT)/share/defaults/kata-containers/runtime-rs/configuration-nested-policy-compat.toml
KATA_ARTIFACT_IMAGE ?= quay.io/kata-containers/kata-deploy-ci:kata-containers-latest
KATA_ARTIFACT_DIR ?=
FLAT_VMDK_CLOUD_HYPERVISOR_REPO ?= https://github.com/cloud-hypervisor/cloud-hypervisor.git
FLAT_VMDK_CLOUD_HYPERVISOR_COMMIT ?= f50661fffd0fef38ddfec88c5fafa93f9779149a
APPROVE_KATA_INSTALL ?= no
GENPOLICY_TARGET ?= x86_64-unknown-linux-musl
GENPOLICY_BIN ?= $(REPO_ROOT)/target/$(GENPOLICY_TARGET)/release/genpolicy
GENPOLICY_STAGE := $(CURDIR)/build/genpolicy

PROFILE_FILE := $(CURDIR)/appliance/profiles/$(PROFILE).env
ifeq ($(wildcard $(PROFILE_FILE)),)
$(error unknown PROFILE "$(PROFILE)")
endif
include $(PROFILE_FILE)

.PHONY: image ensure-image ensure-host-environment prepare-kata-stack verify-kata-provenance ensure-kata-provenance validate genpolicy-bin fixture-e2e ci-fixture-e2e runtime-operations-e2e termination-log-e2e custom-service-account-e2e clean

image: $(GENPOLICY_STAGE)
	@test -n "$(CONTAINER_ENGINE)" || { echo "docker or podman is required"; exit 1; }
	@input_fingerprint="$$(./scripts/image_input_fingerprint.sh \
		"$(REPO_ROOT)" "$(PROFILE_FILE)" "$(KATA_ROOT)" "$(KATA_CONFIG)")"; \
	$(CONTAINER_ENGINE) build \
		--file $(CURDIR)/Dockerfile \
		--build-arg PROFILE_NAME=$(PROFILE_NAME) \
		--build-arg KUBERNETES_VERSION=$(KUBERNETES_VERSION) \
		--build-arg CONTAINERD_VERSION=$(CONTAINERD_VERSION) \
		--build-arg RUNC_VERSION=$(RUNC_VERSION) \
		--build-arg ETCD_VERSION=$(ETCD_VERSION) \
		--build-arg CNI_PLUGINS_VERSION=$(CNI_PLUGINS_VERSION) \
		--build-arg INPUT_FINGERPRINT="$${input_fingerprint}" \
		--tag $(IMAGE) \
		$(REPO_ROOT)

ensure-image:
	@test -n "$(CONTAINER_ENGINE)" || { echo "docker or podman is required"; exit 1; }
	@expected="$$(./scripts/image_input_fingerprint.sh \
		"$(REPO_ROOT)" "$(PROFILE_FILE)" "$(KATA_ROOT)" "$(KATA_CONFIG)")"; \
	actual="$$( \
		$(CONTAINER_ENGINE) image inspect \
			--format '{{ index .Config.Labels "io.katacontainers.nested-policy-compat.input-fingerprint" }}' \
			"$(IMAGE)" 2>/dev/null || true \
	)"; \
	if [[ "$${actual}" == "$${expected}" ]]; then \
		echo "reusing current appliance image: $(IMAGE)"; \
	else \
		if [[ -n "$${actual}" ]]; then \
			echo "appliance inputs changed; rebuilding $(IMAGE)"; \
		else \
			echo "appliance image missing or unlabelled; building $(IMAGE)"; \
		fi; \
		$(MAKE) image; \
	fi

ensure-host-environment:
	APPROVE_KATA_INSTALL="$(APPROVE_KATA_INSTALL)" \
		GENPOLICY_TARGET="$(GENPOLICY_TARGET)" \
		KATA_ARTIFACT_DIR="$(KATA_ARTIFACT_DIR)" \
		KATA_ARTIFACT_IMAGE="$(KATA_ARTIFACT_IMAGE)" \
		FLAT_VMDK_CLOUD_HYPERVISOR_REPO="$(FLAT_VMDK_CLOUD_HYPERVISOR_REPO)" \
		FLAT_VMDK_CLOUD_HYPERVISOR_COMMIT="$(FLAT_VMDK_CLOUD_HYPERVISOR_COMMIT)" \
		ROOTFS_MODE="$(ROOTFS_MODE)" \
		./scripts/ensure_host_environment.sh \
		"$(KATA_ROOT)" "$(KATA_CONFIG)" "$(CONTAINER_ENGINE)"

prepare-kata-stack:
	./scripts/rebuild_kata_stack.sh \
		"$(REPO_ROOT)" "$(KATA_ROOT)" "$(KATA_CONFIG)" "$(CONTAINER_ENGINE)"
	$(MAKE) verify-kata-provenance

verify-kata-provenance:
	./scripts/verify_kata_source_provenance.sh \
		"$(REPO_ROOT)" "$(KATA_ROOT)" "$(KATA_CONFIG)"

ensure-kata-provenance:
	./scripts/ensure_kata_source_provenance.sh \
		"$(REPO_ROOT)" "$(KATA_ROOT)" "$(KATA_CONFIG)" "$(CONTAINER_ENGINE)"

validate:
	./tests/validate.sh

genpolicy-bin:
	$(MAKE) --always-make \
		--directory $(REPO_ROOT)/src/tools/genpolicy \
		src/version.rs
	cargo build --locked --release --package genpolicy \
		--target $(GENPOLICY_TARGET) \
		--manifest-path $(REPO_ROOT)/Cargo.toml

$(GENPOLICY_STAGE): genpolicy-bin
	mkdir -p $(dir $@)
	cp $(GENPOLICY_BIN) $@

define run_fixture_e2e
	CONTAINER_ENGINE="$(CONTAINER_ENGINE)" \
		NESTED_IMAGE="$(IMAGE)" \
		KATA_ROOT="$(KATA_ROOT)" \
		KATA_CONFIG="$(KATA_CONFIG)" \
		FIXTURES="$(FIXTURES)" \
		POD_READY_TIMEOUT="$(POD_READY_TIMEOUT)" \
		OUTPUT_ROOT="$(OUTPUT_ROOT)" \
		./tests/fixture-matrix-e2e.sh
endef

fixture-e2e: ensure-host-environment ensure-kata-provenance ensure-image
	$(run_fixture_e2e)

ci-fixture-e2e: APPROVE_KATA_INSTALL := no
ci-fixture-e2e: ensure-host-environment verify-kata-provenance ensure-image
	$(run_fixture_e2e)

runtime-operations-e2e: FIXTURES := runtime-operations-workload.yaml
runtime-operations-e2e: fixture-e2e

termination-log-e2e: FIXTURES := termination-log-workload.yaml
termination-log-e2e: fixture-e2e

custom-service-account-e2e: FIXTURES := custom-service-account-workload.yaml
custom-service-account-e2e: fixture-e2e

clean:
	rm -rf bin build
