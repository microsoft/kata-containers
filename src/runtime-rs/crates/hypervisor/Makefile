# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# On-demand regeneration of the vendored OpenVMM TTRPC `vmservice` proto.
#
# This mirrors the Cloud Hypervisor client workflow
# (src/runtime/virtcontainers/pkg/cloud-hypervisor/Makefile): it is a manual
# developer target, NOT part of the build. It fetches the proto at the OpenVMM
# revision pinned in versions.yaml. The fetched proto is checked in and compiled
# by build.rs (which regenerates the Rust bindings automatically on change), so
# normal builds need neither network nor this target.
#
# Usage:
#   make -C src/runtime-rs/crates/hypervisor update-proto

MK_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
VERSIONS_FILE := $(MK_DIR)../../../../versions.yaml
YQ_INSTALLER := $(MK_DIR)../../../../ci/install_yq.sh
PROTO_DIR := $(MK_DIR)src/openvmm/protos
VMSERVICE_PROTO_PATH := openvmm/openvmm_ttrpc_vmservice/src/vmservice.proto

YQ := $(shell command -v yq 2>/dev/null)

.PHONY: update-proto
update-proto:
ifndef YQ
	$(YQ_INSTALLER)
endif
	@set -e; \
	openvmm_url=$$(yq '.assets.hypervisor.openvmm.url' "$(VERSIONS_FILE)"); \
	case "$$openvmm_url" in \
		https://github.com/*) openvmm_repo=$${openvmm_url#https://github.com/} ;; \
		*) echo "error: OpenVMM URL must be a GitHub repository URL" >&2; exit 1 ;; \
	esac; \
	openvmm_repo=$${openvmm_repo%.git}; \
	openvmm_version=$$(yq '.assets.hypervisor.openvmm.version' "$(VERSIONS_FILE)"); \
	if [ -z "$$openvmm_version" ] || [ "$$openvmm_version" = "null" ]; then \
		echo "error: .assets.hypervisor.openvmm.version missing from $(VERSIONS_FILE)"; \
		exit 1; \
	fi; \
	echo "fetching vmservice.proto from $$openvmm_repo@$$openvmm_version"; \
	tmp=$$(mktemp "$(PROTO_DIR)/vmservice.proto.XXXXXX"); \
	trap 'rm -f "$$tmp"' EXIT; \
	curl -fSL "https://raw.githubusercontent.com/$$openvmm_repo/$$openvmm_version/$(VMSERVICE_PROTO_PATH)" \
		-o "$$tmp"; \
	chmod 644 "$$tmp"; \
	mv "$$tmp" "$(PROTO_DIR)/vmservice.proto"
