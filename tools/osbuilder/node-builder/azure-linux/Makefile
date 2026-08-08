# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
BUILD_TYPE := release

export SHIM_REDEPLOY_CONFIG := yes
export USE_RUNTIME_RS := no
export BUILD_TARFS := no
export IGVM_KERNEL :=

# Forwarded to package_build.sh -> src/agent. STRICT_POLICY=yes pulls in the
# security reference monitor and implies USE_DEVMAPPER=yes.
STRICT_POLICY ?= no
USE_DEVMAPPER ?= yes
export STRICT_POLICY
export USE_DEVMAPPER

ifeq ($(BUILD_TYPE),debug)
	export AGENT_BUILD_TYPE := debug
	export AGENT_POLICY_FILE := allow-all.rego
	export SHIM_USE_DEBUG_CONFIG := yes
else
	export AGENT_BUILD_TYPE := release
	export AGENT_POLICY_FILE := allow-set-policy.rego
	export SHIM_USE_DEBUG_CONFIG := no
endif

.PHONY: all
all: package uvm

.PHONY: all-confpods
all-confpods: package-confpods uvm-confpods

.PHONY: package
package:
	./package_build.sh

.PHONY: package-confpods
package-confpods:
	CONF_PODS=yes USE_RUNTIME_RS=yes ./package_build.sh

.PHONY: uvm
uvm:
	./uvm_build.sh

.PHONY: uvm-confpods
uvm-confpods:
	CONF_PODS=yes ./uvm_build.sh

.PHONY: clean
clean:
	./clean.sh

.PHONY: clean-confpods
clean-confpods:
	CONF_PODS=yes USE_RUNTIME_RS=yes ./clean.sh

.PHONY: deploy
deploy: deploy-package deploy-uvm

.PHONY: deploy-package
deploy-package:
	./package_install.sh

.PHONY: deploy-package-tools
deploy-package-tools:
	./package_tools_install.sh

.PHONY: deploy-uvm
deploy-uvm:
	./uvm_install.sh

.PHONY: deploy-confpods
deploy-confpods: deploy-confpods-package deploy-confpods-uvm

.PHONY: deploy-confpods-package
deploy-confpods-package:
	CONF_PODS=yes USE_RUNTIME_RS=yes ./package_install.sh

.PHONY: deploy-confpods-package-tools
deploy-confpods-package-tools:
	CONF_PODS=yes USE_RUNTIME_RS=yes ./package_tools_install.sh

.PHONY: deploy-confpods-uvm
deploy-confpods-uvm:
	CONF_PODS=yes ./uvm_install.sh
