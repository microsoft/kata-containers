# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
.PHONY: all
all: package uvm

.PHONY: all-confpods
all-confpods: package-confpods uvm-confpods

.PHONY: package
package:
	./package_build.sh

.PHONY: package-confpods
package-confpods:
	CONF_PODS=yes ./package_build.sh

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
	CONF_PODS=yes ./clean.sh

.PHONY: deploy
deploy:
	./package_install.sh
	./uvm_install.sh

.PHONY: deploy-confpods
deploy-confpods:
	CONF_PODS=yes ./package_install.sh
	CONF_PODS=yes ./uvm_install.sh
