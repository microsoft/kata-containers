# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

IMAGE ?= quay.io/kata-containers/kata-webhook-example:latest
GO_VERSION ?= $(shell yq '.languages.golang.version' $(CURDIR)/../../../versions.yaml)

GENPOLICY_SRC = $(CURDIR)/../../../src/tools/genpolicy
GENPOLICY_BIN ?= $(CURDIR)/../../../target/$(shell uname -m)-unknown-linux-musl/release/genpolicy
# yes: the agent logs policy denials but allows the requests.
GENPOLICY_AUDIT ?= no

all: docker

docker:
	docker build \
	       -f $(CURDIR)/Dockerfile \
	       --build-arg GO_VERSION=$(GO_VERSION) \
	       -t $(IMAGE) \
	       $(CURDIR)

genpolicy-stage:
	$(MAKE) -C $(GENPOLICY_SRC) BUILD_TYPE=release LIBC=musl build
	rm -rf $(CURDIR)/genpolicy
	mkdir -p $(CURDIR)/genpolicy/etc/genpolicy-settings.d
	install -m 0755 $(GENPOLICY_BIN) $(CURDIR)/genpolicy/genpolicy
	cp $(GENPOLICY_SRC)/genpolicy-settings.json $(CURDIR)/genpolicy/etc/
	cp $(CURDIR)/genpolicy-settings.d/*.json $(CURDIR)/genpolicy/etc/genpolicy-settings.d/
	sed -e '$(if $(filter yes,$(GENPOLICY_AUDIT)),s/^default AllowRequestsFailingPolicy := false$$/default AllowRequestsFailingPolicy := true/)' \
		$(GENPOLICY_SRC)/rules.rego >$(CURDIR)/genpolicy/etc/rules.rego

docker-genpolicy: genpolicy-stage
	docker build \
	       -f $(CURDIR)/Dockerfile \
	       --target genpolicy \
	       --build-arg GO_VERSION=$(GO_VERSION) \
	       -t $(IMAGE) \
	       $(CURDIR)

.PHONY: all docker docker-genpolicy genpolicy-stage
