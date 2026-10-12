# check=skip=InvalidDefaultArgInFrom
# InvalidDefaultArgInFrom: Suppresses "Default value for ARG golang:${GO_VERSION}-alpine results in empty or invalid base image name" as GO_VERSION is supplied from Makefile
# Copyright (c) 2019 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

ARG GO_VERSION=

FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /go/src/kata-pod-annotate

COPY . ./
RUN CGO_ENABLED=0 go build -o /go/bin/kata-pod-annotate

# Built only by `make docker-genpolicy`, which stages genpolicy/ first.
FROM mcr.microsoft.com/azurelinux/base/core:3.0 AS genpolicy
# genpolicy must rebuild containerd's EROFS layers bit for bit: match the host's erofs-utils.
RUN tdnf install -y ca-certificates erofs-utils-1.8.5-3.azl3 && tdnf clean all
COPY --from=builder /go/bin/kata-pod-annotate /kata-pod-annotate
COPY genpolicy/genpolicy /usr/local/bin/genpolicy
COPY genpolicy/etc/ /etc/genpolicy/
ENTRYPOINT ["/kata-pod-annotate"]

FROM alpine:3.19
COPY --from=builder /go/bin/kata-pod-annotate /kata-pod-annotate
ENTRYPOINT ["/kata-pod-annotate"]

