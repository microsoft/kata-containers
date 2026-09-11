# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

ARG KUBERNETES_VERSION=v1.36.3
ARG CONTAINERD_VERSION=v2.3.5
ARG RUNC_VERSION=v1.2.8
ARG ETCD_VERSION=v3.5.21
ARG CNI_PLUGINS_VERSION=v1.7.1

FROM registry.k8s.io/pause:3.10 AS pause
FROM busybox:1.36.1 AS busybox
FROM docker.io/library/registry:2.8.3 AS registry

FROM debian:bookworm-slim AS component-downloader
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

FROM component-downloader AS kubernetes-binaries
ARG TARGETARCH=amd64
ARG KUBERNETES_VERSION
RUN set -eux; \
    mkdir -p /out; \
    for binary in kube-apiserver kubelet kubectl; do \
        curl -fsSLo "/out/${binary}" \
            "https://dl.k8s.io/release/${KUBERNETES_VERSION}/bin/linux/${TARGETARCH}/${binary}"; \
        chmod 0755 "/out/${binary}"; \
    done

FROM component-downloader AS runtime-binaries
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG TARGETARCH=amd64
ARG CONTAINERD_VERSION
ARG RUNC_VERSION
ARG ETCD_VERSION
RUN set -eux; \
    mkdir -p /out /tmp/containerd; \
    curl -fsSL \
        "https://github.com/etcd-io/etcd/releases/download/${ETCD_VERSION}/etcd-${ETCD_VERSION}-linux-${TARGETARCH}.tar.gz" \
        | tar -xz --strip-components=1 -C /out \
            "etcd-${ETCD_VERSION}-linux-${TARGETARCH}/etcd" \
            "etcd-${ETCD_VERSION}-linux-${TARGETARCH}/etcdctl"; \
    curl -fsSL \
        "https://github.com/containerd/containerd/releases/download/${CONTAINERD_VERSION}/containerd-${CONTAINERD_VERSION#v}-linux-${TARGETARCH}.tar.gz" \
        | tar -xz -C /tmp/containerd; \
    install -m 0755 \
        /tmp/containerd/bin/containerd \
        /tmp/containerd/bin/containerd-shim-runc-v2 \
        /tmp/containerd/bin/ctr \
        /out/; \
    curl -fsSLo /out/runc.real \
        "https://github.com/opencontainers/runc/releases/download/${RUNC_VERSION}/runc.${TARGETARCH}"; \
    chmod 0755 /out/runc.real

FROM component-downloader AS cni-binaries
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG TARGETARCH=amd64
ARG CNI_PLUGINS_VERSION
RUN set -eux; \
    mkdir -p /out /tmp/cni; \
    curl -fsSL \
        "https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/cni-plugins-linux-${TARGETARCH}-${CNI_PLUGINS_VERSION}.tgz" \
        | tar -xz -C /tmp/cni; \
    install -m 0755 \
        /tmp/cni/bridge \
        /tmp/cni/host-local \
        /tmp/cni/loopback \
        /tmp/cni/portmap \
        /out/

FROM debian:bookworm-slim AS erofs-utils-builder
ARG EROFS_UTILS_VERSION=1.8.4
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        autoconf automake build-essential ca-certificates curl liblz4-dev \
        libtool pkg-config uuid-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    curl -fsSLo /tmp/erofs-utils.tar.gz \
        "https://git.kernel.org/pub/scm/linux/kernel/git/xiang/erofs-utils.git/snapshot/erofs-utils-${EROFS_UTILS_VERSION}.tar.gz"; \
    tar -xzf /tmp/erofs-utils.tar.gz -C /tmp; \
    cd "/tmp/erofs-utils-${EROFS_UTILS_VERSION}"; \
    ./autogen.sh; \
    ./configure --enable-lz4; \
    make -j"$(nproc)"; \
    make install

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates conntrack cryptsetup-bin curl dmsetup iproute2 iptables \
        kmod liblz4-1 libuuid1 openssl python3 python3-yaml tar udev \
        util-linux zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=kubernetes-binaries /out/ /usr/local/bin/
COPY --from=runtime-binaries /out/ /usr/local/bin/
COPY --from=cni-binaries /out/ /opt/cni/bin/
COPY --from=registry /bin/registry /usr/local/bin/registry
COPY --from=erofs-utils-builder /usr/local/bin/mkfs.erofs /usr/local/bin/mkfs.erofs
COPY src/tools/genpolicy/nested-policy-compat/build/genpolicy /usr/local/bin/genpolicy
COPY --from=pause /pause /opt/genpolicy/rootfs/pause/pause
COPY --from=busybox / /opt/genpolicy/rootfs/busybox
RUN mkdir -p /opt/genpolicy/rootfs/busybox/work

COPY src/tools/genpolicy/nested-policy-compat/appliance /opt/genpolicy/appliance
COPY src/tools/genpolicy/rules.rego /opt/genpolicy/policy/rules.rego
COPY src/tools/genpolicy/nested-policy-compat/tests/policy/create-sandbox-reasons.rego.inc \
    /opt/genpolicy/policy/create-sandbox-reasons.rego.inc
COPY src/tools/genpolicy/genpolicy-settings.json \
    /opt/genpolicy/policy/settings/genpolicy-settings.json
COPY src/tools/genpolicy/nested-policy-compat/appliance/policy-settings.d \
    /opt/genpolicy/policy/settings/genpolicy-settings.d
COPY src/tools/genpolicy/nested-policy-compat/config \
    /opt/nested-policy-compat/config
COPY src/tools/genpolicy/nested-policy-compat/scripts \
    /opt/nested-policy-compat/scripts

RUN set -eux; \
    mkdir -p /opt/genpolicy/registry-tls; \
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -subj "/CN=nested-policy-compat-registry" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth" \
        -addext "subjectAltName=IP:10.188.0.1" \
        -keyout /opt/genpolicy/registry-tls/registry.key \
        -out /opt/genpolicy/registry-tls/registry.crt; \
    printf '\n' >>/opt/genpolicy/policy/rules.rego; \
    cat /opt/genpolicy/policy/create-sandbox-reasons.rego.inc \
        >>/opt/genpolicy/policy/rules.rego; \
    chmod 0755 /opt/genpolicy/appliance/scripts/*.sh \
        /opt/nested-policy-compat/scripts/*.sh \
        /opt/nested-policy-compat/scripts/*.py; \
    mkdir -p /opt/genpolicy/images; \
    python3 /opt/genpolicy/appliance/scripts/make_oci_image.py \
        --rootfs /opt/genpolicy/rootfs/pause \
        --reference genpolicy.local:5000/pause:3.10 \
        --entrypoint '["/pause"]' \
        --user 65535:65535 \
        --output /opt/genpolicy/images/pause.tar; \
    python3 /opt/genpolicy/appliance/scripts/make_oci_image.py \
        --rootfs /opt/genpolicy/rootfs/busybox \
        --reference genpolicy.local:5000/busybox:1.36.1 \
        --entrypoint '["/bin/busybox","sleep","3600"]' \
        --output /opt/genpolicy/images/busybox.tar; \
    rm -rf /opt/genpolicy/rootfs

ARG PROFILE_NAME=k8s-1.36-containerd-2.3-erofs-dmverity
ARG INPUT_FINGERPRINT=unknown
LABEL io.katacontainers.nested-policy-compat.input-fingerprint="${INPUT_FINGERPRINT}"
ENV PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV GENPOLICY_APPLIANCE_ROOT=/opt/genpolicy/appliance
ENV GENPOLICY_PROFILE_NAME=${PROFILE_NAME}
ENV NESTED_POLICY_COMPAT_ROOT=/opt/nested-policy-compat

ENTRYPOINT ["/opt/nested-policy-compat/scripts/entrypoint.sh"]
