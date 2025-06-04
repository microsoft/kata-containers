# syntax=docker/dockerfile:1.4

############################################
# 1) Builder stage – compile genpolicy     #
############################################
FROM rust:1.84.0-slim AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      clang \
      libclang-dev \
      pkg-config \
      perl \
      protobuf-compiler \
      libdevmapper-dev \
      libseccomp-dev \
      containerd \
      libssl-dev \
      zlib1g-dev \
      cmake \
      musl-tools && \
    rm -rf /var/lib/apt/lists/*

# Ensure containerd config exists (same as before)
RUN containerd config default >/etc/containerd/config.toml

RUN rustup target add x86_64-unknown-linux-musl

ARG BUILD_TYPE=release
ENV BUILD_TYPE=${BUILD_TYPE}

# Copy everything from your repo root (we assume Docker build context is repo root)
WORKDIR /usr/src
COPY utils.mk . 
COPY src src

# Now build “genpolicy” for musl:
WORKDIR /usr/src/src/tools/genpolicy

# If your Makefile accepts something like “TARGET=…”, set it. 
# Otherwise replace the “make” line with a direct cargo invocation.
# For example, if `make` just calls `cargo build --release`, replace it:
RUN cargo build \
      --release \
      --target x86_64-unknown-linux-musl

############################################
# 2) Export stage – make the static binary #
############################################
FROM scratch AS export

# Copy the musl‐linked genpolicy into /
COPY --from=builder \
     /usr/src/src/tools/genpolicy/target/x86_64-unknown-linux-musl/release/genpolicy \
     /genpolicy