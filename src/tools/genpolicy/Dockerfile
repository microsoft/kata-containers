# syntax=docker/dockerfile:1.4

############################################
# 1) Builder stage – compile genpolicy     #
############################################
FROM rust:1.84.0-slim-bullseye AS builder

# 1.1) Install glibc‐based build dependencies
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
      cmake && \
    rm -rf /var/lib/apt/lists/*

# 1.2) Emit a default containerd config (so that any `make -C ../../agent` step still sees a config file)
RUN containerd config default >/etc/containerd/config.toml

# 1.4) All COPYs are relative to /usr/src from here on
WORKDIR /usr/src

# 1.5) Copy utils.mk → /usr/src/utils.mk so that
#      genpolicy/Makefile (which does `include ../../../utils.mk`) can find it
COPY utils.mk ./utils.mk

# 1.6) Copy the entire src/ folder (including tools/genpolicy, agent, libs/…, etc.)
#      This ensures that:
#        - /usr/src/src/tools/genpolicy
#        - /usr/src/src/agent
#        - /usr/src/src/libs/kata-sys-util
#      all exist, matching what the workspace & Makefiles expect.
COPY src/ ./src/

# 1.7) Change into genpolicy and build with GNU (glibc) linking
WORKDIR /usr/src/src/tools/genpolicy

#      This "make" invocation (with LIBC=gnu) puts the final binary at:
#        /usr/src/src/tools/genpolicy/target/x86_64-unknown-linux-gnu/debug/genpolicy
RUN make LIBC=gnu BUILD_TYPE=

############################################
# 2) Export stage – grab the GNU binary   #
############################################
FROM scratch AS export

# Copy the gnu‐linked binary out of the builder, from the exact path where `make` put it:
COPY --from=builder \
     /usr/src/src/tools/genpolicy/target/x86_64-unknown-linux-gnu/debug/genpolicy \
     /genpolicy