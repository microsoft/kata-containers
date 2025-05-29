# syntax=docker/dockerfile:1.4
FROM rust:1.84.0-slim AS builder

# Install everything needed to compile both your agent and genpolicy,
# including OpenSSL and its Perl-dependent build system.
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

# Your bare‐metal step
RUN containerd config default >/etc/containerd/config.toml

ARG LIBC=gnu
ARG BUILD_TYPE=release
ENV LIBC=${LIBC} BUILD_TYPE=${BUILD_TYPE}

# Mirror your repo under /usr/src
WORKDIR /usr/src
COPY utils.mk .
COPY src src

# Build from the genpolicy directory (will pull in agent, libs, etc.)
WORKDIR /usr/src/src/tools/genpolicy
RUN make

############################################
# 2) Runtime stage – standalone image     #
############################################
FROM debian:bookworm-slim AS runtime

# Only the libs your binary actually needs at runtime:
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      libseccomp2 && \
    rm -rf /var/lib/apt/lists/*

# Copy the genpolicy binary that your builder just produced:
ARG BUILD_TYPE=release
COPY --from=builder \
     /usr/src/src/tools/genpolicy/target/x86_64-unknown-linux-gnu/${BUILD_TYPE}/genpolicy \
     /usr/local/bin/genpolicy

RUN chmod +x /usr/local/bin/genpolicy

# Now any args you pass to the container are forwarded to genpolicy:
ENTRYPOINT ["genpolicy"]
CMD ["--help"]