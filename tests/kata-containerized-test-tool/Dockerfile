FROM mcr.microsoft.com/azurelinux/base/core:3.0

WORKDIR /app
COPY kata-containerized-test-tool .
RUN chmod +x /app/kata-containerized-test-tool

RUN tdnf update -y && tdnf install -y \
    util-linux \
    procps-ng \
    iproute \
    && tdnf clean all

RUN mkdir -p /results

# Default environment variables
ENV ENABLED_TESTS=""

ENTRYPOINT ["/app/kata-containerized-test-tool"]
CMD ["--output", "/results"]