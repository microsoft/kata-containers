FROM mcr.microsoft.com/azurelinux/base/core:3.0

WORKDIR /app
COPY kata-containerized-test-tool .
RUN chmod +x /app/kata-containerized-test-tool

# Install dependencies
RUN tdnf update -y
RUN tdnf install -y util-linux procps-ng iproute dotnet-sdk-9.0 aspnetcore-runtime-9.0 zlib icu bash curl golang rust cargo build-essential protobuf-compiler protobuf-devel expect openssl-devel clang-devel libseccomp-devel btrfs-progs-devel device-mapper-devel cmake fuse-devel

# Install BinSkim
RUN dotnet new console -n TempConsoleApp && \
    cd TempConsoleApp && \
    dotnet add package Microsoft.CodeAnalysis.BinSkim --version 1.9.5
RUN ln -sf ~/.nuget/packages/microsoft.codeanalysis.binskim/1.9.5/tools/netcoreapp3.1/linux-x64/BinSkim /usr/local/bin/binskim

# Install Go tools
RUN go install github.com/sonatype-nexus-community/nancy@latest
RUN go install golang.org/x/vuln/cmd/govulncheck@latest

ENV PATH="/root/go/bin:${PATH}"
RUN tdnf clean all

RUN mkdir -p /results

# Copy the entrypoint script
COPY kata-container-test.sh /app/
RUN chmod +x /app/kata-container-test.sh

ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1

# Set the entrypoint to our custom script
ENTRYPOINT ["/app/kata-container-test.sh"]