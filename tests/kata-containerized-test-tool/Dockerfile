FROM mcr.microsoft.com/azurelinux/base/core:3.0

WORKDIR /app
COPY kata-containerized-test-tool .
RUN chmod +x /app/kata-containerized-test-tool

# Install dependencies
RUN tdnf update -y
RUN tdnf install -y util-linux procps-ng iproute dotnet-sdk-9.0 aspnetcore-runtime-9.0 zlib icu bash curl rust cargo build-essential protobuf-compiler protobuf-devel expect openssl-devel clang-devel libseccomp-devel btrfs-progs-devel device-mapper-devel cmake fuse-devel

# Install BinSkim
RUN dotnet new console -n TempConsoleApp && \
    cd TempConsoleApp && \
    dotnet add package Microsoft.CodeAnalysis.BinSkim --version 1.9.5
RUN ln -sf ~/.nuget/packages/microsoft.codeanalysis.binskim/1.9.5/tools/netcoreapp3.1/linux-x64/BinSkim /usr/local/bin/binskim

# Install Go tools
RUN curl -L https://go.dev/dl/go1.21.1.linux-amd64.tar.gz | tar -C /usr/local -xzf -
ENV PATH="/usr/local/go/bin:${PATH}"
RUN go install github.com/sonatype-nexus-community/nancy@latest
RUN go install golang.org/x/vuln/cmd/govulncheck@latest

ENV PATH="/root/go/bin:${PATH}"
RUN tdnf clean all

RUN mkdir -p /results
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1


ENTRYPOINT ["/app/kata-containerized-test-tool"]
CMD ["--output", "/results"]