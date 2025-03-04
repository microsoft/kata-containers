# Kata Containerized Testing Tool

A containerized testing framework for measuring system metrics in both Host VM and User VM (UVM) environments of Kata Confidential Containers.

## Overview
This tool provides a flexible framework for running tests in both standard container environments (Host VM) and Kata Confidential Containers (UVM) environments. It supports configurable test execution with expected value validation.

## Building the Testing Tool

### Prerequisites

- Go 1.21 or higher
- Docker
- Access to Azure Container Registry (ACR)

### Build Steps

1. Clone the repository

```
git clone https://github.com/kata-containers/kata-containers.git
cd kata-containers/testing-tool
```

2. Build the binary and the container

- Using Makefile
```
# Build both binary and container
make all

# Or build individually
make build      # Just the binary
make docker     # Just the container
```
- Alternatively, build manually using 

```
# Build binary
go build -o kata-containerized-test-tool cmd/katatest/main.go

# Build container
docker build -t kata-test-container .
```

## Uploading to Azure Container Registry
1. Login to your Azure Container Registry

```
docker login yourregistry.azurecr.io
```

2. Tag the container image

```
docker tag kata-test-container yourregistry.azurecr.io/kata-test-container:v1
```

3. Push the image to ACR

```
docker push yourregistry.azurecr.io/kata-test-container:v1
```
## Running Tests

### Pull Container Images
First, pull the container image to your test environment:
```
# Pull using containerd
sudo ctr images pull --user '<username>:<password>' yourregistry.azurecr.io/kata-test-container:v1

# Or pull using crictl
sudo crictl pull yourregistry.azurecr.io/kata-test-container:v1
```
### Run manually 

#### Host VM
```
sudo ctr run \
    --runtime io.containerd.runc.v2 \
    -t --rm \
    --env ENABLED_TESTS=cpu,memory \
    --env TEST_CPU_EXPECTED_VCPU_COUNT=4 \
    --env TEST_MEMORY_EXPECTED_MEMORY_MB=8192 \
    yourregistry.azurecr.io/kata-test-container:v1 host-test
```

#### UVM
```
sudo ctr run \
    --cni \
    --runtime io.containerd.run.kata-cc.v2 \
    --runtime-config-path /opt/confidential-containers/share/defaults/kata-containers/configuration-clh-snp.toml \
    --snapshotter tardev \
    -t --rm \
    --env ENABLED_TESTS=cpu,memory \
    --env TEST_CPU_EXPECTED_VCPU_COUNT=2 \
    --env TEST_MEMORY_EXPECTED_MEMORY_MB=4096 \
    yourregistry.azurecr.io/kata-test-container:v1 uvm-test
```

### Run Using Pod Manifests

#### Test Configuration
- Selecting Tests
Use the ENABLED_TESTS environment variable with a comma-separated list of test names:
`ENABLED_TESTS=cpu,memory`
- Setting Expected Values: 
Use environment variables in the format `TEST_<TESTNAME>_<PARAMETER>`
```
TEST_CPU_EXPECTED_VCPU_COUNT=4
TEST_MEMORY_EXPECTED_MEMORY_MB=8192
```
You can create pod manifests with the test configurations to run the tests. 

For e.g. the following pod manifest runs the test for CPU and memory with relevant expected values.

```
apiVersion: v1
kind: Pod
metadata:
  name: kata-uvm-test
  annotations:
    io.kubernetes.cri.untrusted-workload: "true"
spec:
  runtimeClassName: kata-cc
  containers:
  - name: uvm-test
    image: yourregistry.azurecr.io/kata-test-container:v1
    imagePullPolicy: IfNotPresent
    env:
    - name: ENABLED_TESTS
      value: "cpu,memory"
    - name: TEST_CPU_EXPECTED_VCPU_COUNT
      value: "2"
    - name: TEST_MEMORY_EXPECTED_MEMORY_MB
      value: "4096"
```

## Adding a New Test

To add a new test to the framework, follow these general steps:

1. Create a test file: Add a new test file in the internal/tests directory structure. The file should implement the Test interface with Name() and Run() methods.
2. Register your test: Update the main.go file to register your new test with the framework.
3. Document parameters: Add documentation for your test's expected parameters in the README.md file.
4. Build and deploy: Rebuild the container after adding your test, then push the updated container to your container registry.

Your new test will then be available and can be enabled through the configuration by including it in the ENABLED_TESTS list.

