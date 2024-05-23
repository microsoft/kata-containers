# Cloud Hypervisor OpenAPI generated code

This directory provide tools to generate code client based
on `cloud-hypervisor` `OpenAPI` schema.

## Update client to match latest Cloud Hypervisor server API

Requirements:
 - docker: `openapi-generator` is executed in a docker container

```
make all
```

## Alternative: Update client to match latest Cloud Hypervisor server API

Make sure you have openapi-generator-cli installed
```
sudo npm install -g @openapitools/openapi-generator-cli
```

Update `cloud-hypervisor.yaml` as needed (e.g from https://github.com/microsoft/cloud-hypervisor/blob/msft-main/vmm/src/api/openapi/cloud-hypervisor.yaml)

Warning: currently, we need to include 72558d65d7dae65cbbc265db222a838d14654691 and 7851d7e093bf7cdd93c318fa694f3559b52e0dbd if we just paste `cloud-hypervisor.yaml` from msft fork.

Then
```
sudo openapi-generator-cli generate -i cloud-hypervisor.yaml -g go -o client
```
