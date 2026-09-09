# Self-contained appliance

This directory contains the control-plane configuration and scripts required by
`nested-policy-compat`. Building and running the harness uses only files from
the current checkout; it does not require another branch, repository checkout,
or prebuilt appliance image.

The entrypoint starts the pinned Kubernetes/containerd control plane, imports
fixture images, submits the workload, and remains alive while the parent
harness collects the authoritative nested-Agent verdict.

## Directory layout

- `profiles/*.env` defines a build profile. A profile is a text file containing
  Kubernetes, containerd, etcd, runc, and CNI version pins plus runtime
  metadata; it is not a container image.
- `profiles/erofs-dmverity.settings.json` is shared by the EROFS profiles.
- `profiles/guest-pull.settings.json` enables strict digest-pinned guest pull
  for current containerd.
- `profiles/guest-pull-containerd-1.7.settings.json` also selects OCI 1.1.0 for
  the older containerd request format.
- `config/` contains the kubelet and CNI configuration copied into every
  appliance image.
- `policy-settings.d/` contains settings applied to every policy-generation
  run.
- `scripts/` contains the control-plane entrypoint and helpers embedded in the
  appliance image.

The repository has one shared Dockerfile:

```text
src/tools/genpolicy/nested-policy-compat/Dockerfile
```

There is no Dockerfile per Kubernetes version. The defaults written in that
Dockerfile support a direct build, but `make image` overrides them with values
from the selected profile.

## Building a profile image

For example:

```bash
make -C src/tools/genpolicy/nested-policy-compat \
  PROFILE=k8s-1.33-containerd-2.3-erofs-dmverity image
```

The Makefile performs these steps:

1. Includes
   `appliance/profiles/k8s-1.33-containerd-2.3-erofs-dmverity.env`.
2. Builds GenPolicy from the current checkout and stages it at
   `nested-policy-compat/build/genpolicy`.
3. Invokes the shared Dockerfile with explicit build arguments. For this
   profile, `KUBERNETES_VERSION=v1.33.13` overrides the Dockerfile's
   `v1.36.3` default.
4. Tags the image as
   `nested-policy-compat:k8s-1.33-containerd-2.3-erofs-dmverity`.

The Kubernetes 1.36 EROFS profile follows the same flow. Guest-pull profiles
use the same Dockerfile and produce:

```text
nested-policy-compat:k8s-1.33-containerd-1.7-guest-pull
nested-policy-compat:k8s-1.36-containerd-2.3-guest-pull
```

The Dockerfile downloads Kubernetes, containerd/etcd/runc, and CNI binaries in
independent build stages. Switching between profiles therefore reuses
unmodified component stages where version pins match. The CNI stage copies only the
`bridge`, `host-local`, `loopback`, and `portmap` plugins used by the appliance
configuration rather than storing the complete plugin archive.

Set `IMAGE` to choose another tag:

```bash
make -C src/tools/genpolicy/nested-policy-compat \
  PROFILE=k8s-1.33-containerd-2.3-erofs-dmverity \
  IMAGE=example.com/testing/nested-policy-compat:k8s-1.33 image
```

## Where images are stored

The build does not write a container-image archive under `appliance/` or
commit an image to the repository. It stores the tagged image in the local
image store of the selected container engine:

- Podman is preferred when both Podman and Docker are installed;
- otherwise Docker is used;
- set `CONTAINER_ENGINE` to select one explicitly.

List the result with:

```bash
podman image ls nested-policy-compat
# or
docker image ls nested-policy-compat
```

Podman may display an unqualified local tag with a `localhost/` prefix. The
harness does not push profile images to a registry; pushing or saving an image
is an explicit external step.
