# Example drop-ins for genpolicy settings

Copy the drop-in file(s) you need into the `genpolicy-settings.d/` subdirectory next to your `genpolicy-settings.json`, then point `genpolicy -j` at the parent directory. For example:

```
my-settings/
  genpolicy-settings.json
  genpolicy-settings.d/
    10-non-coco-drop-in.json
    20-oci-1.2.1-drop-in.json
```

```sh
genpolicy -j my-settings/ ...
```

Each drop-in is an [RFC 6902 JSON Patch](https://datatracker.ietf.org/doc/html/rfc6902): a JSON array of operations (`add`, `remove`, `replace`, `move`, `copy`, `test`). Use `replace` for existing paths, `add` for new keys or array append (path ending in `/-`), and optional `test` to assert values before changing them.

Drop-ins are layered: `10-*` files set the platform base, `20-*` files overlay OCI version and other adjustments. You can combine multiple drop-ins (e.g. `10-non-coco-drop-in.json` + `20-oci-1.2.1-drop-in.json`).

| Drop-in file | Use case |
|--------------|----------|
| `10-non-coco-drop-in.json` | Non-confidential guest (e.g. standard VMs) |
| `10-non-coco-aks-drop-in.json` | Non-confidential guest on AKS |
| `10-non-coco-aks-cbl-mariner-drop-in.json` | Non-confidential guest on AKS with CBL-Mariner host |
| `10-guest-pull-drop-in.json` | Confidential guest that pulls images **inside the guest** (e.g. `qemu-coco-dev` with the Nydus snapshotter) |
| `20-oci-1.2.0-drop-in.json` | OCI bundle version 1.2.0 |
| `20-oci-1.2.1-drop-in.json` | OCI bundle version 1.2.1 (e.g. k3s, rke2, NVIDIA GPU, CBL-Mariner) |
| `20-oci-1.3.0-drop-in.json` | OCI bundle version 1.3.0 (e.g. containerd 2.2.x) |
| `20-experimental-force-guest-pull-drop-in.json` | Disable guest pull |

Request/exec overrides (e.g. allowing `kubectl exec` or specific ttRPC requests) are not shipped as drop-in examples; build your own drop-in or merge the needed `request_defaults` into a local file in `genpolicy-settings.d/`.

## Guest pull re-opens a path the defaults deliberately close

`10-guest-pull-drop-in.json` sets `allow_guest_pull_images`, and that is a
security decision, not a compatibility knob. The shipped default is `false`
because an `image_guest_pull` storage is the one storage path with no policy
declaration behind it: `allow_storages` subtracts it from the declared-vs-presented
count, so a host can present one *in addition to* a container's declared layers and
mount undeclared content at the container root without failing a verity check.
Content verification for a guest pull happens in image-rs inside CDH, which returns
no proof to the agent, so the policy binds the image *reference* but cannot confirm
the bytes that arrived.

Use this drop-in only where the cluster genuinely pulls inside the guest, and keep
`require_pinned_image_digests` set — with no dm-verity root hash to bind, the manifest
digest is the only thing identifying the content. Deployments that can pull on the
host should prefer the default `host-erofs-dm-verity`, which declares and verity-binds
every layer, the pause image included.
