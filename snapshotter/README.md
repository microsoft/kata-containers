# cc-snapshotter
A containerd snapshotter for confidential containers.
Currently it adds dmverity protection to container base layers.

## Building

`go` must be installed on the machine and made availabe in the path.

To build, do

```bash
$ ./scripts/build
```

It will produce two executables

```bash
$ ls bin
cc-snapshotter  ctr-remote
```


`ctr-remote` is an drop-in replacement for `ctr` command that addes the `image rpull` subcommand which pulls a
given image using cc-snashotter.

## Setup

The snapshotter must be registered with continerd before it can be used.

### Register the snapshotter with containerd

Edit containerd's config file (typically `/etc/containerd/config.toml`) and add the following lines:

```toml
[proxy_plugins]
  [proxy_plugins."cc-snapshotter"]
    type = "snapshot"
    address = "/var/run/cc-snapshotter.sock"

```

Restart containerd service

``bash
sudo systemctl restart containerd
``

Verify that the snapshotter has been registered with containerd.
```bash
$ sudo ctr plugins ls
TYPE                            ID                       PLATFORMS      STATUS
...
io.containerd.snapshotter.v1    cc-snapshotter           -              ok

...
```

### Run the snapshotter service

Make sure that no other instance of the snapshotter is running. Delete the unix socket file if it is left over from a previous run.
```bash
$ sudo rm -f /var/run/cc-snapshotter.sock

$ sudo ./bin/cc-snapshotter run

```


## Usage

Use another prompt for the following commands.

Use `ctr-remote image rpull` command to pull and image using cc-snapshotter. The image will be pulled consistent with how the image will be pulled in Kubernetes using containerd's CRI plugin.

```bash
$ ./bin/ctr-remote image rpull docker.io/library/redis:latest
fetching sha256:d581aded... application/vnd.docker.distribution.manifest.list.v2+json
fetching sha256:31120dcd... application/vnd.docker.distribution.manifest.v2+json
fetching sha256:2e50d70b... application/vnd.docker.container.image.v1+json
```


Meanwhile the snapshotter will log the operations that it performs
```bash
Committed snapshot sha256:08249ce7456a1c0613eafe868aed936a284ed9f1d6144f7d2d08c514974a2af9
Preparing snapshot with key=default/76/extract-791654956-ZU8W sha256:1cc9e0fe288a20fc9a4c0972353bc4323714b98cb280c7f30a88330fd2e0c1af, parent=sha256:08249ce7456a1c0613eafe868aed936a284ed9f1d6144f7d2d08c514974a2af9
Committed snapshot sha256:1cc9e0fe288a20fc9a4c0972353bc4323714b98cb280c7f30a88330fd2e0c1af
Preparing snapshot with key=default/77/extract-807556011-P18P sha256:92fd29f93c5ed2985ef47d721abfd85917369726779e7fe91cd3e24d07ca1021, parent=sha256:1cc9e0fe288a20fc9a4c0972353bc4323714b98cb280c7f30a88330fd2e0c1af
Committed snapshot sha256:92fd29f93c5ed2985ef47d721abfd85917369726779e7fe91cd3e24d07ca1021
Preparing snapshot with key=default/78/extract-821577471-mmId sha256:51d7aab829870a1ea24dfc3cce7bec89d35d9a43c225370e5401d662837b9c80, parent=sha256:92fd29f93c5ed2985ef47d721abfd85917369726779e7fe91cd3e24d07ca1021
Committed snapshot sha256:51d7aab829870a1ea24dfc3cce7bec89d35d9a43c225370e5401d662837b9c80
Preparing snapshot with key=default/79/extract-837782621-cpVm sha256:e585188120ef8e14abfd097ebceba61cecdf56a85296a67e632fe17f9eed41d1, parent=sha256:51d7aab829870a1ea24dfc3cce7bec89d35d9a43c225370e5401d662837b9c80
Committed snapshot sha256:e585188120ef8e14abfd097ebceba61cecdf56a85296a67e632fe17f9eed41d1
Preparing snapshot with key=default/80/extract-851657132-x00Q sha256:bf318baa6aa554c3aea31b9c91c986cf7b33be4afd5ac5562fc94e88fceb9ac8, parent=sha256:e585188120ef8e14abfd097ebceba61cecdf56a85296a67e632fe17f9eed41d1
Committed snapshot sha256:bf318baa6aa554c3aea31b9c91c986cf7b33be4afd5ac5562fc94e88fceb9ac8
```

The snapshotter will also print the manifests for the layers that it has pulled.
```bash
{
  "Layers": [
    "/var/lib/cc-snapshotter/layers/08249ce7456a1c0613eafe868aed936a284ed9f1d6144f7d2d08c514974a2af9.disk",
    "/var/lib/cc-snapshotter/layers/1cc9e0fe288a20fc9a4c0972353bc4323714b98cb280c7f30a88330fd2e0c1af.disk",
    "/var/lib/cc-snapshotter/layers/92fd29f93c5ed2985ef47d721abfd85917369726779e7fe91cd3e24d07ca1021.disk",
    "/var/lib/cc-snapshotter/layers/51d7aab829870a1ea24dfc3cce7bec89d35d9a43c225370e5401d662837b9c80.disk",
    "/var/lib/cc-snapshotter/layers/e585188120ef8e14abfd097ebceba61cecdf56a85296a67e632fe17f9eed41d1.disk",
    "/var/lib/cc-snapshotter/layers/bf318baa6aa554c3aea31b9c91c986cf7b33be4afd5ac5562fc94e88fceb9ac8.disk"
  ],
  "RootHashes": [
    "0e492a710fe207f41d20d2cfc5e8e57910804f7ede62100d4a4258ba5c0d965a",
    "87ca69e9dc6d9d0231cee0635e5c8ee7f7b27a62a94c9cf2b88107339c367cb6",
    "d0ff5be4e7be82c7f98163c8878f85a0a79afc4c96b178d8ffacde054fc6b824",
    "92f320c3349865aee94cd3b5ef128ac89ec29557f84a46ef14e71cf491e66e54",
    "c69ecd150cf6a4ac1b3a7354d3a53b0312475f8d0ed9edf1f5ddb940b7925543",
    "1ceb7479eb354a8b9c76eaf3235847e30434774b0d3c637651b00c6d07796e39"
  ],
  "DiffIDs": [
    "sha256:08249ce7456a1c0613eafe868aed936a284ed9f1d6144f7d2d08c514974a2af9",
    "sha256:5659b3a1146e8bdda814e4ad825e107088057e8578c83b758ad6aab93700d067",
    "sha256:cf3ae502d7faa4e90c159cc42b63b46a6be04864fe9d04fb0939e2b0c8b1f7c7",
    "sha256:4ca33072d02630d1d55ada52c3bde95a1ffe02ae60da9ef147c836db444f7a0f",
    "sha256:58bcc523fc9281a3a7033280804e841d1fcec71cbd6359c643c7e06a90efb34c",
    "sha256:be56018ff4790f7f1d96f500e9757c27979c37e476e21a2932746b4654955806"
  ],
  "ChainIDs": [
    "sha256:08249ce7456a1c0613eafe868aed936a284ed9f1d6144f7d2d08c514974a2af9",
    "sha256:1cc9e0fe288a20fc9a4c0972353bc4323714b98cb280c7f30a88330fd2e0c1af",
    "sha256:92fd29f93c5ed2985ef47d721abfd85917369726779e7fe91cd3e24d07ca1021",
    "sha256:51d7aab829870a1ea24dfc3cce7bec89d35d9a43c225370e5401d662837b9c80",
    "sha256:e585188120ef8e14abfd097ebceba61cecdf56a85296a67e632fe17f9eed41d1",
    "sha256:bf318baa6aa554c3aea31b9c91c986cf7b33be4afd5ac5562fc94e88fceb9ac8"
  ],
  "RWLayer": ""
}
```

Run a container using the image pulled by the snapshotter, use the ctr-remote command and specify both the snapshotter as well as the runtime.
```bash
$  ./bin/ctr-remote run --snapshotter cc-snapshotter --runtime io.containerd.kata.v2 --rm -t docker.io/library/redis:latest test bash
root@ummu:/data#
```
