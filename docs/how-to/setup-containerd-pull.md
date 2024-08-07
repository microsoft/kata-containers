# Manual Steps for Setting Up Containerd and Docker for Genpolicy Tool

This guide provides instructions for manually setting up your system to use the genpolicy tool with containerd and Docker. This setup is needed for managed identity-based authentication to private registries using an identity token.

These are the steps performed by the script `src/tools/genpolicy/setup_containerd_docker.sh`

## Prerequisites

- Ensure you have `sudo` access on the system.
- Determine the package manager used by your system (`apt-get` or `tdnf`).

## Steps

### 1. Install Containerd

#### Using `apt-get` (for Debian/Ubuntu-based systems)

```bash
sudo apt-get update
sudo apt-get install -y containerd
```

#### Using `tdnf` (for Photon OS-based systems)
```bash
sudo tdnf makecache
sudo tdnf install -y containerd
```

### 2. Modify Containerd Configuration
Open the containerd configuration file `/etc/containerd/config.toml`. Ensure the cri plugin is not disabled. Locate the line that looks like this (if present):

```toml
disabled_plugins = ["cri"]
```

Modify it to:

```toml
disabled_plugins = [] # leave other plugins if present
```
Such that `cri` is not disabled. Save and close the file.

### 3. Restart Containerd
```bash
sudo systemctl restart containerd
```

If containerd is not running, start it:

```bash
sudo systemctl start containerd
```
### 4. Verify Containerd Status
```bash
sudo systemctl status containerd --no-pager
```

### 5. Find Containerd Socket File Location
Locate the containerd socket file by inspecting the configuration file:

```bash
SOCKET_FILE_LOCATION=$(awk '/\[grpc\]/ {found=1} found && /address *= */ {print $3; exit}' /etc/containerd/config.toml | tr -d '"')
```

The socket file is usually `/run/containerd/containerd.sock` or `/var/run/containerd/containerd.sock`

### 6. Fix Containerd Socket File Permissions

This step is necessary so genpolicy tool can run without `sudo`

```bash
sudo chmod a+rw "$SOCKET_FILE_LOCATION"
```

### 7. Install Docker and jq
Using apt-get (for Debian/Ubuntu-based systems)

```bash
sudo apt-get install -y docker.io jq
```

Using tdnf (for Photon OS-based systems)
```bash
sudo tdnf install -y docker jq
```

### 8. Adapt Docker Configuration

Remove `credstore` key and value from `~/.docker/config.json` if present.

### Conclusion
The setup is now complete. Please use the socket file location found in the configuration when running the genpolicy tool. For example:

```bash
genpolicy -d=$SOCKET_FILE_LOCATION -y foo.yaml
```