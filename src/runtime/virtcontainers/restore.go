// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist"
	persistapi "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist/api"
	pbTypes "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols"
)

// restore.go builds a real, kata-managed *Sandbox from a `kata-runtime snapshot` dir. it
// boots via NewVMFromSnapshot and skips container creation (the containers are already live
// in the snapshotted guest RAM).

// RestoreOpts parameterizes a restore.
type RestoreOpts struct {
	// id for the restored sandbox; empty -> generated. ALWAYS distinct from the source's
	// id -- the original sandbox may still be running.
	SandboxID string

	// node-authoritative hypervisor binary paths; when set they override the snapshot's
	// persisted paths (which may belong to the source node). the shim passes bare paths,
	// not its RuntimeConfig, because virtcontainers cannot import pkg/oci (import cycle).
	// empty keeps whatever the persisted config carried.
	HypervisorPath string
	KernelPath     string
	ImagePath      string

	// optional CIDR (e.g. "192.168.240.1/24"); when set, best-effort host tap + agent
	// re-IP so the guest gets a fresh non-colliding address. empty skips networking (the
	// sandbox is still real + managed, just not reachable on a new IP).
	GuestIP string
}

// RestoreSandbox restores a snapshot directory as a fully-wired, running *Sandbox.
func RestoreSandbox(ctx context.Context, snapshotDir string, opts RestoreOpts) (_ *Sandbox, err error) {
	if _, statErr := os.Stat(filepath.Join(snapshotDir, "config.json")); statErr != nil {
		return nil, fmt.Errorf("not a snapshot dir (no config.json): %s", snapshotDir)
	}

	// new id, always: the source sandbox may be live, so we never reuse its id.
	newID := opts.SandboxID
	if newID == "" {
		newID = genCloneID("")
	}
	if err := validateSandboxID(newID); err != nil {
		return nil, err
	}

	// seed the persist store for newID so createSandbox -> s.Restore() rehydrates
	// endpoints/devices/containers and the "state != empty" early-return fires (skipping
	// fresh-boot agent work).
	if err := seedPersist(snapshotDir, newID); err != nil {
		return nil, fmt.Errorf("seed persist for restore: %w", err)
	}

	// reuse the existing persist->live converter to rebuild the SandboxConfig under newID.
	sandboxConfig, err := loadSandboxConfig(newID)
	if err != nil {
		return nil, fmt.Errorf("load restored sandbox config: %w", err)
	}
	sandboxConfig.ID = newID

	// the snapshot's persisted config carries the right hypervisor TYPE + tuning, but its
	// on-disk binary paths may belong to the source node; prefer the live node's.
	if opts.HypervisorPath != "" {
		sandboxConfig.HypervisorConfig.HypervisorPath = opts.HypervisorPath
	}
	if opts.KernelPath != "" {
		sandboxConfig.HypervisorConfig.KernelPath = opts.KernelPath
	}
	if opts.ImagePath != "" {
		sandboxConfig.HypervisorConfig.ImagePath = opts.ImagePath
	}

	// map the rebuilt config's guest memory MAP_PRIVATE. belt-and-suspenders: RestoreVM
	// actually hands CLH the snapshot's own config.json, so the patch below is the real COW
	// guarantee, not this field.
	sandboxConfig.HypervisorConfig.FileBackedMemory = &FileBackedMemoryConfig{
		Path:   filepath.Join(snapshotDir, "memory-ranges"),
		Shared: false,
	}
	// mark the snapshot's in-dir config.json memory private (the file CLH actually opens);
	// without it the clone could write the source's RAM.
	if err := PatchCLHSnapshotMemoryPrivate(snapshotDir); err != nil {
		return nil, fmt.Errorf("patch snapshot memory private: %w", err)
	}

	// build the Sandbox shell. with persist seeded, createSandbox early-returns a
	// rehydrated struct without doing fresh-boot agent work.
	s, err := createSandbox(ctx, *sandboxConfig, nil)
	if err != nil {
		return nil, fmt.Errorf("create restored sandbox: %w", err)
	}
	defer func() {
		if err != nil {
			s.Delete(ctx)
		}
	}()

	// host cgroups for the sandbox (incl. the hypervisor process).
	if err = s.setupResourceController(); err != nil {
		return nil, err
	}

	// createSandbox early-returns on the rehydrated restore path and skips fsShare.Prepare,
	// so the sandbox dir assignSandbox symlinks into is never made. create just that parent
	// dir -- not full Prepare, whose slave bind-mount assignSandbox never uses and which would
	// leak on a failed restore (s.Delete early-returns on state="running" before Cleanup).
	if err = os.MkdirAll(getSandboxPath(s.id), DirMode); err != nil {
		return nil, fmt.Errorf("create restored sandbox dir: %w", err)
	}

	// boot the VM from the snapshot: CreateVM -> launchAndInit (virtiofsd + CLH) ->
	// RestoreVM. returns PAUSED.
	vmConfig := VMConfig{
		HypervisorType:   sandboxConfig.HypervisorType,
		HypervisorConfig: sandboxConfig.HypervisorConfig,
		AgentConfig:      sandboxConfig.AgentConfig,
	}
	vm, err := NewVMFromSnapshot(ctx, vmConfig, snapshotDir)
	if err != nil {
		return nil, fmt.Errorf("restore vm from snapshot: %w", err)
	}
	defer func() {
		if err != nil {
			s.stopVM(ctx)
		}
	}()

	// attach the restored VM to the sandbox (reuses the VM's live agent + hypervisor).
	if err = vm.assignSandbox(s); err != nil {
		return nil, fmt.Errorf("assign restored vm to sandbox: %w", err)
	}

	// best-effort networking, only when a guest IP was requested; never fatal.
	if opts.GuestIP != "" {
		if nerr := setupRestoreNetwork(ctx, s, snapshotDir, opts.GuestIP); nerr != nil {
			s.Logger().WithError(nerr).Warn("restore: best-effort networking failed; sandbox is up but may not be reachable on the new IP")
		}
	}

	// un-pause the guest.
	if err = vm.Resume(ctx); err != nil {
		return nil, fmt.Errorf("resume restored vm: %w", err)
	}

	if err = s.Save(); err != nil {
		return nil, fmt.Errorf("save restored sandbox state: %w", err)
	}

	s.Logger().WithField("restored-sandbox", newID).Info("restore: managed sandbox up")
	return s, nil
}

// seedPersist loads the snapshot's persist.json, rewrites the sandbox identity to newID,
// and writes it into the persist store under newID. per-application container ids are
// LEFT ALONE: the in-guest agent knows them by their original id, so rewriting would
// desync host<->guest.
func seedPersist(snapshotDir, newID string) error {
	raw, err := os.ReadFile(filepath.Join(snapshotDir, "persist.json"))
	if err != nil {
		return fmt.Errorf("read snapshot persist.json: %w", err)
	}
	var ss persistapi.SandboxState
	if err := json.Unmarshal(raw, &ss); err != nil {
		return fmt.Errorf("decode snapshot persist.json: %w", err)
	}

	// the reused kata-agent dials AgentState.URL (loaded by s.Restore() -> loadState). the
	// snapshot carries the original id; assignSandbox symlinks /run/vc/vm/<newID> to the
	// restored VM dir, so rebuild the url from newID (a substring replace would over-match a
	// short --name like "vm" or "1024" and corrupt the path/port). without this the agent
	// talks to the source sandbox and the restore is immediately torn down.
	if ss.AgentState.URL != "" {
		ss.AgentState.URL = fmt.Sprintf("hvsock:///run/vc/vm/%s/clh.sock:1024", newID)
	}
	// the on-disk sandbox dir is keyed by ss.SandboxContainer (persist/fs.ToDisk), and
	// SandboxConfig has no ID field, so this is the only identity rewrite needed.
	ss.SandboxContainer = newID
	// cgroup paths embed the old id; clear them so setupResourceController re-derives
	// fresh ones rather than colliding with the source sandbox's cgroups.
	ss.SandboxCgroupPath = ""
	ss.OverheadCgroupPath = ""
	ss.CgroupPaths = nil
	// the old clh pid + sockets are dead in the restoring process; assignSandbox swaps in the
	// freshly-launched hypervisor, but zero them so a failure BEFORE that can not signal a
	// stale/recycled pid or deref a nil client during deferred cleanup.
	ss.HypervisorState.Pid = 0
	ss.HypervisorState.VirtiofsDaemonPid = 0
	ss.HypervisorState.APISocket = ""

	store, err := persist.GetDriver()
	if err != nil {
		return err
	}
	// empty container map: app-container state lives per-container on disk and is restored
	// from guest RAM, not from host persist.
	return store.ToDisk(ss, map[string]persistapi.ContainerState{})
}

// setupRestoreNetwork is the best-effort host-tap + agent re-IP for a restored clone.
func setupRestoreNetwork(ctx context.Context, s *Sandbox, snapshotDir, guestIPCIDR string) error {
	net, err := allocateCloneNet()
	if err != nil {
		return err
	}
	if guestIPCIDR != "" {
		net.guestIP = guestIPCIDR
	}
	if err := setupTap(net); err != nil {
		return err
	}

	mac, err := readSnapshotMAC(snapshotDir)
	if err != nil {
		return err
	}
	addr, mask := splitCIDR(net.guestIP)
	ifc := &pbTypes.Interface{
		Device: "eth0",
		Name:   "eth0",
		Mtu:    1500,
		HwAddr: mac,
		IPAddresses: []*pbTypes.IPAddress{{
			Family:  pbTypes.IPFamily_v4,
			Address: addr,
			Mask:    mask,
		}},
	}
	if _, err := s.agent.updateInterface(ctx, ifc); err != nil {
		return fmt.Errorf("agent updateInterface: %w", err)
	}
	return nil
}

// readSnapshotMAC pulls .net[0].mac out of the snapshot's config.json. the clone reuses
// the original MAC; a fresh MAC is deferred until dup-MAC actually bites.
func readSnapshotMAC(snapshotDir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(snapshotDir, "config.json"))
	if err != nil {
		return "", err
	}
	var cfg struct {
		Net []struct {
			Mac string `json:"mac"`
		} `json:"net"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", err
	}
	if len(cfg.Net) == 0 || cfg.Net[0].Mac == "" {
		return "", fmt.Errorf("snapshot config.json: .net[0].mac missing")
	}
	return cfg.Net[0].Mac, nil
}

// ---- networking helpers (best-effort, copied from cmd/kata-runtime/restore.go --
// different package, so not importable). ----

const (
	tapPrefix     = "kat"
	tapSubnetBase = 240 // 192.168.240.x for clone 0, .241 for clone 1, ...
	maxClones     = 15
)

type cloneNet struct {
	tap     string
	hostIP  string // CIDR
	guestIP string // CIDR
}

// genCloneID returns name if given, else a random clone-<hex> id.
func genCloneID(name string) string {
	if name != "" {
		return name
	}
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "clone-fallback"
	}
	return "clone-" + hex.EncodeToString(b)
}

// validateSandboxID rejects ids that would let on-disk state dirs escape their base
// (no path separators or ".."). duplicated here because virtcontainers cannot import
// katautils (import cycle).
func validateSandboxID(id string) error {
	if id == "" {
		return fmt.Errorf("sandbox id is required")
	}
	if id == "." || id == ".." || strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return fmt.Errorf("invalid sandbox id %q: must not contain path separators or ..", id)
	}
	return nil
}

// allocateCloneNet atomically claims a free tap slot (ip tuntap add fails if the device
// exists) and derives its point-to-point subnet.
func allocateCloneNet() (cloneNet, error) {
	for n := 0; n < maxClones; n++ {
		tap := fmt.Sprintf("%s%d", tapPrefix, n)
		if err := runIP("tuntap", "add", "mode", "tap", tap); err != nil {
			continue
		}
		octet := tapSubnetBase + n
		return cloneNet{
			tap:     tap,
			hostIP:  fmt.Sprintf("192.168.%d.2/24", octet),
			guestIP: fmt.Sprintf("192.168.%d.1/24", octet),
		}, nil
	}
	return cloneNet{}, fmt.Errorf("no free clone tap slot (all %d in use)", maxClones)
}

// setupTap brings an allocated tap up and assigns the host IP + a /32 route to the guest.
func setupTap(net cloneNet) error {
	guestAddr, _ := splitCIDR(net.guestIP)
	for _, args := range [][]string{
		{"link", "set", "dev", net.tap, "up"},
		{"a", "add", net.hostIP, "dev", net.tap},
		{"route", "add", guestAddr + "/32", "dev", net.tap},
	} {
		if err := runIP(args...); err != nil {
			return err
		}
	}
	return nil
}

// splitCIDR splits "192.168.240.1/24" into ("192.168.240.1", "24").
func splitCIDR(cidr string) (addr, mask string) {
	if i := strings.IndexByte(cidr, '/'); i >= 0 {
		return cidr[:i], cidr[i+1:]
	}
	return cidr, ""
}

// runIP shells out to `ip` (matches the exec.Command("ip",...) precedent in
// network_linux.go).
func runIP(args ...string) error {
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("ip %s: %s (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
