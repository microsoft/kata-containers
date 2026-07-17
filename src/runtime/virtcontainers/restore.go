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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist"
	persistapi "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist/api"
	pbTypes "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/compatoci"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
)

// restore.go builds a real, kata-managed *Sandbox from a `kata-runtime snapshot` dir. it
// boots via NewVMFromSnapshot and skips container creation (the containers are already live
// in the snapshotted guest RAM).

// kataIfaceNeutralize is a raw_flags sentinel (a high bit that is NOT a valid IFF_* flag) the
// restore path sets on the frozen source NIC of a cloned VM. the guest kata-agent's
// update_interface handles it by DOWNING the link + DELETING all its addresses, so the clone
// shares no network identity with its source. MUST match KATA_IFACE_NEUTRALIZE in the rust
// agent (src/agent/src/netlink.rs).
const kataIfaceNeutralize uint32 = 0x8000_0000

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

	// path to the pod's CNI network namespace (e.g. /var/run/netns/cni-<id>), read by the
	// shim from the LIVE OCI spec (containerd ran CNI ADD during RunPodSandbox). when set, the
	// restore boots the VM INSIDE this netns and adopts its tap, so the restored guest lands on
	// the real pod IP instead of the frozen snapshot IP. empty -> legacy no-netns behavior.
	// NOT sourced from the persisted config -- that carries the SOURCE sandbox's netns.
	NetNSPath string
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
	// fresh-boot agent work). returns the ORIGINAL sandbox id (the guest still knows the pause
	// container by it) so adoptPauseContainer can set the pause's guestID for agent RPCs.
	origSandboxID, err := seedPersist(snapshotDir, newID)
	if err != nil {
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

	// map the rebuilt config's guest memory MAP_PRIVATE (COW). CLH-specific: the snapshot is a
	// CLH memory-ranges dump + config.json, so both the file-backed mapping and the in-dir
	// config.json private-patch only make sense for cloud-hypervisor. gate both so a non-CLH
	// restore does not mmap a foreign CLH RAM dump or mis-patch a foreign config.
	if sandboxConfig.HypervisorType == ClhHypervisor {
		sandboxConfig.HypervisorConfig.FileBackedMemory = &FileBackedMemoryConfig{
			Path:   filepath.Join(snapshotDir, "memory-ranges"),
			Shared: false,
		}
		if err := PatchCLHSnapshotMemoryPrivate(snapshotDir); err != nil {
			return nil, fmt.Errorf("patch snapshot memory private: %w", err)
		}
	}

	// set the VM/run store paths on the hypervisor config. newSandbox normally does this
	// (sandbox.go), but createSandbox's rehydrate early-return skips it -- and without
	// VMStorePath the CLH socket paths become relative (uuid/clh-api.sock) so CLH creates them
	// under cwd instead of /run/vc/vm/<uuid>/, leaving the agent's absolute vsock unreachable.
	// fatal on error (S2): a nil/failed driver silently reintroduces the relative-socket bug,
	// surfacing only as an opaque agent-dial timeout. sandbox.go treats the same call as fatal.
	drv, derr := persist.GetDriver()
	if derr != nil {
		return nil, fmt.Errorf("restore: get persist driver for store paths: %w", derr)
	}
	if drv == nil {
		return nil, fmt.Errorf("restore: nil persist driver for store paths")
	}
	sandboxConfig.HypervisorConfig.VMStorePath = drv.RunVMStoragePath()
	sandboxConfig.HypervisorConfig.RunStorePath = drv.RunStoragePath()

	// T4a: point the network config at the pod's CNI netns so the restored VM boots INSIDE it
	// and adopts the CNI tap (real pod IP), instead of the empty netns NewVMFromSnapshot builds.
	// NetworkID IS literally the netns path (oci/utils.go). the shim sourced this from the LIVE
	// OCI spec; the persisted config's NetworkID is the SOURCE sandbox's netns and must NOT be
	// used. NetworkCreated=false: we ADOPT the CNI-created netns, we do not create/own it.
	if opts.NetNSPath != "" {
		sandboxConfig.NetworkConfig.NetworkID = opts.NetNSPath
		sandboxConfig.NetworkConfig.NetworkCreated = false
	}

	// build the Sandbox shell. with persist seeded, createSandbox early-returns a
	// rehydrated struct without doing fresh-boot agent work.
	s, err := createSandbox(ctx, *sandboxConfig, nil)
	if err != nil {
		return nil, fmt.Errorf("create restored sandbox: %w", err)
	}
	defer func() {
		if err != nil {
			// M2: a restored sandbox rehydrates state="running", but Sandbox.Delete
			// hard-returns for anything not Ready/Paused/Stopped -- so a plain
			// s.Delete(ctx) here is a NO-OP and leaks the cgroup slice, seeded persist
			// store, sandbox dir, and assignSandbox symlinks on any late error. force
			// state->Stopped first so resourceControllerDelete + store.Destroy actually
			// run. the stopVM defer below reaps the CLH VM; this reaps host artifacts.
			s.state.State = types.StateStopped
			s.Delete(ctx)
		}
	}()

	// S3: the restore path depends on createSandbox's rehydrate early-return firing, which
	// requires the seeded persist to carry state="running" (the snapshot was taken of a
	// running sandbox). if it does not, createSandbox fell through to fresh-boot work OR the
	// seed was malformed -- either way the shim (T2.1) will unconditionally skip Start and we
	// would report a Running sandbox with no resumed VM. fail loudly instead.
	if s.state.State != types.StateRunning {
		err = fmt.Errorf("restored sandbox in unexpected state %q (want running); snapshot persist may be malformed", s.state.State)
		return nil, err
	}

	// T4a Step 3: reset s.network to the CLONE's CNI netns. newSandbox built s.network from the
	// config, but createSandbox -> s.Restore() -> loadNetwork OVERWROTE it with the SOURCE
	// sandbox's persisted netns + stale endpoints. rebuild it from the clone NetworkConfig
	// (NetworkID = the CNI netns path set above) so AddEndpoints/Run below operate on the RIGHT
	// namespace. only when we actually have a CNI netns to adopt.
	if opts.NetNSPath != "" {
		net, nerr := NewNetwork(&sandboxConfig.NetworkConfig)
		if nerr != nil {
			err = fmt.Errorf("restore: build clone network for netns %q: %w", opts.NetNSPath, nerr)
			return nil, err
		}
		s.network = net
	}

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

	// T4a Step 4: coldplug the CNI netns endpoints BEFORE launching the VM (mirrors startVM's
	// createNetwork -> AddEndpoints(...,false) at sandbox.go:1027). this scans the clone netns,
	// builds the veth/tap endpoint, populates TapInterface.VMFds, and clh.addNet stashes the tap
	// fds keyed by MAC -- so the VM launch below can bind the guest NIC to the real CNI tap.
	if opts.NetNSPath != "" {
		if _, nerr := s.network.AddEndpoints(ctx, s, nil, false); nerr != nil {
			err = fmt.Errorf("restore: adopt CNI netns endpoints: %w", nerr)
			return nil, err
		}
	}

	// boot the VM from the snapshot: CreateVM -> launchAndInit (virtiofsd + CLH) ->
	// RestoreVM. returns PAUSED. T4a Step 5: run it INSIDE the CNI netns via network.Run ->
	// doNetNS (LockOSThread + setns), so CLH's exec.Command fork inherits the pod netns and its
	// tap lives in the right namespace. with no netns (opts.NetNSPath==""), Run's doNetNS is a
	// no-op in the current namespace -- identical to the pre-T4a behavior.
	vmConfig := VMConfig{
		HypervisorType:   sandboxConfig.HypervisorType,
		HypervisorConfig: sandboxConfig.HypervisorConfig,
		AgentConfig:      sandboxConfig.AgentConfig,
	}
	var vm *VM
	err = s.network.Run(ctx, func() error {
		var e error
		vm, e = NewVMFromSnapshot(ctx, vmConfig, snapshotDir)
		return e
	})
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

	// Q2 RehydratePodIdentity: build the host-side PAUSE/sandbox Container object keyed to
	// newID and register it in s.containers, so the shim's Start -> IOStream(newID,newID) ->
	// findContainer(newID) succeeds. Without it Start fails "Could not find the container from
	// the sandbox containers list" and containerd tears the sandbox down. Pause-container only:
	// it has no rootfs/block devices (createDevices/createMounts are no-ops), and adopting the
	// APP container here would rebuild it from the SOURCE pod's bundle + hot-plug its devices
	// into the clone -- unsafe. The app container's host-side struct is adopted later, when
	// kubelet calls CreateContainer/StartContainer per-container against the clone (a separate
	// name-keyed no-op adopt step). seedPersist already re-keyed the pause ContainerConfig's
	// ID + bundle_path to newID, so loadSandboxConfig put it in s.config.Containers.
	if err = adoptPauseContainer(ctx, s, newID, origSandboxID); err != nil {
		return nil, fmt.Errorf("adopt restored pause container: %w", err)
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

	// T4a Step 6 (sub-plan 2, restore-then-hotplug): bind the CNI tap to the now-running
	// restored VM. Step 4 coldplugged the endpoint (host tap + fds in the CNI netns) but the
	// restore path never sends net devices to CLH (bootVM's vmAddNetPut is skipped on restore).
	// so hotplug-add each adopted endpoint to the live VM via SCM_RIGHTS (hotplugAddNetDevice ->
	// addNet + vmAddNetPut). the guest sees the CNI tap as a NEW nic (the snapshot's frozen nic
	// stays); T4b re-IPs whichever iface carries the CNI tap. never fatal here -- a networking
	// failure must not tear down an otherwise-good restore (the sandbox is still managed).
	if opts.NetNSPath != "" {
		for _, ep := range s.network.Endpoints() {
			if _, herr := s.hypervisor.HotplugAddDevice(ctx, ep, NetDev); herr != nil {
				s.Logger().WithError(herr).Warn("restore: hotplug CNI net device failed; pod may not be reachable on its CNI IP")
			}
		}

		// T4b (Design B): configure the freshly-hotplugged CNI NIC in the guest -- give it the
		// pod's real CNI IP + install the default route -- and neutralize the FROZEN snapshot NIC
		// so the clone carries ONLY its own network identity (complete isolation: the two clones
		// never knew each other). never fatal: a networking failure must leave a managed sandbox
		// up (retryable), not tear it down.
		if nerr := applyRestoreNetwork(ctx, s); nerr != nil {
			s.Logger().WithError(nerr).Warn("restore: applying CNI network to guest failed; pod may lack reachability/egress")
		}
	}

	if err = s.Save(); err != nil {
		return nil, fmt.Errorf("save restored sandbox state: %w", err)
	}

	s.Logger().WithField("restored-sandbox", newID).Info("restore: managed sandbox up")
	return s, nil
}

// adoptPauseContainer builds the host-side *Container for the restored sandbox's pause
// container (id == sandbox id == newID after seedPersist re-keyed it) and registers it in
// s.containers, WITHOUT creating it in the guest (it is already live from the snapshot).
// mirrors fetchContainers, but for the single pause entry only. this is the Q2
// RehydratePodIdentity adopt the shim's Start/IOStream path depends on.
func adoptPauseContainer(ctx context.Context, s *Sandbox, newID, origSandboxID string) error {
	for i := range s.config.Containers {
		cc := &s.config.Containers[i]
		if cc.ID != newID {
			continue
		}
		// pull the OCI spec from the clone's containerd bundle (bundle_path annotation was
		// re-pointed to /run/containerd/.../<newID> by seedPersist).
		spec, err := compatoci.GetContainerSpec(cc.Annotations)
		if err != nil {
			return fmt.Errorf("get pause container spec: %w", err)
		}
		cc.CustomSpec = &spec
		c, err := newContainer(ctx, s, cc)
		if err != nil {
			return fmt.Errorf("new pause container: %w", err)
		}
		// c.id == newID for host-side lookups; the GUEST still knows the pause container by the
		// ORIGINAL sandbox id, so agent RPCs (signal/stop/wait on teardown) must use guestID.
		// the pause init exec-id == guest container id, so the process token is origSandboxID.
		if origSandboxID != "" {
			c.guestID = origSandboxID
			c.process = Process{Token: origSandboxID, Pid: -1}
		}
		if err := s.addContainer(c); err != nil {
			return fmt.Errorf("add pause container: %w", err)
		}
		// the pause container is already live in the restored guest, but newContainer built it
		// with empty state (no per-container persist for newID). mark it Running so the shim's
		// IOStream/signal path (which gates on Ready|Running) accepts it.
		if err := c.setContainerState(types.StateRunning); err != nil {
			return fmt.Errorf("set pause container running: %w", err)
		}
		return nil
	}
	return fmt.Errorf("pause container config (id=%s) not found in restored sandbox config", newID)
}

// RestoreContainer adopts an APP container that is ALREADY LIVE in the restored guest into the
// host-side sandbox, WITHOUT creating it in the guest. It is the restore-path counterpart of
// Sandbox.CreateContainer: same config-append + newContainer + addContainer bookkeeping, but it
// SKIPS c.create() (the guest agent CreateContainer RPC) -- the container's processes are
// already running from the snapshot, and re-creating would collide with them and trip guest
// gates (e.g. the Guest-SELinux host/guest mismatch). The container is marked Running so the
// shim's Start/IOStream path accepts it. This is the T5 per-container "name-keyed adopt/no-op"
// the CRI two-phase (CreateContainer/StartContainer) lands on for a restored pod.
func (s *Sandbox) RestoreContainer(ctx context.Context, contConfig ContainerConfig) (VCContainer, error) {
	// the guest knows this container by its ORIGINAL snapshot id, not the fresh containerd id
	// in contConfig.ID. the original app-container id is the one non-sandbox, non-pause entry the
	// snapshot's persisted config carried (seedPersist re-keyed ONLY the pause entry to newID, so
	// the app entry still holds its original id). find it so agent-facing ops (waitProcess, ...)
	// target the live guest container instead of missing on the clone id.
	guestID := restoreGuestContainerID(s, contConfig.ID)

	s.config.Containers = append(s.config.Containers, contConfig)
	var err error
	defer func() {
		if err != nil && len(s.config.Containers) > 0 {
			s.config.Containers = s.config.Containers[:len(s.config.Containers)-1]
		}
	}()

	c, err := newContainer(ctx, s, &s.config.Containers[len(s.config.Containers)-1])
	if err != nil {
		return nil, err
	}
	// c.id == contConfig.ID (the containerd/clone id) for host-side lookups (findContainer,
	// IOStream). c.guestID == the original id for agent RPCs. the guest keys the init process by
	// exec-id == guest container id (kata_agent createContainer), so the process token is guestID.
	c.guestID = guestID
	c.process = Process{Token: guestID, Pid: -1}
	// NO c.create(ctx): the container is already live in the restored guest.
	if err = s.addContainer(c); err != nil {
		return nil, err
	}
	if err = c.setContainerState(types.StateRunning); err != nil {
		return nil, err
	}
	return c, nil
}

// restoreGuestContainerID returns the original (guest-known) container id for the app container
// being adopted. The snapshot's persisted config (now in s.config.Containers, minus the pause
// entry which seedPersist re-keyed) carries the original app-container id; there is exactly one
// non-pause app container in the demo pods. If none is found (unexpected), fall back to the
// clone id -- the adopt still registers host-side, only guest waitProcess would miss.
func restoreGuestContainerID(s *Sandbox, cloneID string) string {
	for i := range s.config.Containers {
		cc := &s.config.Containers[i]
		// skip the pause/sandbox container (already re-keyed to the sandbox id == s.id)
		if cc.ID == s.id {
			continue
		}
		if cc.Annotations[criContainerTypeAnnotation] == criSandboxType {
			continue
		}
		return cc.ID
	}
	return cloneID
}

// seedPersist loads the snapshot's persist.json, rewrites the sandbox identity to newID,
// and writes it into the persist store under newID. per-application container ids are
// LEFT ALONE: the in-guest agent knows them by their original id, so rewriting would
// desync host<->guest.
func seedPersist(snapshotDir, newID string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(snapshotDir, "persist.json"))
	if err != nil {
		return "", fmt.Errorf("read snapshot persist.json: %w", err)
	}
	var ss persistapi.SandboxState
	if err := json.Unmarshal(raw, &ss); err != nil {
		return "", fmt.Errorf("decode snapshot persist.json: %w", err)
	}

	// the guest kata-agent still knows the pause container by the ORIGINAL sandbox id (== the
	// original SandboxContainer); capture it before we overwrite, so the caller can set the
	// pause container's guestID for agent RPCs.
	origSandboxID := ss.SandboxContainer

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

	// rehydrate identity of the PAUSE/sandbox container so the restored Sandbox gets a
	// host-side Container object keyed to newID (Q2 RehydratePodIdentity). the shim's Start ->
	// IOStream(newID, newID) -> Sandbox.findContainer(newID) needs it; without it Start fails
	// "Could not find the container from the sandbox containers list" and containerd tears the
	// sandbox down. the sandbox/pause container's id == the sandbox id, so it must move to
	// newID (like ss.SandboxContainer). its bundle_path + sandbox-id annotations must point at
	// the CLONE's containerd bundle (containerd created /run/containerd/.../<newID>/ for us).
	// APP containers are LEFT ALONE: the in-guest agent knows them by their original id, and
	// their bundles belong to the source pod -- rewriting would desync host<->guest.
	for i := range ss.Config.ContainerConfigs {
		cc := &ss.Config.ContainerConfigs[i]
		if cc.Annotations[criContainerTypeAnnotation] == criSandboxType {
			cc.ID = newID
			if cc.Annotations == nil {
				cc.Annotations = map[string]string{}
			}
			cc.Annotations[ociBundlePathAnnotation] = filepath.Join(containerdBundleBase, newID)
			cc.Annotations[criSandboxIDAnnotation] = newID
		}
	}

	store, err := persist.GetDriver()
	if err != nil {
		return "", err
	}
	// container map stays empty on disk: per-container STATE is restored from guest RAM, not
	// host persist. the host-side Container STRUCTS are rebuilt post-createSandbox via
	// s.fetchContainers (which tolerates missing per-container persist).
	if err := store.ToDisk(ss, map[string]persistapi.ContainerState{}); err != nil {
		return "", err
	}
	return origSandboxID, nil
}

// CRI + OCI annotation keys used to identify + re-key the pause container on restore.
const (
	criContainerTypeAnnotation = "io.kubernetes.cri.container-type"
	criSandboxIDAnnotation     = "io.kubernetes.cri.sandbox-id"
	criSandboxType             = "sandbox"
	ociBundlePathAnnotation    = "io.katacontainers.pkg.oci.bundle_path"
	containerdBundleBase       = "/run/containerd/io.containerd.runtime.v2.task/k8s.io"
)

// applyRestoreNetwork configures the restored guest's CNI networking (Design B). It reuses the
// SAME structures the fresh-boot path builds (generateVCNetworkStructures over the adopted CNI
// endpoints, which carry the real pod IP/routes captured by AddEndpoints), but AVOIDS renaming
// guest interfaces: it matches each generated interface to the guest's CURRENT interface name by
// MAC and uses that name, so the agent's update_interface only ADDS the pod IP (no rename dance,
// which collides with the frozen snapshot NIC that also holds "eth0"). The guest keeps its own
// device names (e.g. the CNI NIC stays eth1); functionally correct, and collision-free.
func applyRestoreNetwork(ctx context.Context, s *Sandbox) error {
	eps := s.network.Endpoints()
	if len(eps) == 0 {
		return fmt.Errorf("no CNI endpoints adopted; nothing to configure")
	}

	// what does the guest currently look like? map MAC -> current guest iface name, so we can
	// re-IP in place WITHOUT triggering a rename (rename collides with the frozen snapshot NIC).
	before, lerr := s.agent.listInterfaces(ctx)
	if lerr != nil {
		return fmt.Errorf("list guest interfaces: %w", lerr)
	}
	macToGuestName := map[string]string{}
	for _, gi := range before {
		if gi != nil && gi.HwAddr != "" {
			macToGuestName[strings.ToUpper(gi.HwAddr)] = gi.Name
		}
	}

	ifaces, routes, _, gerr := generateVCNetworkStructures(ctx, eps)
	if gerr != nil {
		return fmt.Errorf("generate guest network structures: %w", gerr)
	}

	// re-IP each CNI NIC in place. rewrite Name/Device to the guest's CURRENT name for that MAC
	// so update_interface (which matches by HwAddr) adds the address without renaming.
	epNames := map[string]string{} // endpoint-name -> guest-name, for route device remap below
	for _, ifc := range ifaces {
		guestName, ok := macToGuestName[strings.ToUpper(ifc.HwAddr)]
		if !ok {
			s.Logger().WithField("mac", ifc.HwAddr).Warn("restore: CNI NIC mac not present in guest; skipping re-IP")
			continue
		}
		epNames[ifc.Name] = guestName
		ifc.Name = guestName
		ifc.Device = guestName
		if _, uerr := s.agent.updateInterface(ctx, ifc); uerr != nil {
			return fmt.Errorf("updateInterface %s (mac %s): %w", guestName, ifc.HwAddr, uerr)
		}
	}
	s.Logger().WithField("restore-net", "interfaces-applied").WithField("count", len(ifaces)).Info("restore: CNI interfaces configured")

	// install routes. updateRoutes matches the link by DEVICE NAME, so remap each route's Device
	// from the endpoint name to the guest's actual iface name.
	for _, r := range routes {
		if gn, ok := epNames[r.Device]; ok {
			r.Device = gn
		}
	}
	if len(routes) > 0 {
		if _, rerr := s.agent.updateRoutes(ctx, routes); rerr != nil {
			return fmt.Errorf("updateRoutes: %w", rerr)
		}
		s.Logger().WithField("restore-net", "routes-applied").WithField("count", len(routes)).Info("restore: CNI routes installed")
	}

	// #2 isolation-via-routing: the FROZEN snapshot NIC still holds an on-link route for the
	// pod subnet (e.g. 10.244.0.0/16 dev eth0) baked into guest RAM -- it competes with the CNI
	// NIC's route and, because eth0's dead tap can't carry traffic, black-holes the clone. the
	// agent's update_routes uses NLM_F_REPLACE, so re-asserting the subnet + default routes
	// pinned to the CNI guest NIC (by device name) OVERRIDES the frozen ones onto the live NIC.
	// build override routes from each CNI interface's own address/subnet.
	var overrides []*pbTypes.Route
	for _, ifc := range ifaces {
		guestName, ok := macToGuestName[strings.ToUpper(ifc.HwAddr)]
		if !ok {
			continue
		}
		for _, a := range ifc.IPAddresses {
			if a == nil || a.Family != pbTypes.IPFamily_v4 || a.Address == "" || a.Mask == "" {
				continue
			}
			// on-link subnet route for this NIC's network, pinned to the live CNI NIC.
			if sub := subnetCIDR(a.Address, a.Mask); sub != "" {
				overrides = append(overrides, &pbTypes.Route{
					Dest:   sub,
					Device: guestName,
					Scope:  253, // RT_SCOPE_LINK
					Family: pbTypes.IPFamily_v4,
				})
			}
		}
	}
	if len(overrides) > 0 {
		if _, rerr := s.agent.updateRoutes(ctx, overrides); rerr != nil {
			s.Logger().WithError(rerr).Warn("restore: subnet-override routes failed (frozen NIC route may still shadow)")
		} else {
			s.Logger().WithField("restore-net", "override-routes").WithField("count", len(overrides)).Info("restore: pinned pod-subnet route to CNI NIC (frozen-NIC isolation)")
		}
	}

	// isolation: neutralize the frozen snapshot NIC (the source pod's identity baked into the
	// clone's RAM). any guest iface whose MAC is NOT owned by an adopted CNI endpoint is the
	// frozen one; the (rebuilt) agent downs it + flushes its addresses so the clone shares no
	// mac/ip/route with its source. this is what makes TCP + egress work (the frozen NIC's stale
	// /16 route otherwise black-holes) AND delivers complete isolation.
	neutralizeFrozenNIC(ctx, s, before, eps)

	return nil
}

// subnetCIDR returns the network CIDR for an ipv4 address + prefix-length string, e.g.
// ("10.244.0.204", "16") -> "10.244.0.0/16". empty on parse failure.
func subnetCIDR(addr, maskLen string) string {
	prefix, err := strconv.Atoi(maskLen)
	if err != nil || prefix < 0 || prefix > 32 {
		return ""
	}
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() == nil {
		return ""
	}
	mask := net.CIDRMask(prefix, 32)
	network := ip.Mask(mask)
	return fmt.Sprintf("%s/%d", network.String(), prefix)
}

// neutralizeFrozenNIC downs + flushes the FROZEN snapshot NIC so a restored clone shares NO
// network identity with its source (the original pod's MAC + stale pod IP + its /16 route must
// not survive in the clone, or they leak identity and can black-hole the clone's own subnet
// route). The frozen NIC is any guest interface (from the pre-reconfig `before` list) whose MAC
// is NOT owned by an adopted CNI endpoint and which is not loopback. Best-effort: never fatal.
func neutralizeFrozenNIC(ctx context.Context, s *Sandbox, before []*pbTypes.Interface, eps []Endpoint) {
	// set of CNI-owned MACs (upper-cased for comparison; agent reports MACs upper-case).
	cniMACs := map[string]struct{}{}
	for _, ep := range eps {
		cniMACs[strings.ToUpper(ep.HardwareAddr())] = struct{}{}
	}
	for _, ifc := range before {
		if ifc == nil || ifc.Name == "lo" || ifc.HwAddr == "" {
			continue
		}
		mac := strings.ToUpper(ifc.HwAddr)
		if _, isCNI := cniMACs[mac]; isCNI {
			continue // a CNI NIC -- keep it
		}
		// this is the frozen snapshot NIC. neutralize it: send updateInterface with the
		// KATA_IFACE_NEUTRALIZE sentinel in RawFlags, which the (rebuilt) guest agent handles by
		// DOWNING the link + DELETING all its addresses -- so its stale pod IP + on-link /16
		// route go away, leaving the clone with only its own CNI identity (complete isolation).
		// requires the guest to run the neutralize-capable agent (baked into fresh snapshots).
		down := &pbTypes.Interface{
			Device:      ifc.Name,
			Name:        ifc.Name,
			HwAddr:      ifc.HwAddr,
			Mtu:         ifc.Mtu,
			RawFlags:    kataIfaceNeutralize,
			IPAddresses: nil,
		}
		if _, err := s.agent.updateInterface(ctx, down); err != nil {
			s.Logger().WithError(err).WithField("frozen-nic", ifc.Name).WithField("mac", ifc.HwAddr).Warn("restore: could not neutralize frozen snapshot NIC (isolation best-effort)")
			continue
		}
		s.Logger().WithField("frozen-nic", ifc.Name).WithField("mac", ifc.HwAddr).Info("restore: neutralized frozen snapshot NIC for clone isolation")
	}
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
