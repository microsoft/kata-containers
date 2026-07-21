// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist"
	persistapi "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist/api"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/compatoci"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
)

// RestoreOpts configures an annotation-driven restore.
type RestoreOpts struct {
	// SandboxID is the caller-provided target sandbox ID.
	SandboxID string

	// Runtime paths override paths persisted by the source node.
	HypervisorPath string
	KernelPath     string
	ImagePath      string

	// NetNSPath identifies the target pod's CNI namespace.
	NetNSPath string
}

// RestoreSandbox restores a snapshot as a managed, paused sandbox.
func RestoreSandbox(ctx context.Context, snapshotDir string, opts RestoreOpts) (_ *Sandbox, err error) {
	if _, statErr := os.Stat(filepath.Join(snapshotDir, "config.json")); statErr != nil {
		return nil, fmt.Errorf("not a snapshot dir (no config.json): %s", snapshotDir)
	}

	newID := opts.SandboxID
	if err := validateSandboxID(newID); err != nil {
		return nil, err
	}
	if opts.NetNSPath == "" {
		return nil, fmt.Errorf("kata restore failed: target network namespace is required")
	}

	origSandboxID, err := seedPersist(snapshotDir, newID)
	if err != nil {
		return nil, fmt.Errorf("seed persist for restore: %w", err)
	}

	sandboxConfig, err := loadSandboxConfig(newID)
	if err != nil {
		return nil, fmt.Errorf("load restored sandbox config: %w", err)
	}
	sandboxConfig.ID = newID

	if opts.HypervisorPath != "" {
		sandboxConfig.HypervisorConfig.HypervisorPath = opts.HypervisorPath
	}
	if opts.KernelPath != "" {
		sandboxConfig.HypervisorConfig.KernelPath = opts.KernelPath
	}
	if opts.ImagePath != "" {
		sandboxConfig.HypervisorConfig.ImagePath = opts.ImagePath
	}

	// Keep source memory immutable through a private mapping.
	sandboxConfig.HypervisorConfig.FileBackedMemory = &FileBackedMemoryConfig{
		Path:   filepath.Join(snapshotDir, "memory-ranges"),
		Shared: false,
	}

	drv, derr := persist.GetDriver()
	if derr != nil {
		return nil, fmt.Errorf("restore: get persist driver for store paths: %w", derr)
	}
	if drv == nil {
		return nil, fmt.Errorf("restore: nil persist driver for store paths")
	}
	sandboxConfig.HypervisorConfig.VMStorePath = drv.RunVMStoragePath()
	sandboxConfig.HypervisorConfig.RunStorePath = drv.RunStoragePath()

	// Adopt the target CNI namespace without taking ownership of it.
	sandboxConfig.NetworkConfig.NetworkID = opts.NetNSPath
	sandboxConfig.NetworkConfig.NetworkCreated = false

	s, err := createSandbox(ctx, *sandboxConfig, nil)
	if err != nil {
		return nil, fmt.Errorf("create restored sandbox: %w", err)
	}
	defer func() {
		if err != nil {
			// Delete accepts only terminal or pre-running states.
			s.state.State = types.StateStopped
			s.Delete(ctx)
		}
	}()

	if s.state.State != types.StateRunning {
		err = fmt.Errorf("restored sandbox in unexpected state %q (want running); snapshot persist may be malformed", s.state.State)
		return nil, err
	}

	// Replace the restored source network with the target CNI namespace.
	net, nerr := NewNetwork(&sandboxConfig.NetworkConfig)
	if nerr != nil {
		err = fmt.Errorf("restore: build clone network for netns %q: %w", opts.NetNSPath, nerr)
		return nil, err
	}
	s.network = net

	if err = s.setupResourceController(); err != nil {
		return nil, err
	}

	if err = os.MkdirAll(getSandboxPath(s.id), DirMode); err != nil {
		return nil, fmt.Errorf("create restored sandbox dir: %w", err)
	}

	// Prepare target TAP FDs without installing TC redirects.
	s.restoreNetFence = true
	if _, nerr := s.network.AddEndpoints(ctx, s, nil, false); nerr != nil {
		err = fmt.Errorf("restore: adopt CNI netns endpoints: %w", nerr)
		return nil, err
	}

	// Restore the existing guest NIC with the target TAP FDs while inside its netns.
	vmConfig := VMConfig{
		HypervisorType:      sandboxConfig.HypervisorType,
		HypervisorConfig:    sandboxConfig.HypervisorConfig,
		AgentConfig:         sandboxConfig.AgentConfig,
		RestoreNetEndpoints: s.network.Endpoints(),
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
	// Transfer cleanup ownership after assignSandbox succeeds.
	vmAssigned := false
	defer func() {
		if err != nil {
			if vmAssigned {
				s.stopVM(ctx)
			} else {
				vm.Stop(ctx)
			}
		}
	}()

	if err = vm.assignSandbox(s); err != nil {
		return nil, fmt.Errorf("assign restored vm to sandbox: %w", err)
	}
	vmAssigned = true

	if err = adoptPauseContainer(s, origSandboxID); err != nil {
		return nil, fmt.Errorf("adopt restored pause container: %w", err)
	}

	s.Logger().WithField("restored-sandbox", newID).Info("restore: managed sandbox restored paused")
	return s, nil
}

// FinalizeRestoreNetwork replaces guest identity before enabling TC redirects.
func (s *Sandbox) FinalizeRestoreNetwork(ctx context.Context) (err error) {

	// Keep forwarding closed on failure.
	eps := s.network.Endpoints()
	if len(eps) != 1 {
		return fmt.Errorf("kata restore failed: expected exactly one adopted CNI endpoint, found %d", len(eps))
	}
	defer func() {
		if err != nil {
			_ = s.network.Run(ctx, func() error {
				cleanupRestoreTCFence(eps[0])
				return nil
			})
		}
	}()

	if err = s.hypervisor.ResumeVM(ctx); err != nil {
		return fmt.Errorf("kata restore failed: resume: %w", err)
	}

	// The restored NIC still has the source identity, so select it by name.
	before, lerr := s.agent.listInterfaces(ctx)
	if lerr != nil {
		return fmt.Errorf("kata restore failed: list guest interfaces: %w", lerr)
	}
	var guestNICName string
	guestNICCount := 0
	for _, gi := range before {
		if gi == nil || gi.Name == "" || gi.Name == "lo" {
			continue
		}
		guestNICCount++
		guestNICName = gi.Name
	}
	if guestNICCount != 1 {
		return fmt.Errorf("kata restore failed: expected exactly one non-loopback guest NIC, found %d", guestNICCount)
	}

	ifaces, routes, neighbors, gerr := generateVCNetworkStructures(ctx, eps)
	if gerr != nil {
		return fmt.Errorf("kata restore failed: generate guest network structures: %w", gerr)
	}
	if len(ifaces) != 1 {
		return fmt.Errorf("kata restore failed: expected exactly one target CNI interface, found %d", len(ifaces))
	}

	target := ifaces[0]
	targetName := target.Name // endpoint name, kept for route device remap
	target.Name = guestNICName
	target.Device = guestNICName
	// TC redirects do not translate MAC addresses.
	props := eps[0].Properties()
	if len(props.Iface.HardwareAddr) == 0 {
		return fmt.Errorf("kata restore failed: adopted endpoint has no scanned CNI veth MAC")
	}
	target.HwAddr = props.Iface.HardwareAddr.String()
	target.RawFlags |= kataIfaceRestoreReplace
	if _, uerr := s.agent.updateInterface(ctx, target); uerr != nil {
		return fmt.Errorf("kata restore failed: restore-replace interface %s: %w", guestNICName, uerr)
	}

	for _, r := range routes {
		if r.Device == targetName {
			r.Device = guestNICName
		}
	}
	if len(routes) > 0 {
		if _, rerr := s.agent.updateRoutes(ctx, routes); rerr != nil {
			return fmt.Errorf("kata restore failed: install target routes: %w", rerr)
		}
	}

	for _, n := range neighbors {
		if n != nil && n.Device == targetName {
			n.Device = guestNICName
		}
	}
	if len(neighbors) > 0 {
		if nerr := s.agent.addARPNeighbors(ctx, neighbors); nerr != nil {
			return fmt.Errorf("kata restore failed: install target neighbors: %w", nerr)
		}
	}

	after, aerr := s.agent.listInterfaces(ctx)
	if aerr != nil {
		return fmt.Errorf("kata restore failed: read back guest interfaces: %w", aerr)
	}
	targetAddrs := map[string]struct{}{}
	for _, a := range target.IPAddresses {
		if a != nil && a.Address != "" {
			targetAddrs[strings.ToLower(a.Address+"/"+a.Mask)] = struct{}{}
		}
	}
	sourceAddrs := map[string]struct{}{}
	for _, gi := range before {
		if gi != nil && gi.Name == guestNICName {
			for _, a := range gi.IPAddresses {
				if a != nil && a.Address != "" {
					sourceAddrs[strings.ToLower(a.Address+"/"+a.Mask)] = struct{}{}
				}
			}
		}
	}
	macOK := false
	gotAddrs := map[string]struct{}{}
	for _, gi := range after {
		if gi == nil || gi.Name != guestNICName {
			continue
		}
		if strings.EqualFold(gi.HwAddr, target.HwAddr) {
			macOK = true
		}
		for _, a := range gi.IPAddresses {
			if a != nil && a.Address != "" {
				gotAddrs[strings.ToLower(a.Address+"/"+a.Mask)] = struct{}{}
			}
		}
	}
	if !macOK {
		return fmt.Errorf("kata restore failed: guest NIC %s did not take target MAC %s after restore-replace", guestNICName, target.HwAddr)
	}
	for want := range targetAddrs {
		if _, ok := gotAddrs[want]; !ok {
			return fmt.Errorf("kata restore failed: guest NIC %s missing target address %s after restore-replace", guestNICName, want)
		}
	}
	for src := range sourceAddrs {
		if _, isTarget := targetAddrs[src]; isTarget {
			continue
		}
		if _, ok := gotAddrs[src]; ok {
			return fmt.Errorf("kata restore failed: stale source address %s still present on guest NIC %s", src, guestNICName)
		}
	}

	// Expose traffic only after identity verification.
	if ferr := s.network.Run(ctx, func() error {
		return activateRestoreTCFence(ctx, eps[0])
	}); ferr != nil {
		return fmt.Errorf("kata restore failed: activate network fence: %w", ferr)
	}

	idx, _, ierr := soleGuestWorkloadIndex(s)
	if ierr != nil {
		return fmt.Errorf("kata restore failed: locate adopted workload to mark running: %w", ierr)
	}
	c := s.containers[s.config.Containers[idx].ID]
	if c == nil {
		return fmt.Errorf("kata restore failed: adopted workload container %s not registered", s.config.Containers[idx].ID)
	}
	if serr := c.setContainerState(types.StateRunning); serr != nil {
		return fmt.Errorf("kata restore failed: mark adopted workload running: %w", serr)
	}
	s.Logger().WithField("guest-nic", guestNICName).Info("restored network activated")
	return nil
}

// Must match KATA_IFACE_RESTORE_REPLACE in agent netlink.rs.
const kataIfaceRestoreReplace uint32 = 0x4000_0000

// adoptPauseContainer registers the already-live pause container on the host.
func adoptPauseContainer(s *Sandbox, origSandboxID string) error {
	for i := range s.config.Containers {
		cc := &s.config.Containers[i]
		if cc.ID != s.id {
			continue
		}
		spec, err := compatoci.GetContainerSpec(cc.Annotations)
		if err != nil {
			return fmt.Errorf("get pause container spec: %w", err)
		}
		cc.CustomSpec = &spec
		c, err := newAdoptedContainer(s, cc)
		if err != nil {
			return fmt.Errorf("new pause container: %w", err)
		}
		c.guestID = origSandboxID
		c.process = Process{Token: origSandboxID, Pid: -1}
		if err := s.addContainer(c); err != nil {
			return fmt.Errorf("add pause container: %w", err)
		}
		if err := c.setContainerState(types.StateRunning); err != nil {
			return fmt.Errorf("set pause container running: %w", err)
		}
		return nil
	}
	return fmt.Errorf("pause container config (id=%s) not found in restored sandbox config", s.id)
}

// RestoreContainer adopts the sole persisted workload; the caller guarantees compatibility.
func (s *Sandbox) RestoreContainer(_ context.Context, contConfig ContainerConfig) (VCContainer, error) {
	if spec := contConfig.CustomSpec; spec != nil && spec.Hooks != nil {
		h := spec.Hooks
		if len(h.Prestart) > 0 || len(h.CreateRuntime) > 0 || len(h.CreateContainer) > 0 ||
			len(h.StartContainer) > 0 || len(h.Poststart) > 0 || len(h.Poststop) > 0 {
			return nil, fmt.Errorf("kata restore failed: workload declares OCI hooks, which are not supported by the first restore slice")
		}
	}

	idx, guestID, err := soleGuestWorkloadIndex(s)
	if err != nil {
		return nil, err
	}
	if guestID == "" {
		return nil, fmt.Errorf("kata restore failed: persisted workload has an empty guest id")
	}

	if len(s.containers) != 1 || s.containers[s.id] == nil {
		return nil, fmt.Errorf("kata restore failed: expected only the pause container before workload adoption")
	}

	savedCopy := s.config.Containers[idx]
	s.config.Containers[idx] = contConfig
	rollback := true
	defer func() {
		if rollback {
			s.config.Containers[idx] = savedCopy
		}
	}()

	c, err := newAdoptedContainer(s, &s.config.Containers[idx])
	if err != nil {
		return nil, err
	}
	c.guestID = guestID
	c.process = Process{Token: guestID, Pid: -1}
	if err = s.addContainer(c); err != nil {
		return nil, err
	}
	if err = c.setContainerState(types.StateReady); err != nil {
		delete(s.containers, c.id)
		return nil, fmt.Errorf("kata restore failed: persist adopted container mapping: %w", err)
	}
	rollback = false
	return c, nil
}

// newAdoptedContainer builds host bookkeeping without guest or device side effects.
func newAdoptedContainer(sandbox *Sandbox, contConfig *ContainerConfig) (*Container, error) {
	if !contConfig.valid() {
		return nil, fmt.Errorf("kata restore failed: invalid adopted container configuration")
	}
	c := &Container{
		id:            contConfig.ID,
		guestID:       contConfig.ID,
		sandboxID:     sandbox.id,
		rootFs:        contConfig.RootFs,
		config:        contConfig,
		sandbox:       sandbox,
		containerPath: filepath.Join(sandbox.id, contConfig.ID),
		rootfsSuffix:  "rootfs",
		mounts:        contConfig.Mounts,
		ctx:           sandbox.ctx,
	}
	return c, nil
}

// soleGuestWorkloadIndex returns the only persisted workload and its guest ID.
func soleGuestWorkloadIndex(s *Sandbox) (int, string, error) {
	idx := -1
	count := 0
	for i := range s.config.Containers {
		cc := &s.config.Containers[i]
		if cc.ID == s.id {
			continue
		}
		if cc.Annotations[criContainerTypeAnnotation] == criSandboxType {
			continue
		}
		count++
		idx = i
	}
	switch count {
	case 1:
		return idx, s.config.Containers[idx].ID, nil
	case 0:
		return -1, "", fmt.Errorf("kata restore failed: no persisted workload container found in snapshot (expected exactly one)")
	default:
		return -1, "", fmt.Errorf("kata restore failed: snapshot has %d workload containers; the first restore slice supports exactly one", count)
	}
}

// seedPersist rekeys sandbox state while preserving guest workload IDs.
func seedPersist(snapshotDir, newID string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(snapshotDir, "persist.json"))
	if err != nil {
		return "", fmt.Errorf("read snapshot persist.json: %w", err)
	}
	var ss persistapi.SandboxState
	if err := json.Unmarshal(raw, &ss); err != nil {
		return "", fmt.Errorf("decode snapshot persist.json: %w", err)
	}
	if HypervisorType(ss.Config.HypervisorType) != ClhHypervisor {
		return "", fmt.Errorf("kata restore failed: snapshot hypervisor %q is not %q; only cloud-hypervisor restore is supported", ss.Config.HypervisorType, ClhHypervisor)
	}

	origSandboxID := ss.SandboxContainer
	if origSandboxID == "" {
		return "", fmt.Errorf("kata restore failed: snapshot has an empty sandbox container id")
	}

	// Point the restored agent at the target sandbox symlink.
	ss.AgentState.URL = fmt.Sprintf("hvsock:///run/vc/vm/%s/clh.sock:1024", newID)
	ss.SandboxContainer = newID
	ss.SandboxCgroupPath = ""
	ss.OverheadCgroupPath = ""
	ss.CgroupPaths = nil
	ss.HypervisorState.Pid = 0
	ss.HypervisorState.VirtiofsDaemonPid = 0
	ss.HypervisorState.APISocket = ""

	// Rekey only the pause container; workload IDs remain guest-owned.
	for i := range ss.Config.ContainerConfigs {
		cc := &ss.Config.ContainerConfigs[i]
		if cc.Annotations[criContainerTypeAnnotation] == criSandboxType {
			cc.ID = newID
			cc.Annotations[ociBundlePathAnnotation] = filepath.Join(containerdBundleBase, newID)
			cc.Annotations[criSandboxIDAnnotation] = newID
		}
	}

	store, err := persist.GetDriver()
	if err != nil {
		return "", err
	}
	if err := store.ToDisk(ss, map[string]persistapi.ContainerState{}); err != nil {
		return "", err
	}
	return origSandboxID, nil
}

const (
	criContainerTypeAnnotation = "io.kubernetes.cri.container-type"
	criSandboxIDAnnotation     = "io.kubernetes.cri.sandbox-id"
	criSandboxType             = "sandbox"
	ociBundlePathAnnotation    = "io.katacontainers.pkg.oci.bundle_path"
	containerdBundleBase       = "/run/containerd/io.containerd.runtime.v2.task/k8s.io"
)

// validateSandboxID rejects IDs that can escape runtime state directories.
func validateSandboxID(id string) error {
	if id == "" {
		return fmt.Errorf("sandbox id is required")
	}
	if id == "." || id == ".." || strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return fmt.Errorf("invalid sandbox id %q: must not contain path separators or ..", id)
	}
	return nil
}
