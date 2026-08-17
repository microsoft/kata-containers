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
	"time"

	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist"
	persistapi "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist/api"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/compatoci"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
)

// RestoreOpts configures an annotation-driven restore.
type RestoreOpts struct {
	SandboxID            string
	HypervisorPath       string
	KernelPath           string
	ImagePath            string
	NetNSPath            string
	DisableSeccomp       bool
	ClhMemoryRestoreMode ClhMemoryRestoreMode
}

func (opts RestoreOpts) applyHypervisorOverrides(config *HypervisorConfig) {
	if opts.HypervisorPath != "" {
		config.HypervisorPath = opts.HypervisorPath
	}
	if opts.KernelPath != "" {
		config.KernelPath = opts.KernelPath
	}
	if opts.ImagePath != "" {
		config.ImagePath = opts.ImagePath
	}

	// The restored VMM is a new host process, so use the current runtime's
	// host policies rather than the snapshot's persisted configuration.
	config.DisableSeccomp = opts.DisableSeccomp
	config.ClhMemoryRestoreMode = opts.ClhMemoryRestoreMode
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

	drv, err := persist.GetDriver()
	if err != nil {
		return nil, fmt.Errorf("restore: get persist driver: %w", err)
	}
	if drv == nil {
		return nil, fmt.Errorf("restore: nil persist driver")
	}
	cleanupSafe := true
	defer func() {
		if err != nil && cleanupSafe {
			_ = drv.Destroy(newID)
		}
	}()

	if err := seedPersist(snapshotDir, newID, drv); err != nil {
		return nil, fmt.Errorf("seed persist for restore: %w", err)
	}

	sandboxConfig, err := loadSandboxConfig(newID)
	if err != nil {
		return nil, fmt.Errorf("load restored sandbox config: %w", err)
	}
	sandboxConfig.ID = newID

	opts.applyHypervisorOverrides(&sandboxConfig.HypervisorConfig)

	// Keep source memory immutable through a private mapping.
	sandboxConfig.HypervisorConfig.FileBackedMemory = &FileBackedMemoryConfig{
		Path:   filepath.Join(snapshotDir, "memory-ranges"),
		Shared: false,
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
			if !cleanupSafe {
				s.Logger().WithError(err).Error("preserving restore resources because VMM stop was not confirmed")
				return
			}
			cleanupCtx, cancel := context.WithTimeout(context.Background(), restoreFailureCleanupTimeout)
			defer cancel()
			if s.restoreNetFence {
				_ = s.network.Run(cleanupCtx, func() error {
					for _, ep := range s.network.Endpoints() {
						cleanupRestoreTCFence(ep)
					}
					return nil
				})
			}
			// Delete accepts only terminal or pre-running states.
			s.state.State = types.StateStopped
			s.Delete(cleanupCtx)
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
	eps := s.network.Endpoints()
	if len(eps) != 1 {
		err = fmt.Errorf("kata restore failed: expected exactly one CNI endpoint, found %d", len(eps))
		return nil, err
	}

	// Restore the existing guest NIC with the target TAP FDs while inside its netns.
	vmConfig := VMConfig{
		HypervisorType:      sandboxConfig.HypervisorType,
		HypervisorConfig:    sandboxConfig.HypervisorConfig,
		AgentConfig:         sandboxConfig.AgentConfig,
		RestoreNetEndpoints: eps,
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
			cleanupCtx, cancel := context.WithTimeout(context.Background(), restoreFailureCleanupTimeout)
			defer cancel()
			if vmAssigned {
				if abortErr := s.AbortRestore(cleanupCtx); abortErr != nil {
					cleanupSafe = false
					s.Logger().WithError(abortErr).Error("failed to abort partially restored sandbox")
				}
			} else {
				if stopErr := vm.Stop(cleanupCtx); stopErr != nil {
					cleanupSafe = false
					s.Logger().WithError(stopErr).Error("failed to stop unassigned restored VM")
				}
			}
		}
	}()

	if err = vm.assignSandbox(s); err != nil {
		return nil, fmt.Errorf("assign restored vm to sandbox: %w", err)
	}
	vmAssigned = true
	s.restoredVM = vm

	if err = adoptPauseContainer(s); err != nil {
		return nil, fmt.Errorf("adopt restored pause container: %w", err)
	}

	s.Logger().WithField("restored-sandbox", newID).Info("restore: managed sandbox restored paused")
	return s, nil
}

// FinalizeRestoreNetwork replaces guest identity before enabling TC redirects.
func (s *Sandbox) FinalizeRestoreNetwork(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			s.cleanupFailedRestore(err)
		}
	}()

	eps := s.network.Endpoints()
	if len(eps) != 1 {
		return fmt.Errorf("kata restore failed: expected exactly one adopted CNI endpoint, found %d", len(eps))
	}
	if s.restoredVM == nil {
		return fmt.Errorf("kata restore failed: restored VM lifecycle is unavailable")
	}

	if err = s.restoredVM.Resume(ctx); err != nil {
		return fmt.Errorf("kata restore failed: resume: %w", err)
	}
	if err = s.restoredVM.ReseedRNG(ctx); err != nil {
		return fmt.Errorf("kata restore failed: reseed guest RNG: %w", err)
	}
	if err = s.restoredVM.SyncTime(ctx); err != nil {
		return fmt.Errorf("kata restore failed: sync guest time: %w", err)
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

	ifaces, routes, _, gerr := generateVCNetworkStructures(ctx, eps)
	if gerr != nil {
		return fmt.Errorf("kata restore failed: generate guest network structures: %w", gerr)
	}
	if len(ifaces) != 1 {
		return fmt.Errorf("kata restore failed: expected exactly one target CNI interface, found %d", len(ifaces))
	}

	target := ifaces[0]
	targetName := target.Name
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

	if serr := s.markAdoptedWorkloadsRunning(); serr != nil {
		return fmt.Errorf("kata restore failed: mark adopted workloads running: %w", serr)
	}
	s.restoreActivated = true
	s.restoredVM = nil
	s.Logger().WithField("guest-nic", guestNICName).Info("restored network activated")
	return nil
}

const restoreFailureCleanupTimeout = 30 * time.Second

// cleanupFailedRestore stops the VMM before releasing the TAP resources it is
// using. Cleanup must not inherit a failed or canceled task RPC context.
func (s *Sandbox) cleanupFailedRestore(cause error) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), restoreFailureCleanupTimeout)
	defer cancel()

	s.Logger().WithError(cause).Error("restore finalization failed; stopping restored VM")
	if abortErr := s.AbortRestore(cleanupCtx); abortErr != nil {
		s.Logger().WithError(abortErr).Error("failed to abort restored VM after finalization error")
	}
}

// AbortRestore makes a failed restore terminal. The VMM is stopped and reaped
// before any TAP descriptor or link is released.
func (s *Sandbox) AbortRestore(ctx context.Context) error {
	if stopErr := s.hypervisor.StopVM(ctx, false); stopErr != nil {
		return fmt.Errorf("stop restored VM: %w", stopErr)
	}
	s.restoredVM = nil
	for _, c := range s.containers {
		c.state.State = types.StateStopped
	}
	s.state.State = types.StateStopped

	if cleanupErr := s.network.Run(ctx, func() error {
		for _, endpoint := range s.network.Endpoints() {
			cleanupRestoreTCFence(endpoint)
		}
		return nil
	}); cleanupErr != nil {
		s.Logger().WithError(cleanupErr).Error("failed to clean restore network fence")
	}
	if cleanupErr := s.network.RemoveEndpoints(ctx, s, nil, false); cleanupErr != nil {
		s.Logger().WithError(cleanupErr).Error("failed to remove restore network endpoints")
	}
	if releaseErr := s.Release(ctx); releaseErr != nil {
		s.Logger().WithError(releaseErr).Warn("failed to release sandbox after aborting restore")
	}
	return nil
}

// private raw_flags bit for restore-only identity replacement; keep in sync with kata-agent.
const kataIfaceRestoreReplace uint32 = 0x4000_0000

// rekeySandboxAgentContainerIDMap maintains direct mappings from current host
// container IDs to the progenitor pod's canonical agent container IDs.
func rekeySandboxAgentContainerIDMap(state *persistapi.SandboxState, newSandboxID string) error {
	oldSandboxID := state.SandboxContainer
	if oldSandboxID == "" {
		return fmt.Errorf("kata restore failed: snapshot has an empty sandbox container id")
	}

	containerIDs := make(map[string]struct{}, len(state.Config.ContainerConfigs))
	// On the first restore, host and agent IDs are still identical.
	if state.AgentContainerIDMap == nil {
		state.AgentContainerIDMap = make(map[string]string, len(state.Config.ContainerConfigs))
		for _, config := range state.Config.ContainerConfigs {
			if config.ID == "" {
				return fmt.Errorf("kata restore failed: snapshot has a container with an empty id")
			}
			if _, exists := state.AgentContainerIDMap[config.ID]; exists {
				return fmt.Errorf("kata restore failed: snapshot has duplicate container id %q", config.ID)
			}
			state.AgentContainerIDMap[config.ID] = config.ID
		}
	}

	// Validate one canonical agent ID for every persisted container ID.
	for _, config := range state.Config.ContainerConfigs {
		if _, exists := containerIDs[config.ID]; exists {
			return fmt.Errorf("kata restore failed: snapshot has duplicate container id %q", config.ID)
		}
		containerIDs[config.ID] = struct{}{}
		agentID, exists := state.AgentContainerIDMap[config.ID]
		if !exists || agentID == "" {
			return fmt.Errorf("kata restore failed: container %q has no canonical agent id", config.ID)
		}
	}
	if len(containerIDs) != len(state.AgentContainerIDMap) {
		return fmt.Errorf("kata restore failed: agent container id map does not match the persisted containers")
	}

	// Rekey the pause host ID without changing its progenitor agent ID.
	agentSandboxID, exists := state.AgentContainerIDMap[oldSandboxID]
	if !exists || agentSandboxID == "" {
		return fmt.Errorf("kata restore failed: sandbox container %q has no canonical agent id", oldSandboxID)
	}
	if oldSandboxID != newSandboxID {
		if _, exists := state.AgentContainerIDMap[newSandboxID]; exists {
			return fmt.Errorf("kata restore failed: target sandbox id %q already exists in the agent container id map", newSandboxID)
		}
		delete(state.AgentContainerIDMap, oldSandboxID)
		state.AgentContainerIDMap[newSandboxID] = agentSandboxID
	}

	// Rewrite the persisted pause config for the current host generation.
	pauseContainerFound := false
	for index := range state.Config.ContainerConfigs {
		config := &state.Config.ContainerConfigs[index]
		if config.Annotations[criContainerTypeAnnotation] != criSandboxType {
			continue
		}
		if pauseContainerFound || config.ID != oldSandboxID {
			return fmt.Errorf("kata restore failed: snapshot pause container does not match sandbox id %q", oldSandboxID)
		}
		pauseContainerFound = true
		config.ID = newSandboxID
		if config.Annotations == nil {
			config.Annotations = make(map[string]string)
		}
		config.Annotations[ociBundlePathAnnotation] = filepath.Join(containerdBundleBase, newSandboxID)
		config.Annotations[criSandboxIDAnnotation] = newSandboxID
	}
	if !pauseContainerFound {
		return fmt.Errorf("kata restore failed: snapshot has no pause container for sandbox %q", oldSandboxID)
	}

	state.SandboxContainer = newSandboxID
	return nil
}

func (s *Sandbox) rekeyAgentContainerID(oldHostID, newHostID string) (string, error) {
	if s.agentContainerIDMap == nil {
		return "", fmt.Errorf("kata restore failed: sandbox has no agent container id map")
	}
	agentID, exists := s.agentContainerIDMap[oldHostID]
	if !exists || agentID == "" {
		return "", fmt.Errorf("kata restore failed: container %q has no canonical agent id", oldHostID)
	}
	if oldHostID != newHostID {
		if _, exists := s.agentContainerIDMap[newHostID]; exists {
			return "", fmt.Errorf("kata restore failed: target container id %q already exists in the agent container id map", newHostID)
		}
		delete(s.agentContainerIDMap, oldHostID)
		s.agentContainerIDMap[newHostID] = agentID
	}
	return agentID, nil
}

// adoptPauseContainer rekeys host bookkeeping while preserving the pause process's guest ID.
func adoptPauseContainer(s *Sandbox) error {
	agentID, exists := s.agentContainerIDMap[s.id]
	if !exists || agentID == "" {
		return fmt.Errorf("pause container %q has no canonical agent id", s.id)
	}
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
		c.process = Process{Token: agentID, Pid: -1}
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

// RestoreContainer adopts the persisted workload whose CRI container name matches the target's.
func (s *Sandbox) RestoreContainer(ctx context.Context, contConfig ContainerConfig) (VCContainer, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("kata restore failed: workload adoption canceled: %w", err)
	}
	if spec := contConfig.CustomSpec; spec != nil && spec.Hooks != nil {
		h := spec.Hooks
		if len(h.Prestart) > 0 || len(h.CreateRuntime) > 0 || len(h.CreateContainer) > 0 ||
			len(h.StartContainer) > 0 || len(h.Poststart) > 0 || len(h.Poststop) > 0 {
			return nil, fmt.Errorf("kata restore failed: workload declares OCI hooks, which are not supported by the first restore slice")
		}
	}

	idx, persistedHostID, err := guestWorkloadIndexByName(s, contConfig.Annotations[criContainerNameAnnotation])
	if err != nil {
		return nil, err
	}

	if s.containers[s.id] == nil {
		return nil, fmt.Errorf("kata restore failed: the restored pause container must be adopted before workloads")
	}

	savedCopy := s.config.Containers[idx]
	savedIDMap := cloneAgentContainerIDMap(s.agentContainerIDMap)
	agentID, err := s.rekeyAgentContainerID(persistedHostID, contConfig.ID)
	if err != nil {
		return nil, err
	}
	s.config.Containers[idx] = contConfig
	rollback := true
	defer func() {
		if rollback {
			s.config.Containers[idx] = savedCopy
			s.agentContainerIDMap = savedIDMap
		}
	}()

	c, err := newAdoptedContainer(s, &s.config.Containers[idx])
	if err != nil {
		return nil, err
	}
	c.process = Process{Token: agentID, Pid: -1}
	if err = s.addContainer(c); err != nil {
		return nil, err
	}
	// adoptions after the vm resumed go straight to running; earlier ones are
	// promoted by FinalizeRestoreNetwork when the first workload starts
	adoptedState := types.StateReady
	if s.restoreActivated {
		adoptedState = types.StateRunning
	}
	if err = c.setContainerState(adoptedState); err != nil {
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

// guestWorkloadIndexByName locates the unclaimed persisted workload whose CRI
// container name matches the target's. an adopted slot holds the target's own
// config, whose ID is registered host-side, so it can never be claimed twice.
func guestWorkloadIndexByName(s *Sandbox, name string) (int, string, error) {
	if name == "" {
		return -1, "", fmt.Errorf("kata restore failed: target container has no %s annotation", criContainerNameAnnotation)
	}
	for i := range s.config.Containers {
		cc := &s.config.Containers[i]
		if cc.ID == s.id {
			continue
		}
		if cc.Annotations[criContainerTypeAnnotation] == criSandboxType {
			continue
		}
		if cc.Annotations[criContainerNameAnnotation] != name {
			continue
		}
		if s.containers[cc.ID] != nil {
			return -1, "", fmt.Errorf("kata restore failed: workload %q is already adopted", name)
		}
		return i, cc.ID, nil
	}
	return -1, "", fmt.Errorf("kata restore failed: snapshot has no unclaimed workload container named %q", name)
}

// markAdoptedWorkloadsRunning promotes every adopted-but-ready workload once the vm resumed.
func (s *Sandbox) markAdoptedWorkloadsRunning() error {
	for id, c := range s.containers {
		if id == s.id {
			continue
		}
		if c.state.State != types.StateReady {
			continue
		}
		if err := c.setContainerState(types.StateRunning); err != nil {
			return fmt.Errorf("workload %s: %w", id, err)
		}
	}
	return nil
}

// seedPersist rekeys snapshot state for the new sandbox without changing agent IDs.
func seedPersist(snapshotDir, newID string, store persistapi.PersistDriver) error {
	raw, err := os.ReadFile(filepath.Join(snapshotDir, "persist.json"))
	if err != nil {
		return fmt.Errorf("read snapshot persist.json: %w", err)
	}
	var ss persistapi.SandboxState
	if err := json.Unmarshal(raw, &ss); err != nil {
		return fmt.Errorf("decode snapshot persist.json: %w", err)
	}
	if HypervisorType(ss.Config.HypervisorType) != ClhHypervisor {
		return fmt.Errorf("kata restore failed: snapshot hypervisor %q is not %q; only cloud-hypervisor restore is supported", ss.Config.HypervisorType, ClhHypervisor)
	}

	if err := rekeySandboxAgentContainerIDMap(&ss, newID); err != nil {
		return err
	}

	ss.AgentState.URL = fmt.Sprintf("hvsock:///run/vc/vm/%s/clh.sock:1024", newID)
	ss.SandboxCgroupPath = ""
	ss.OverheadCgroupPath = ""
	ss.CgroupPaths = nil
	ss.HypervisorState.Pid = 0
	ss.HypervisorState.VirtiofsDaemonPid = 0
	ss.HypervisorState.APISocket = ""
	ss.Config.HypervisorConfig.VMid = ""

	if err := store.ToDisk(ss, map[string]persistapi.ContainerState{}); err != nil {
		return err
	}
	return nil
}

const (
	criContainerTypeAnnotation = "io.kubernetes.cri.container-type"
	criContainerNameAnnotation = "io.kubernetes.cri.container-name"
	criSandboxIDAnnotation     = "io.kubernetes.cri.sandbox-id"
	criSandboxType             = "sandbox"
	ociBundlePathAnnotation    = "io.katacontainers.pkg.oci.bundle_path"
	containerdBundleBase       = "/run/containerd/io.containerd.runtime.v2.task/k8s.io"
)

func validateSandboxID(id string) error {
	if id == "" {
		return fmt.Errorf("sandbox id is required")
	}
	if id == "." || id == ".." || strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return fmt.Errorf("invalid sandbox id %q: must not contain path separators or ..", id)
	}
	return nil
}
