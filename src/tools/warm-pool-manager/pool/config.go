// Copyright © 2026, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

package pool

import (
	"time"

	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// Tier selects the warm-member strategy.
//
//	Tier A: member is a bare kata pod sandbox (VM + pause), kept live. Claim
//	        attaches a workload container (CreateContainer + StartContainer).
//	Tier B: member is a restore-configured pod sandbox whose VM is left
//	        deferred-paused by runtime-rs (~16 MiB idle). Claim wakes the VM
//	        with an exec no-op into the wake container.
type Tier string

const (
	TierA Tier = "A"
	TierB Tier = "B"
)

// LabelManagedBy tags every sandbox this manager owns, so members survive a
// manager restart and can be re-adopted via ListPodSandbox.
const (
	LabelManagedBy = "warm-pool-manager"
	LabelTier      = "warm-pool-manager.tier"
	LabelValue     = "warm-pool-manager"
)

// Config drives the manager. Both tiers create members through the same
// RunPodSandbox path; only the member shape and the claim action differ.
type Config struct {
	// Endpoint is the containerd CRI socket.
	Endpoint string
	// RuntimeHandler is the kata runtime handler registered in containerd
	// (e.g. "kata" or "kata-clh").
	RuntimeHandler string
	// PoolSize is the number of free warm members to maintain.
	PoolSize int
	// Namespace tags member pod sandboxes.
	Namespace string
	// Tier selects the member strategy.
	Tier Tier

	// Image is the workload image. Tier A runs it at claim time; Tier B runs
	// it up front as the restore-adopted container. Ignored when
	// ContainerTemplate is set (the template's image wins).
	Image string
	// Command overrides the container entrypoint (optional).
	Command []string

	// PodTemplate, if set, is the base CRI PodSandboxConfig for members. Per
	// member the manager overrides metadata (unique name/uid), hostname,
	// log directory and merges labels/annotations; everything else (linux
	// security context, dns, sysctls, ...) is taken from the template.
	PodTemplate *runtimeapi.PodSandboxConfig
	// ContainerTemplate, if set, is the base CRI ContainerConfig for member
	// workloads (Tier A attach and Tier B restore-adopted container). This is
	// how the pyruntime workload (envs + command) is plumbed in.
	ContainerTemplate *runtimeapi.ContainerConfig

	// MemberLabels are extra labels stamped on every member pod sandbox so
	// claim selectors can match a specific pool/template.
	MemberLabels map[string]string

	// RestoreAnnotations are set on Tier B member pod sandboxes so runtime-rs
	// takes the (deferred) restore path. Empty for Tier A.
	RestoreAnnotations map[string]string
	// WakeContainer is the Tier B container the wake exec targets.
	WakeContainer string

	// MemberTTL recycles free members older than this (0 = no expiry).
	MemberTTL time.Duration
	// ReconcileInterval is the maintenance-loop period.
	ReconcileInterval time.Duration
	// CallTimeout bounds each CRI call.
	CallTimeout time.Duration
}

// withDefaults fills unset fields with sensible values.
func (c *Config) withDefaults() {
	if c.RuntimeHandler == "" {
		c.RuntimeHandler = "kata"
	}
	if c.Namespace == "" {
		c.Namespace = "warmpool"
	}
	if c.WakeContainer == "" {
		c.WakeContainer = "agent"
	}
	if c.ReconcileInterval == 0 {
		c.ReconcileInterval = 5 * time.Second
	}
	if c.CallTimeout == 0 {
		c.CallTimeout = 2 * time.Minute
	}
	if c.PoolSize < 0 {
		c.PoolSize = 0
	}
}
