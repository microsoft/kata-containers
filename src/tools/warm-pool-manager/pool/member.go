// Copyright © 2026, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

package pool

import (
	"time"

	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// MemberState is the lifecycle state of a warm-pool member.
type MemberState string

const (
	// StateCreating is a reserved slot whose pod sandbox is being created.
	StateCreating MemberState = "creating"
	// StateFree is a ready, claimable member.
	StateFree MemberState = "free"
	// StateClaiming is a member mid-claim (attaching workload / waking VM).
	StateClaiming MemberState = "claiming"
	// StateClaimed is a member handed to a caller.
	StateClaimed MemberState = "claimed"
	// StateDraining is a member being torn down.
	StateDraining MemberState = "draining"
	// StateFailed is a member that errored and must be recycled.
	StateFailed MemberState = "failed"
)

// Member is one warm pod sandbox (a full shim -> cloud-hypervisor pair) plus
// the manager's bookkeeping over it.
type Member struct {
	// ID is the CRI pod sandbox ID. Empty while StateCreating.
	ID string
	// Name is the pod sandbox name.
	Name string
	// State is the lifecycle state (guarded by Manager.mu).
	State MemberState
	// Ready mirrors the last observed CRI readiness (guarded by Manager.mu).
	Ready bool
	// WorkloadID is the Tier A container attached at claim time.
	WorkloadID string
	// Labels are the member pod sandbox labels, matched by claim selectors.
	Labels map[string]string
	// CreatedAt / ExpiresAt drive TTL recycling.
	CreatedAt time.Time
	ExpiresAt time.Time

	// podConfig is retained for Tier A CreateContainer (its SandboxConfig
	// field) and for diagnostics.
	podConfig *runtimeapi.PodSandboxConfig
	// key is the manager map key (pod ID once created, temp key while creating).
	key string
}
